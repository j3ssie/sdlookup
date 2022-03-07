package main

import (
    "bufio"
    "crypto/tls"
    "flag"
    "fmt"
    jsoniter "github.com/json-iterator/go"
    "github.com/projectdiscovery/mapcidr"
    "io/ioutil"
    "net"
    "net/http"
    "os"
    "sort"
    "strings"
    "sync"
)

// Extract Shodan IPInfo from internetdb.shodan.io
// cat /tmp/list_of_IP | cinfo -c 100
var (
    csvOutput   bool
    jsonOutput  bool
    onlyHost    bool
    concurrency int
)

type ShodanIPInfo struct {
    Cpes      []string `json:"cpes"`
    Hostnames []string `json:"hostnames"`
    IP        string   `json:"ip"`
    Ports     []int    `json:"ports"`
    Tags      []string `json:"tags"`
    Vulns     []string `json:"vulns"`
}

func main() {
    // cli arguments
    flag.IntVar(&concurrency, "c", 20, "Set the concurrency level")
    flag.BoolVar(&jsonOutput, "json", false, "Show Output as Json format")
    flag.BoolVar(&csvOutput, "csv", true, "Show Output as CSV format")
    flag.BoolVar(&onlyHost, "open", false, "Show Output as format 'IP:Port' only")
    flag.Parse()

    stat, _ := os.Stdin.Stat()
    if (stat.Mode() & os.ModeCharDevice) != 0 {
        args := os.Args[1:]
        sort.Strings(args)
        ip := args[len(args)-1]
        StartJob(ip)
        os.Exit(0)
    }

    var wg sync.WaitGroup
    jobs := make(chan string, concurrency)

    for i := 0; i < concurrency; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for job := range jobs {

                StartJob(job)
            }
        }()
    }

    sc := bufio.NewScanner(os.Stdin)
    go func() {
        for sc.Scan() {
            url := strings.TrimSpace(sc.Text())
            if err := sc.Err(); err == nil && url != "" {
                jobs <- url
            }
        }
        close(jobs)
    }()
    wg.Wait()
}

func StartJob(raw string) {
    _, _, err := net.ParseCIDR(raw)
    if err != nil {
        GetIPInfo(raw)
        return
    }

    if ips, err := mapcidr.IPAddresses(raw); err == nil {
        for _, ip := range ips {
            GetIPInfo(ip)
        }
    }
}

func GetIPInfo(IP string) {
    data := sendGET(IP)
    if data == "" {
        return
    }

    if jsonOutput {
        fmt.Println(data)
        return
    }

    var shodanIPInfo ShodanIPInfo
    if ok := jsoniter.Unmarshal([]byte(data), &shodanIPInfo); ok != nil {
        return
    }

    if csvOutput {
        for _, port := range shodanIPInfo.Ports {
            line := fmt.Sprintf("%s:%d", IP, port)
            if onlyHost {
                fmt.Println(line)
                continue
            }

            line = fmt.Sprintf("%s,%s,%s,%s,%s", line, strings.Join(shodanIPInfo.Hostnames, ";"), strings.Join(shodanIPInfo.Tags, ";"), strings.Join(shodanIPInfo.Cpes, ";"), strings.Join(shodanIPInfo.Vulns, ";"))
            fmt.Println(line)
        }
    }
}

func sendGET(IP string) string {
    ipURL := fmt.Sprintf("https://internetdb.shodan.io/%s", IP)
    tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }

    client := &http.Client{Transport: tr}
    resp, err := client.Get(ipURL)
    if err != nil {
        fmt.Fprintf(os.Stderr, "%v", err)
        return ""
    }
    defer resp.Body.Close()
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        fmt.Fprintf(os.Stderr, "%v", err)
        return ""
    }
    return string(body)
}
