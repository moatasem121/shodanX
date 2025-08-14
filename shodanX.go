package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

var shodanAPI = "https://api.shodan.io"

// Search Shodan for a query and return hostnames
func searchShodan(query, apiKey string) []string {
	url := fmt.Sprintf("%s/shodan/host/search?key=%s&query=%s", shodanAPI, apiKey, query)
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Request failed:", err)
		return nil
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(body, &result)

	subs := []string{}
	if matches, ok := result["matches"].([]interface{}); ok {
		for _, m := range matches {
			if rec, ok := m.(map[string]interface{}); ok {
				// Hostnames field
				if hostnames, exists := rec["hostnames"].([]interface{}); exists {
					for _, h := range hostnames {
						subs = append(subs, h.(string))
					}
				}
				// SSL SANs
				if sslData, exists := rec["ssl"].(map[string]interface{}); exists {
					if cert, exists := sslData["cert"].(map[string]interface{}); exists {
						if san, exists := cert["subject"].(map[string]interface{}); exists {
							for _, v := range san {
								if s, ok := v.(string); ok && strings.Contains(s, ".") {
									subs = append(subs, s)
								}
							}
						}
					}
				}
			}
		}
	}
	return subs
}

// Get subdomains from Shodan DNS API
func getDNSSubs(domain, apiKey string) []string {
	url := fmt.Sprintf("%s/dns/domain/%s?key=%s", shodanAPI, domain, apiKey)
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("DNS API request failed:", err)
		return nil
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(body, &result)

	subs := []string{}
	if data, ok := result["subdomains"].([]interface{}); ok {
		for _, s := range data {
			subs = append(subs, fmt.Sprintf("%s.%s", s.(string), domain))
		}
	}
	return subs
}

// Remove duplicates
func unique(input []string) []string {
	seen := make(map[string]bool)
	result := []string{}
	for _, v := range input {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	return result
}

func main() {
	apiKey := flag.String("apikey", "insert-api-key", "Shodan API key")
	output := flag.String("output", "", "Output file name (without extension)")
	flag.Parse()

	if len(flag.Args()) < 1 {
		fmt.Println("Usage: go run shodanX.go <domain> [--apikey <key>] [--output filename]")
		os.Exit(1)
	}
	domain := flag.Arg(0)

	queries := []string{
		fmt.Sprintf("hostname:\"%s\"", domain),
		fmt.Sprintf("ssl.cert.subject.cn:\"%s\"", domain),
		fmt.Sprintf("ssl.cert.subject.an:\"%s\"", domain),
		fmt.Sprintf("ssl.cert.issuer.cn:\"%s\"", domain),
		fmt.Sprintf("ssl.cert.issuer.o:\"%s\"", domain),
		fmt.Sprintf("http.title:\"%s\"", domain),
		fmt.Sprintf("http.html:\"%s\"", domain),
		fmt.Sprintf("all:\"%s\"", domain),
		fmt.Sprintf("org:\"%s\"", domain),
	}

	var allSubs []string

	for _, q := range queries {
		fmt.Println("[*] Query:", q)
		subs := searchShodan(q, *apiKey)
		allSubs = append(allSubs, subs...)
	}

	// Add DNS API results
	dnsSubs := getDNSSubs(domain, *apiKey)
	allSubs = append(allSubs, dnsSubs...)

	// Remove duplicates
	allSubs = unique(allSubs)

	fmt.Printf("\n[+] Found %d unique subdomains:\n", len(allSubs))
	for _, s := range allSubs {
		fmt.Println(s)
	}

	if *output != "" {
		// Save TXT
		txtFile := *output + ".txt"
		ioutil.WriteFile(txtFile, []byte(strings.Join(allSubs, "\n")), 0644)
		fmt.Println("[+] TXT results saved to", txtFile)

		// Save JSON
		jsonFile := *output + ".json"
		jsonData := map[string]interface{}{
			"domain":       domain,
			"total":        len(allSubs),
			"queries_used": queries,
			"subdomains":   allSubs,
		}
		jsonBytes, _ := json.MarshalIndent(jsonData, "", "  ")
		ioutil.WriteFile(jsonFile, jsonBytes, 0644)
		fmt.Println("[+] JSON results saved to", jsonFile)
	}
}
