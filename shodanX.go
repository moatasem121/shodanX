package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// NOTE: Only use this tool against domains you are authorized to test.

var shodanAPI = "https://api.shodan.io"

type searchResult struct {
	Matches []map[string]interface{} `json:"matches"`
	Total   int                      `json:"total"`
}

func newHTTPClient(timeoutSec int) *http.Client {
	return &http.Client{
		Timeout: time.Duration(timeoutSec) * time.Second,
	}
}

func doGet(client *http.Client, fullURL string) ([]byte, int, error) {
	resp, err := client.Get(fullURL)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

func extractFromMatch(m map[string]interface{}) []string {
	out := []string{}
	// hostnames
	if hostnamesRaw, ok := m["hostnames"]; ok {
		if hostnames, ok := hostnamesRaw.([]interface{}); ok {
			for _, h := range hostnames {
				if s, ok := h.(string); ok && s != "" {
					out = append(out, s)
				}
			}
		}
	}
	// try SSL cert fields -- be defensive
	if sslRaw, ok := m["ssl"]; ok {
		if ssl, ok := sslRaw.(map[string]interface{}); ok {
			// many Shodan responses contain ssl.cert.subject or ssl.cert.extensions.subjectAltName
			if certRaw, ok := ssl["cert"]; ok {
				if cert, ok := certRaw.(map[string]interface{}); ok {
					// Common Name (CN)
					if subjectRaw, ok := cert["subject"]; ok {
						if subject, ok := subjectRaw.(map[string]interface{}); ok {
							for _, v := range subject {
								// values in subject could be string or nested
								if s, ok := v.(string); ok && strings.Contains(s, ".") {
									out = append(out, s)
								}
							}
						}
					}
					// Alternative names under cert["extensions"] or cert["subjectAltName"]
					if extRaw, ok := cert["extensions"]; ok {
						if ext, ok := extRaw.(map[string]interface{}); ok {
							for _, v := range ext {
								switch t := v.(type) {
								case []interface{}:
									for _, item := range t {
										if s, ok := item.(string); ok && strings.Contains(s, ".") {
											out = append(out, s)
										}
									}
								case string:
									// extension might be a single string with comma-separated names
									for _, part := range strings.Split(t, ",") {
										part = strings.TrimSpace(part)
										if strings.Contains(part, ".") {
											out = append(out, part)
										}
									}
								}
							}
						}
					}
					// subjectAltName sometimes directly available
					if sanRaw, ok := cert["subjectAltName"]; ok {
						if sanList, ok := sanRaw.([]interface{}); ok {
							for _, v := range sanList {
								if s, ok := v.(string); ok && strings.Contains(s, ".") {
									out = append(out, s)
								}
							}
						}
					}
				}
			}
		}
	}
	// http.host or banner data
	if httpRaw, ok := m["http"]; ok {
		if httpObj, ok := httpRaw.(map[string]interface{}); ok {
			if titleRaw, ok := httpObj["title"]; ok {
				if s, ok := titleRaw.(string); ok && strings.Contains(s, ".") {
					out = append(out, s)
				}
			}
			if hRaw, ok := httpObj["host"]; ok {
				if s, ok := hRaw.(string); ok && strings.Contains(s, ".") {
					out = append(out, s)
				}
			}
		}
	}
	// fallback: parse ip_str? (not a hostname) skip
	return out
}

func uniqueNormalized(items []string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(items))
	for _, s := range items {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		// normalize to lower-case
		key := strings.ToLower(s)
		if !seen[key] {
			seen[key] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func searchShodanPaginated(client *http.Client, query, apiKey string, maxPages int, rps <-chan time.Time) ([]string, error) {
	results := []string{}
	escaped := url.QueryEscape(query)
	for page := 1; page <= maxPages; page++ {
		<-rps // rate limiter tick
		fullURL := fmt.Sprintf("%s/shodan/host/search?key=%s&query=%s&page=%d", shodanAPI, url.QueryEscape(apiKey), escaped, page)
		body, status, err := doGet(client, fullURL)
		if err != nil {
			return results, fmt.Errorf("request error (page %d): %w", page, err)
		}
		if status != http.StatusOK {
			// attempt to read message
			var text string
			if len(body) > 0 {
				text = string(body)
			}
			return results, fmt.Errorf("shodan returned status %d: %s", status, text)
		}
		var sr searchResult
		if err := json.Unmarshal(body, &sr); err != nil {
			return results, fmt.Errorf("json unmarshal (page %d): %w", page, err)
		}
		if len(sr.Matches) == 0 {
			// no more matches
			break
		}
		for _, m := range sr.Matches {
			results = append(results, extractFromMatch(m)...)
		}
		// early stop: if fewer matches than typical page size, probably last page
		if len(sr.Matches) < 100 {
			// common Shodan page size is 100
			break
		}
	}
	return results, nil
}

func getDNSSubs(client *http.Client, domain, apiKey string, rps <-chan time.Time) ([]string, error) {
	<-rps
	fullURL := fmt.Sprintf("%s/dns/domain/%s?key=%s", shodanAPI, url.PathEscape(domain), url.QueryEscape(apiKey))
	body, status, err := doGet(client, fullURL)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("dns api returned status %d: %s", status, string(body))
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	out := []string{}
	if subRaw, ok := raw["subdomains"]; ok {
		if subs, ok := subRaw.([]interface{}); ok {
			for _, s := range subs {
				if str, ok := s.(string); ok {
					out = append(out, fmt.Sprintf("%s.%s", str, domain))
				}
			}
		}
	}
	return out, nil
}

func verifyDNSNames(names []string) []string {
	out := []string{}
	for _, n := range names {
		// try lookup host (quick)
		if _, err := net.LookupHost(n); err == nil {
			out = append(out, n)
		}
		// NOTE: we intentionally do not surface non-resolving names unless user wants them
	}
	return out
}

func main() {
	apiKey := flag.String("apikey", "", "Shodan API key (required)")
	domain := flag.String("domain", "", "Domain to search (required)")
	output := flag.String("output", "", "Output file name (without extension)")
	pages := flag.Int("pages", 2, "Max pages to fetch per query (Shodan host/search pages start at 1)")
	concurrency := flag.Int("concurrency", 1, "Number of concurrent queries (respect Shodan TOS)")
	timeout := flag.Int("timeout", 15, "HTTP client timeout in seconds")
	rps := flag.Int("rps", 1, "Requests per second (rate limit)")
	verify := flag.Bool("verify", false, "Verify discovered hostnames with DNS lookup (may slow results)")
	flag.Parse()

	if *apiKey == "" || *domain == "" {
		fmt.Fprintln(os.Stderr, "apikey and domain are required. Example:")
		fmt.Fprintln(os.Stderr, "  go run shodanX.go -domain atw.ltd -apikey <KEY> -output subs -pages 3 -concurrency 2")
		flag.Usage()
		os.Exit(2)
	}
	// queries to run (same as your original set)
	queries := []string{
		fmt.Sprintf("hostname:\"%s\"", *domain),
		fmt.Sprintf("ssl.cert.subject.cn:\"%s\"", *domain),
		fmt.Sprintf("ssl.cert.subject.an:\"%s\"", *domain),
		fmt.Sprintf("ssl.cert.issuer.cn:\"%s\"", *domain),
		fmt.Sprintf("ssl.cert.issuer.o:\"%s\"", *domain),
		fmt.Sprintf("http.title:\"%s\"", *domain),
		fmt.Sprintf("http.html:\"%s\"", *domain),
		fmt.Sprintf("all:\"%s\"", *domain),
		fmt.Sprintf("org:\"%s\"", *domain),
	}

	client := newHTTPClient(*timeout)
	// create rate limiter ticker channel
	ticker := time.NewTicker(time.Second / time.Duration(*rps))
	defer ticker.Stop()
	rpsChan := ticker.C

	// concurrency control
	sem := make(chan struct{}, *concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	allSubs := []string{}
	errorsFound := make([]error, 0)

	for _, q := range queries {
		wg.Add(1)
		sem <- struct{}{}
		go func(query string) {
			defer wg.Done()
			defer func() { <-sem }()
			fmt.Fprintln(os.Stderr, "[*] Query:", query)
			subres, err := searchShodanPaginated(client, query, *apiKey, *pages, rpsChan)
			if err != nil {
				mu.Lock()
				errorsFound = append(errorsFound, fmt.Errorf("query %q: %w", query, err))
				mu.Unlock()
				return
			}
			mu.Lock()
			allSubs = append(allSubs, subres...)
			mu.Unlock()
		}(q)
	}
	wg.Wait()

	// Add DNS API results (single)
	dnsSubs, err := getDNSSubs(client, *domain, *apiKey, rpsChan)
	if err != nil {
		// not fatal, but report
		fmt.Fprintln(os.Stderr, "[!] DNS API error:", err)
	} else {
		allSubs = append(allSubs, dnsSubs...)
	}

	// Deduplicate & normalize
	allSubs = uniqueNormalized(allSubs)

	// optional DNS verification
	if *verify {
		fmt.Fprintln(os.Stderr, "[*] Verifying hostnames via DNS lookup (this will take time)...")
		allSubs = verifyDNSNames(allSubs)
	}

	fmt.Printf("\n[+] Found %d unique hostnames/subdomains:\n", len(allSubs))
	for _, s := range allSubs {
		fmt.Println(s)
	}

	// save outputs if requested
	if *output != "" {
		txtFile := *output + ".txt"
		if err := os.WriteFile(txtFile, []byte(strings.Join(allSubs, "\n")), 0644); err != nil {
			fmt.Fprintln(os.Stderr, "Failed to write txt:", err)
		} else {
			fmt.Fprintln(os.Stderr, "[+] TXT saved to", txtFile)
		}

		jsonFile := *output + ".json"
		meta := map[string]interface{}{
			"domain":       *domain,
			"total":        len(allSubs),
			"queries_used": queries,
			"subdomains":   allSubs,
			"generated_at": time.Now().UTC().Format(time.RFC3339),
		}
		j, _ := json.MarshalIndent(meta, "", "  ")
		if err := os.WriteFile(jsonFile, j, 0644); err != nil {
			fmt.Fprintln(os.Stderr, "Failed to write json:", err)
		} else {
			fmt.Fprintln(os.Stderr, "[+] JSON saved to", jsonFile)
		}
	}

	// print errors summary
	if len(errorsFound) > 0 {
		fmt.Fprintln(os.Stderr, "\n[!] Some queries returned errors:")
		for _, e := range errorsFound {
			fmt.Fprintln(os.Stderr, " -", e)
		}
	}
}
