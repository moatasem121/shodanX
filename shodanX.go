package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Failed to read response:", err)
		return nil
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		fmt.Println("Failed to parse JSON response:", err)
		return nil
	}

	subs := []string{}
	if matches, ok := result["matches"].([]interface{}); ok {
		for _, m := range matches {
			if rec, ok := m.(map[string]interface{}); ok {
				// Hostnames field
				if hostnames, exists := rec["hostnames"].([]interface{}); exists {
					for _, h := range hostnames {
						if hostname, ok := h.(string); ok {
							subs = append(subs, hostname)
						}
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Failed to read DNS response:", err)
		return nil
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		fmt.Println("Failed to parse DNS JSON response:", err)
		return nil
	}

	subs := []string{}
	if data, ok := result["subdomains"].([]interface{}); ok {
		for _, s := range data {
			if subdomain, ok := s.(string); ok {
				subs = append(subs, fmt.Sprintf("%s.%s", subdomain, domain))
			}
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

// IMPROVED SAVING FUNCTION WITH ERROR HANDLING AND FALLBACK
func saveResults(domain string, allSubs []string, queries []string, outputPrefix string) error {
	// Create output directory if it doesn't exist
	outputDir := filepath.Dir(outputPrefix)
	if outputDir != "." && outputDir != "" {
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			fmt.Printf("Warning: Could not create directory %s: %v\n", outputDir, err)
		}
	}

	// Always save TXT first (most reliable format)
	txtFile := outputPrefix + ".txt"
	txtContent := strings.Join(allSubs, "\n")
	if err := os.WriteFile(txtFile, []byte(txtContent), 0644); err != nil {
		fmt.Printf("Error: Failed to save TXT file %s: %v\n", txtFile, err)
		return err
	}
	fmt.Println("[+] TXT results saved to", txtFile)

	// Try to save JSON format
	jsonFile := outputPrefix + ".json"
	jsonData := map[string]interface{}{
		"domain":       domain,
		"total":        len(allSubs),
		"queries_used": queries,
		"subdomains":   allSubs,
	}

	// Attempt JSON marshaling with error handling
	jsonBytes, err := json.MarshalIndent(jsonData, "", "  ")
	if err != nil {
		fmt.Printf("Warning: JSON marshaling failed: %v\n", err)
		fmt.Println("[!] Falling back to CSV format...")
		return saveCSVFallback(domain, allSubs, outputPrefix)
	}

	// Attempt JSON file writing with error handling
	if err := os.WriteFile(jsonFile, jsonBytes, 0644); err != nil {
		fmt.Printf("Warning: Failed to save JSON file %s: %v\n", jsonFile, err)
		fmt.Println("[!] Falling back to CSV format...")
		return saveCSVFallback(domain, allSubs, outputPrefix)
	}

	fmt.Println("[+] JSON results saved to", jsonFile)
	return nil
}

// Fallback function to save as CSV if JSON fails
func saveCSVFallback(domain string, allSubs []string, outputPrefix string) error {
	csvFile := outputPrefix + ".csv"
	file, err := os.Create(csvFile)
	if err != nil {
		fmt.Printf("Error: Failed to create CSV file %s: %v\n", csvFile, err)
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	
	if err := writer.Write([]string{"Domain", "Subdomain"}); err != nil {
		fmt.Printf("Error: Failed to write CSV header: %v\n", err)
		return err
	}

	 
	for _, sub := range allSubs {
		if err := writer.Write([]string{domain, sub}); err != nil {
			fmt.Printf("Error: Failed to write CSV row: %v\n", err)
			return err
		}
	}

	fmt.Println("[+] CSV results saved to", csvFile)
	return nil
}

func main() {
	apiKey := flag.String("apikey", "", "Shodan API key (required)")
	output := flag.String("output", "", "Output file name (without extension)")
	flag.Parse()

	if len(flag.Args()) < 1 {
		fmt.Println("Usage: go run shodanX.go <domain> --apikey <your_api_key> [--output filename]")
		fmt.Println("Example: go run shodanX.go example.com --apikey YOUR_SHODAN_API_KEY --output results")
		os.Exit(1)
	}

	
	if *apiKey == "" {
		fmt.Println("Error: Shodan API key is required!")
		fmt.Println("Usage: go run shodanX.go <domain> --apikey <your_api_key> [--output filename]")
		fmt.Println("Example: go run shodanX.go example.com --apikey YOUR_SHODAN_API_KEY --output results")
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
		fmt.Sprintf("http.component:\"%s\"", domain),
		
		
		fmt.Sprintf("ssl.cert.subject.alt_names:\"%s\"", domain),
		fmt.Sprintf("ssl.cert.extensions.subject_alt_name:\"%s\"", domain),
		
		
		fmt.Sprintf("http.server:\"%s\"", domain),
		fmt.Sprintf("http.headers:\"%s\"", domain),
		fmt.Sprintf("http.location:\"%s\"", domain),
		
		// Mail servers and email-related services
		fmt.Sprintf("smtp.starttls.tls.certificate.parsed.subject.common_name:\"%s\"", domain),
		fmt.Sprintf("smtp.starttls.tls.certificate.parsed.extensions.subject_alt_name.dns_names:\"%s\"", domain),
		
		
		fmt.Sprintf("ftp.banner:\"%s\"", domain),
		
		s
		fmt.Sprintf("dns.txt:\"%s\"", domain),
		fmt.Sprintf("dns.mx:\"%s\"", domain),
		
		
		fmt.Sprintf("org:\"%s\"", domain),
		fmt.Sprintf("asn.description:\"%s\"", domain),
		
		
		fmt.Sprintf("ssl.cert.serial:\"%s\"", domain),
		fmt.Sprintf("ssl.cert.fingerprint:\"%s\"", domain),
		
		
		fmt.Sprintf("all:\"%s\"", domain),
		
		
		fmt.Sprintf("hostname:\"*.%s\"", domain),
		fmt.Sprintf("ssl.cert.subject.cn:\"*.%s\"", domain),
		fmt.Sprintf("ssl.cert.subject.alt_names:\"*.%s\"", domain),
	}

	var allSubs []string

	for _, q := range queries {
		fmt.Println("[*] Query:", q)
		subs := searchShodan(q, *apiKey)
		allSubs = append(allSubs, subs...)
	}

	
	dnsSubs := getDNSSubs(domain, *apiKey)
	allSubs = append(allSubs, dnsSubs...)

	// Remove duplicates
	allSubs = unique(allSubs)

	fmt.Printf("\n[+] Found %d unique subdomains:\n", len(allSubs))
	for _, s := range allSubs {
		fmt.Println(s)
	}

	
	if *output != "" {
		if err := saveResults(domain, allSubs, queries, *output); err != nil {
			fmt.Printf("Error: Failed to save results: %v\n", err)
			os.Exit(1)
		}
	}
}
