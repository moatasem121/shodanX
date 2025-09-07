# ShodanX - Advanced Subdomain Discovery Tool

A powerful Go-based subdomain enumeration tool that leverages Shodan's extensive database to discover subdomains through multiple search vectors including SSL certificates, HTTP headers, DNS records, and more.

## Features

- **Multi-Vector Search**: Uses 20+ different Shodan search queries to maximize subdomain discovery
- **SSL Certificate Analysis**: Extracts subdomains from SSL certificate Subject Alternative Names (SANs)
- **DNS API Integration**: Utilizes Shodan's DNS API for additional subdomain discovery
- **Multiple Output Formats**: Saves results in TXT, JSON, and CSV formats with automatic fallback
- **Duplicate Removal**: Automatically removes duplicate subdomains from results
- **Error Handling**: Robust error handling with graceful fallbacks
- **Progress Tracking**: Real-time query progress and result counting

## Installation

### Prerequisites
- Go 1.16 or higher
- Valid Shodan API key

### Build from Source
```bash
git clone <repository-url>
cd shodanx
go build -o shodanx shodanx.go
```

### Or Run Directly
```bash
go run shodanx.go [options] <domain>
```

## Usage

### Basic Usage
```bash
./shodanx --apikey YOUR_SHODAN_API_KEY example.com
```

### With Output File
```bash
./shodanx --apikey YOUR_SHODAN_API_KEY --output results example.com
```

### Command Line Options
- `--apikey`: Shodan API key (required)
- `--output`: Output file prefix (optional, saves as .txt, .json, and .csv)

### Examples

**Scan a specific domain:**
```bash
./shodanx --apikey abc123def456 --output tesla_results tesla.com
```

**Scan a TLD (Top Level Domain):**
```bash
./shodanx --apikey abc123def456 --output mil_scan .mil
```

**Scan without saving to file:**
```bash
./shodanx --apikey abc123def456 github.com
```

## Search Queries

ShodanX uses multiple search vectors to maximize subdomain discovery:

### Certificate-Based Queries
- SSL certificate common names
- SSL certificate subject alternative names
- SSL certificate issuer information
- Certificate transparency logs

### HTTP-Based Queries
- HTTP titles and HTML content
- Server headers and components
- HTTP location headers
- HTTP metadata

### Network Service Queries
- SMTP/Mail server certificates
- FTP service banners
- DNS TXT and MX records

### Organizational Queries
- Organization names
- ASN descriptions
- Wildcard hostname patterns

## Output Formats

### TXT Format (Primary)
Plain text file with one subdomain per line:
```
subdomain1.example.com
subdomain2.example.com
www.example.com
```

### JSON Format
Structured JSON with metadata:
```json
{
  "domain": "example.com",
  "total": 25,
  "queries_used": ["hostname:\"example.com\"", "..."],
  "subdomains": ["sub1.example.com", "sub2.example.com"]
}
```

### CSV Format (Fallback)
CSV format with domain and subdomain columns:
```csv
Domain,Subdomain
example.com,sub1.example.com
example.com,sub2.example.com
```

## Error Handling

- **Graceful Fallbacks**: If JSON saving fails, automatically falls back to CSV
- **Directory Creation**: Automatically creates output directories if they don't exist
- **Network Resilience**: Handles API request failures gracefully
- **Input Validation**: Validates required parameters before execution

## API Rate Limits

- Respects Shodan API rate limits
- Uses efficient query batching
- Displays API key confirmation (first 8 characters) for verification

## Security Considerations

- API keys are masked in output (only first 8 characters shown)
- No sensitive data is logged to files
- Safe file handling with proper permissions

## Troubleshooting

### Common Issues

**"Error: Shodan API key is required!"**
- Ensure you provide the `--apikey` parameter
- Verify your API key is valid

**"Request failed" errors**
- Check your internet connection
- Verify your Shodan API key has sufficient credits
- Ensure you haven't exceeded rate limits

**"Failed to save" errors**
- Check write permissions in the output directory
- Ensure sufficient disk space
- Tool will automatically fallback to alternative formats

### Getting a Shodan API Key

1. Visit [shodan.io](https://shodan.io)
2. Create an account
3. Navigate to your account page
4. Copy your API key from the dashboard

## Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.



## Disclaimer

This tool is for educational and authorized security testing purposes only. Users are responsible for complying with all applicable laws and regulations. Only test against domains you own or have explicit permission to test.


---

**Note**: This tool requires a valid Shodan API key and sufficient API credits. Free Shodan accounts have limited query capabilities.
