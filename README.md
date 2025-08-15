# shodanX

A small Go command-line tool to collect hostnames/subdomains from Shodan for a target domain. It queries multiple Shodan endpoints (host/search and DNS API), extracts hostnames from responses (hostnames, SSL certificate fields, HTTP data), de-duplicates results, and can optionally verify DNS resolution.

---

## Features

* Run multiple Shodan queries that target certificate fields, hostnames, HTTP content, org, and general results.
* Paginated requests for `host/search` (configurable pages).
* Rate limiting and concurrency controls to avoid hitting API limits.
* Robust JSON parsing of Shodan responses to extract hostnames and certificate SANs.
* Optional DNS verification of discovered hostnames.
* Save results to TXT and JSON files with metadata.

---

## Requirements

* Go 1.20+ installed (or a recent Go toolchain).
* A valid Shodan API key.

---

## Installation

1. Clone or copy the repository files.
2. Place `shodanX.go` in the project directory.
3. Build:

```bash
go build -o shodanX shodanX.go
```

Or run directly with `go run`.

---

## Usage

```
shodanX -domain <domain> -apikey <YOUR_SHODAN_KEY> [flags]
```

### Flags

* `-apikey` (string, required) – Shodan API key.
* `-domain` (string, required) – Domain to search (e.g. `example.com`).
* `-output` (string) – Output filename prefix (creates `.txt` and `.json`).
* `-pages` (int, default: 2) – Max pages to fetch per query from `/shodan/host/search`.
* `-concurrency` (int, default: 1) – Number of concurrent queries.
* `-timeout` (int, default: 15) – HTTP client timeout in seconds.
* `-rps` (int, default: 1) – Requests per second (rate limiting).
* `-verify` (bool) – Verify hostnames with DNS lookups (slow).

---

## Examples

Basic (run and print results to stdout):

```bash
./shodanX -domain atw.ltd -apikey MROkuK8hcziWeWlKwj5xKlXyJCRpwht5
```

Save results to files and increase pages:

```bash
./shodanX -domain atw.ltd -apikey <KEY> -output subs -pages 3
```

Use concurrency and higher request rate (only if your Shodan plan allows it):

```bash
./shodanX -domain atw.ltd -apikey <KEY> -output subs -concurrency 2 -rps 2
```

Verify DNS resolution for discovered hostnames (may be slow):

```bash
./shodanX -domain atw.ltd -apikey <KEY> -verify
```

---

## Output

If `-output <name>` is provided, two files are created:

* `<name>.txt` — newline-separated hostnames.
* `<name>.json` — JSON with metadata (`domain`, `total`, `queries_used`, `subdomains`, `generated_at`).

If `-output` is not provided, results are printed to stdout.

---

## Notes & Tips

* **Rate limits:** Keep `-rps` low (1) unless you know your Shodan plan supports higher throughput. Exceeding rate limits may lead to errors or blocked requests.
* **Pages:** Increasing `-pages` will attempt to fetch more pages of search results, but this increases API usage and runtime.
* **Field variance:** Shodan responses vary across services and time. The tool parses multiple possible certificate and HTTP fields defensively, but it may not extract every possible host depending on response shape.
* **DNS verification:** DNS lookups can filter to only resolvable hosts, but some valid hostnames (e.g., internal or ephemeral) may not resolve publicly and will be omitted if `-verify` is used.

---

## Troubleshooting

* **Permission errors building/running:** Ensure Go is installed and you have execution permissions. Use `chmod +x shodanX` after building to make it executable.
* **HTTP errors / non-200 responses:** Check your API key and Shodan account limits. The tool prints response details to stderr for debugging.
* **Slow runs:** Lower `-pages`, reduce `-verify`, or increase `-rps` conservatively.

---

## Contributing

Contributions are welcome. Suggestions:

* Add `crt.sh` and `Censys` aggregation and dedupe.
* Add output formats (CSV) or integrations (Amass, Subfinder).
* Replace manual parsing with typed structs for stricter JSON handling.

If you want, open an issue or PR with proposed changes.




