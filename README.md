# ctprobe — Certificate Transparency Subdomain Enumeration & HTTP/S Reconnaissance

A command-line tool for enumerating the subdomains of a target domain from
Certificate Transparency logs and probing their HTTP/S reachability. Intended
for **authorized** security assessments and OSINT reconnaissance only.

> `ctprobe` is not an anonymity tool. `--stealth` lowers request rate and
> concurrency; it does not make traffic anonymous or undetectable.

**Features:**
- Query crt.name for SSL certificates issued to a target domain
- Extract, normalize, and deduplicate certificate-derived subdomains
- Test discovered subdomains for HTTP/S reachability
- Support for HTTP/1.1, HTTP/2, and HTTP/3
- Conservative ("stealth") scanning mode with rate limiting
- Concurrent testing with configurable workers
- Output in TXT, JSON, or XLSX format
- Basic threat heuristics analysis
- Proxy and Tor support
- TLS verification control
- Custom headers and User-Agent

## How It Works

1. You supply a **target (apex) domain** — e.g. `example.com`. A full URL or a
   deep subdomain is normalized down to the registrable apex first.
2. `ctprobe` queries **Certificate Transparency** data (via crt.name) for
   certificates issued under that apex.
3. **Certificate DNS names** (SAN entries) are extracted from the response.
4. Names are **normalized** (lowercased, trailing dots and wildcards stripped)
   and **deduplicated**.
5. Names are **filtered to the target apex** using label-aware matching, so
   sibling or unrelated certificate names are dropped. The result is a set of
   **subdomains** associated with the target — e.g. `www.example.com`,
   `api.example.com`, `dev.example.com` (the apex itself is included).
6. Optionally, each subdomain is **probed over HTTP/S** to test reachability.
7. Responses are classified against a status-code policy you control with
   `-mc`/`--match-code` and `-fc`/`--filter-code`. A subdomain is reported
   **LIVE** only when its response is *matched* by the effective policy.

> **What the results represent.** `ctprobe` reports the certificate-derived DNS
> names returned by the CT source for your apex query, filtered to the target
> apex with label-aware matching. CT logs only ever reveal names that appear in
> *issued certificates* — hosts that never had a public certificate will not
> appear. Wildcard certificate entries (`*.example.com`) are reduced to the
> parent domain rather than expanded into concrete hosts. Treat the output as a
> strong starting point for reconnaissance, not an exhaustive subdomain list.

## Requirements

- **Python:** 3.9+
- **Core:** requests, urllib3
- **Optional - HTTP/2:** httpx[http2]
- **Optional - Excel output:** openpyxl
- **Optional - HTTP/3:** curl with HTTP/3 support

## Installation

### Basic Setup

```bash
# Clone or navigate to the project directory
cd ctprobe

# Install core dependencies
pip install -r requirements.txt
```

### Optional Dependencies

```bash
# Enable HTTP/2 support
pip install 'httpx[http2]'

# Enable Excel output (XLSX)
pip install openpyxl

# Enable HTTP/3 support
# Requires curl with HTTP/3: brew install --HEAD curl (macOS with Homebrew)
```

## Usage

### Interactive Mode

```bash
python -m ctprobe
```

Prompts for a target domain, then asks whether to perform live testing.

### Command-Line Mode

```bash
# Enumerate subdomains only
python -m ctprobe example.com --no-live

# Enumerate subdomains and test them live
python -m ctprobe example.com --live

# Enumerate, test, and write JSON output
python -m ctprobe example.com --live --output json

# Conservative scanning (slow, low-rate)
python -m ctprobe example.com --live --stealth

# Custom settings
python -m ctprobe example.com \
  --live \
  --workers 5 \
  --timeout 15 \
  --http-version 2 \
  --output xlsx \
  --threat
```

## Common Options

### Target Domain
```bash
python -m ctprobe example.com          # Positional argument
python -m ctprobe                       # Interactive prompt
```

### Live Testing
```bash
--live                  # Automatically perform live testing
--no-live              # Skip live testing (discovery only)
-mc 200                 # Match HTTP 200 and automatically enable testing
-mc all -fc 400-599    # Match 100-399; --match-code never prompts
```

Supplying `--match-code` is an explicit request for HTTP response matching,
so it automatically enables testing. It cannot be combined with `--no-live`.
Without `--live`, `--no-live`, or `--match-code`, the interactive y/n prompt
is used. In quiet mode, testing is skipped rather than waiting for input.

### HTTP Protocol
```bash
--http-version auto   # Try HTTP/3 → HTTP/2 → HTTP/1.1 (default)
--http-version 1.1    # HTTP/1.1 only
--http-version 2      # HTTP/2 only
--http-version 3      # HTTP/3 only
--force               # Don't fall back if selected protocol fails
```

### Network & Routing
```bash
--proxy http://127.0.0.1:8080       # HTTP proxy
--tor                               # Use Tor (default: socks5h://127.0.0.1:9050)
--tor socks5://127.0.0.1:9050       # Custom Tor endpoint
```

### TLS/SSL
```bash
--bypass-tls          # Disable certificate verification (insecure)
--bypass-ssl          # Alias for --bypass-tls
```

### Performance & Concurrency
```bash
--workers 30          # Concurrent workers (default: 30)
--timeout 10.0        # HTTP timeout in seconds (default: 10.0)
--stealth             # Low-rate scanning mode
--stealth-min-delay 1.0      # Minimum stealth delay (default: 1.0)
--stealth-max-delay 3.0      # Maximum stealth delay (default: 3.0)
```

### Analysis & Output
```bash
--threat              # Run threat heuristics
--match-code 200      # Match one status code
--match-code 200-299,301,302  # Match ranges and comma-separated codes
--filter-code 404,500-599     # Exclude codes from the match set
# Default matches: 200-299,301,302,307,401,403,405,500
# Use --match-code all for 100-599, then subtract --filter-code values
--output txt          # TXT format (default)
--output json         # JSON format
--output xlsx         # Excel format
-f results            # Custom filename (creates results.ALL-output.* and results.LIVE-output.*)
--output-dir ./out    # Output directory (default: Outputs)
```

Live classification is based on the effective status-code policy, not on
HTTP 200 alone. A received response can be `MATCHED`, `FILTERED`, or
`NOT_MATCHED`; a domain is `LIVE` only when its response is matched. DNS,
TLS, timeout, proxy, and connection failures have no HTTP status and are
reported as network failures. `--filter-code` takes precedence over
`--match-code`; removing every match code is rejected before scanning.

### Verbosity
```bash
--verbose             # Detailed progress
--debug               # Debugging information
--quiet               # Minimal output
```

### Custom Headers
```bash
--header "Accept: text/html"              # Single header
--header "X-Custom: value"                # Can repeat for multiple headers
--user-agent "Custom/1.0"                 # Custom User-Agent
```

## Example Workflows

### 1. Quick Subdomain Enumeration

```bash
python -m ctprobe example.com --no-live
```

Enumerates subdomains, saves to `Outputs/example.com.output.txt`.

### 2. Complete Reachability Audit

```bash
python -m ctprobe example.com --live --output json
```

Enumerates subdomains, tests reachability, saves to:
- `Outputs/example.com.ALL-output.json` (all discovered)
- `Outputs/example.com.LIVE-output.json` (reachable only)

### 3. Conservative Scanning Through Proxy

```bash
python -m ctprobe example.com \
  --live \
  --stealth \
  --stealth-min-delay 2 \
  --stealth-max-delay 5 \
  --proxy http://proxy.local:8080 \
  --workers 2
```

Slow, conservative scanning with random delays.

### 4. Threat Analysis

```bash
python -m ctprobe example.com --live --threat --output xlsx
```

Includes threat heuristic analysis in results. Saves as Excel file.

### 5. Tor-Routed Scanning

```bash
python -m ctprobe example.com --live --tor
```

Routes requests through Tor (requires Tor running on localhost:9050).

### 6. Force HTTP/2

```bash
python -m ctprobe example.com --live --http-version 2 --force
```

Use HTTP/2 only; fail if unavailable.

## Output Formats

### TXT (Plain Text)

One subdomain per line, sorted.

```
api.example.com
mail.example.com
www.example.com
```

### JSON (Structured)

Rich metadata including status codes, HTTP versions, response times.

```json
{
  "domain": "www.example.com",
  "live": true,
  "status_code": 200,
  "scheme": "https",
  "final_url": "https://www.example.com/",
  "http_version": "HTTP/2",
  "response_time_ms": 142.5,
  "threat_level": "none",
  "threat_score": 0
}
```

### XLSX (Excel)

Spreadsheet with columns: Subdomain, Live, Status Code, Scheme, Final URL, HTTP Version, Response Time, Threat Level, etc.

## Files Generated

### When Live Testing is Enabled

```
Outputs/
  └─ example.com.ALL-output.txt   # All discovered subdomains
  └─ example.com.LIVE-output.txt  # Only reachable subdomains
```

### When Live Testing is Disabled

```
Outputs/
  └─ example.com.output.txt       # All discovered subdomains
```

### With Custom Filename

```
Outputs/
  └─ my-scan.ALL-output.txt       # All discovered subdomains
  └─ my-scan.LIVE-output.txt      # Reachable subdomains only
```

## Stealth Mode

**What It Is:**
- Low-rate, conservative scanning
- Reduced concurrency
- Randomized request spacing
- Respectful retry behavior
- Connection reuse where possible
- Rates limiting compliance

**What It Is NOT:**
- Anonymous or undetectable
- WAF/IDS bypass
- Invisibility
- Rate-limit defeat

**Use When:**
- Testing systems you own or are authorized to test
- Want to avoid unnecessary network load
- Prefer stability over speed

## Threat Analysis

**Heuristic Indicators:**

- Suspicious TLDs (.zip, .tk, .ga, .cf, etc.)
- Suspicious keywords (login, verify, secure, wallet, payment, etc.)
- Very long domains (>50 chars)
- Excessive hyphens (≥3)
- Many consecutive digits
- Excessive subdomain depth (>4 levels)

**Threat Levels:**
- **NONE:** No suspicious indicators
- **LOW:** 1 indicator
- **MEDIUM:** 2-4 indicators
- **HIGH:** 5+ indicators

**Important:** These are heuristics only. Not an authoritative verdict.

## Error Handling

The scanner classifies errors:

- **DNS_ERROR:** Domain name resolution failed
- **CONNECTION_ERROR:** TCP connection refused or failed
- **CONNECTION_TIMEOUT:** Request timeout
- **TLS_ERROR:** SSL/TLS certificate or handshake failure
- **HTTP_429:** Rate limited by server
- **HTTP_5XX:** Server error response
- **PROXY_ERROR:** Proxy connection failed
- **INVALID_URL:** Malformed URL
- **UNKNOWN_ERROR:** Other errors

One failed subdomain never stops the scan—all discovered subdomains are tested.

## Troubleshooting

### OpenSSL/LibreSSL Warning

```
[!] TLS backend: LibreSSL 2.8.3
[!] urllib3 v2 officially supports OpenSSL 1.1.1+.
[!] Your Python ssl module is using LibreSSL.
[!] Consider using a Python build linked against OpenSSL 1.1.1+ or OpenSSL 3.x.
[+] Continuing with the current Python TLS environment.
```

The TLS backend is determined by the Python interpreter build. Installing or
upgrading `requests` does not replace the OpenSSL/LibreSSL implementation used
by Python's `ssl` module. Use this diagnostic command to inspect the active
runtime:

```bash
python3 -c "import ssl; print(ssl.OPENSSL_VERSION)"
```

For a durable fix, use a Python distribution or build linked against OpenSSL
1.1.1+ or OpenSSL 3.x. The exact upgrade or reinstall procedure depends on how
Python was installed on the host.

### HTTP/2 Not Available

```
[-] HTTP/2 requires httpx. Install with: pip install 'httpx[http2]'
```

**Solution:**
```bash
pip install 'httpx[http2]'
```

### HTTP/3 Not Available

```
[-] HTTP/3 requires curl with HTTP/3 support.
```

**Solution:**
```bash
# macOS with Homebrew
brew install --HEAD curl
```

### TLS Certificate Errors

```
[-] TLS error: certificate verify failed
```

**Solution (if authorized):**
```bash
python -m ctprobe example.com --bypass-tls
```

### Rate Limited (HTTP 429)

Normal—the server rejected the request due to rate limiting.

**Solution:**
```bash
python -m ctprobe example.com --stealth --stealth-min-delay 5
```

### Proxy Connection Failed

```
[-] Proxy error: connection refused
```

**Verify proxy is running and accessible:**
```bash
python -m ctprobe example.com --proxy http://127.0.0.1:8080 --debug
```

### Tor Connection Failed

Ensure Tor is running:
```bash
# macOS with Homebrew
brew install tor
brew services start tor

# Verify
curl --socks5 127.0.0.1:9050 https://check.torproject.org
```

## Security Considerations

### Authorized Testing Only

Only use this tool on domains and systems you own or have explicit authorization to test.

### TLS Verification

Always keep TLS verification enabled. `--bypass-tls` is for authorized testing only.

### Credentials

Never include credentials in:
- Domain names
- User-Agent strings
- Custom headers (automatic redaction in debug output)
- Proxy URLs (automatic redaction in debug output)

### Rate Limiting

Respect `HTTP 429` responses and `Retry-After` headers. Use `--stealth` for conservative scanning.

### Tor & Proxy

Using Tor or proxies for "anonymity" in security testing is unreliable. Use them for:
- Testing access policies
- Rotating IP addresses legitimately
- Routing through authorized gateways

## Performance Tips

### For Large Subdomain Sets (1000+)

```bash
python -m ctprobe example.com \
  --live \
  --workers 20 \
  --timeout 5 \
  --stealth \
  --stealth-min-delay 0.1 \
  --stealth-max-delay 0.5
```

### For Speed

```bash
python -m ctprobe example.com --live --workers 50 --timeout 5
```

### For Stability

```bash
python -m ctprobe example.com --live --workers 5 --timeout 15 --stealth
```

## Architecture

```
ctprobe/
  ├─ __init__.py           # Package info
  ├─ __main__.py           # Module entry point
  ├─ main.py               # Main orchestrator
  ├─ cli.py                # CLI/argument parsing
  ├─ models.py             # Data models (dataclasses)
  ├─ domain.py             # Domain normalization
  ├─ crt_client.py         # CRT.name API client
  ├─ http_client.py        # HTTP protocol abstraction
  ├─ live_test.py          # Live reachability testing
  ├─ threat.py             # Threat heuristics
  ├─ output.py             # Output/export functions
  ├─ logging_utils.py      # Logging and formatting
  └─ environment.py        # Environment checks
```

## Testing

```bash
# Install test dependencies
pip install pytest pytest-cov pytest-mock

# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=ctprobe --cov-report=html

# Run specific test file
pytest tests/test_scanner.py -v
```

## Development

### Adding Features

1. Add models to `models.py`
2. Add functionality to appropriate module
3. Add tests to `tests/`
4. Update README

### Code Style

- Follow PEP 8
- Use type hints
- Docstrings for public functions
- Use dataclasses for models

## Known Limitations

1. **CT Coverage & Precision:** Results are the certificate-derived DNS names
   returned for your apex query, filtered to the target apex with label-aware
   matching. CT logs only reveal names that appeared in an *issued
   certificate*, so subdomains without a public certificate are never found.
   The output can also include the apex itself, and wildcard entries are
   reduced to the parent domain rather than expanded. It is not an exhaustive
   or authoritative subdomain list.

2. **CRT.name Rate Limiting:** Large domains (1000s of certificates) may be rate-limited. Implement retry logic if needed.

3. **Protocol Negotiation:** Reported HTTP version depends on client library capabilities. May not be 100% accurate.

4. **Redirect Limits:** Follows up to typical redirect limits (usually 30). Protects against redirect loops.

5. **Threat Analysis:** Heuristic-only. Not a replacement for actual threat intelligence.

6. **Performance:** Very large subdomain sets (10,000+) may require memory/CPU optimization.

## License

[Specify your license here]

## Contributing

[Contribution guidelines]

## Support

For issues, feature requests, or questions:
[Contact information]
