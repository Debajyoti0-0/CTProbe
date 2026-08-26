# ctprobe — Quick Start Guide

`ctprobe` enumerates the subdomains of a target domain from Certificate
Transparency logs (via crt.name) and probes their HTTP/S reachability. It is
intended for **authorized** security assessments and OSINT reconnaissance only.

> `ctprobe` is not an anonymity tool. `--stealth` lowers request rate and
> concurrency; it does not make traffic anonymous or undetectable.

---

## 1. Requirements

- **Python:** 3.9 or newer
- **Core dependencies (installed automatically):**
  - `requests[socks]` — HTTP/1.1 and fail-closed SOCKS/Tor routing
  - `urllib3`
  - `tldextract` — public-suffix-aware apex extraction
  - `aiohttp` — powers the asynchronous live-testing engine
- **Optional dependencies (features degrade gracefully without them):**
  - `httpx[http2]` — explicit `--http-version 2`
  - `openpyxl` — `--output xlsx`
  - `rich` — enhanced terminal UI / progress display
  - `curl` built with HTTP/3 — `--http-version 3`

---

## 2. Installation

From the project root:

```bash
cd /Users/dhaldar/POC/ctprobe

# Recommended: install the package (provides the `ctprobe` command)
pip install -e .

# Or install just the pinned dependency set
pip install -r requirements.txt
```

### Optional extras

```bash
pip install -e '.[http2]'   # HTTP/2 via httpx
pip install -e '.[xlsx]'    # Excel output via openpyxl
pip install -e '.[rich]'    # Enhanced terminal UI
pip install -e '.[dev]'     # Test tooling (pytest, pytest-cov, pytest-mock)

# All optional runtime extras at once
pip install -e '.[http2,xlsx,rich]'
```

### HTTP/3 (optional)

HTTP/3 uses a `curl` subprocess and requires a curl built with HTTP/3 support:

```bash
# macOS (Homebrew)
brew install --HEAD curl

# Linux (Debian/Ubuntu)
sudo apt install curl   # check support: curl --version | grep http3

# Windows
winget install cURL.cURL
```

---

## 3. Running the tool

Two equivalent invocation styles:

```bash
ctprobe example.com --live          # console script (after `pip install`)
python3 -m ctprobe example.com --live   # module form (no install needed)
```

The examples below use the module form so they work without installation.

### Interactive mode (good for first-time use)

```bash
python3 -m ctprobe
# → prompts for a target domain
# → asks yes/no whether to perform live testing
```

### Command-line mode

```bash
# Subdomain enumeration only (no reachability testing)
python3 -m ctprobe example.com --no-live

# Subdomain enumeration + live reachability testing
python3 -m ctprobe example.com --live

# JSON output
python3 -m ctprobe example.com --live --output json

# Conservative ("stealth") scanning — slow, low request rate
python3 -m ctprobe example.com --live --stealth

# Threat heuristics
python3 -m ctprobe example.com --live --threat

# Combined example
python3 -m ctprobe example.com \
  --live \
  --workers 10 \
  --timeout 15 \
  --http-version 2 \
  --output xlsx \
  --threat \
  --verbose
```

### See every option

```bash
python3 -m ctprobe --help
```

---

## 4. Most-used options at a glance

| Option | Purpose |
|--------|---------|
| `--live` / `--no-live` | Force enable / skip live testing (otherwise prompted) |
| `--match-code 200-299,301` | Match these HTTP codes (also auto-enables testing) |
| `--filter-code 404,500-599` | Exclude codes from the match set (takes precedence) |
| `--http-version auto\|1.1\|2\|3` | Protocol selection (`auto` tries HTTP/3 → HTTP/2 → HTTP/1.1) |
| `--force` | Do not fall back if the chosen protocol fails |
| `--workers 30` | Concurrent workers (default: 30) |
| `--timeout 10.0` | Per-request timeout in seconds |
| `--stealth` | Low-rate mode with randomized delays and reduced concurrency |
| `--stealth-min-delay` / `--stealth-max-delay` | Delay bounds in stealth mode |
| `--proxy http://host:port` | Route through an HTTP/SOCKS proxy |
| `--tor` | Route through Tor (default `socks5h://127.0.0.1:9050`) |
| `--bypass-tls` / `--bypass-ssl` | Disable certificate verification (authorized testing only) |
| `--threat` | Run threat heuristics |
| `--header "K: V"` | Add a custom header (repeatable) |
| `--user-agent "Custom/1.0"` | Set the User-Agent |
| `--output txt\|json\|xlsx` | Output format (default: `txt`) |
| `-f NAME` | Custom output basename |
| `--output-dir ./out` | Output directory (default: `Outputs`) |
| `--verbose` / `--debug` / `--quiet` | Verbosity control |

Default match set when `--match-code` is not given:
`200-299,301,302,307,401,403,405,500`. Use `--match-code all` for `100-599`,
then subtract with `--filter-code`.

---

## 5. Output files

Output is written under `Outputs/` (or `--output-dir`) using atomic writes.

**With live testing enabled:**

```
Outputs/
├── example.com.ALL-output.txt    # every discovered subdomain
└── example.com.LIVE-output.txt   # only reachable (matched) subdomains
```

**Discovery only (`--no-live`):**

```
Outputs/
└── example.com.output.txt
```

**Other formats** (`--output json` / `--output xlsx`) produce the same names with
`.json` / `.xlsx` extensions. A custom basename via `-f my-scan` yields
`my-scan.ALL-output.*` and `my-scan.LIVE-output.*`.

### Example JSON record

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

A subdomain is reported `LIVE` only when its response is **matched** by the
effective status-code policy — not on HTTP 200 alone. DNS, TLS, timeout, proxy,
and connection failures have no HTTP status and are reported as network failures.

---

## 6. Running the tests

```bash
pip install -e '.[dev]'          # or: pip install pytest pytest-cov pytest-mock

pytest tests/                    # run the full suite (118 tests)
pytest tests/test_scanner.py -v  # verbose
pytest tests/ --cov=ctprobe --cov-report=html   # with coverage
```

---

## 7. Common issues & fixes

**`No module named ctprobe`**
Run from the project root, or install the package:
```bash
cd /Users/dhaldar/POC/ctprobe
pip install -e .
```

**`HTTP/2 requires httpx`**
```bash
pip install 'httpx[http2]'
```

**`XLSX output requires openpyxl`**
```bash
pip install openpyxl
```

**HTTP/3 unavailable** — install a curl built with HTTP/3 (`brew install --HEAD curl`).

**LibreSSL / OpenSSL warning** — the TLS backend is fixed by how Python itself was
built; installing `requests` does not change it. The scan continues regardless.
Inspect the active runtime with:
```bash
python3 -c "import ssl; print(ssl.OPENSSL_VERSION)"
```
For a durable fix, use a Python linked against OpenSSL 1.1.1+ or OpenSSL 3.x.

**Rate limited (HTTP 429)** — scan more gently:
```bash
python3 -m ctprobe example.com --live --stealth --stealth-min-delay 5
```

**Tor connection failed** — ensure Tor is running on `127.0.0.1:9050`:
```bash
# macOS (Homebrew)
brew install tor && brew services start tor

# Linux (Debian/Ubuntu)
sudo apt install tor && sudo systemctl start tor

# Windows
winget install TorProject.TorBrowser   # run Tor Browser's bundled daemon

# Verify
curl --socks5 127.0.0.1:9050 https://check.torproject.org
```

---

## 8. Feature summary

- ✅ Query Certificate Transparency logs (crt.name) for issued certificates
- ✅ Extract, normalize, and deduplicate certificate-derived subdomains
- ✅ Live HTTP/S reachability testing with status-code matching/filtering
- ✅ HTTP/1.1, HTTP/2, and HTTP/3 support with auto-negotiation
- ✅ Asynchronous concurrent testing (configurable workers)
- ✅ Conservative "stealth" scanning with randomized delays
- ✅ Proxy and Tor routing (fail-closed)
- ✅ TLS verification control
- ✅ Custom headers and User-Agent (credentials redacted in debug output)
- ✅ Threat heuristics analysis
- ✅ TXT, JSON, and XLSX output with atomic writes
- ✅ Rich-enhanced terminal UI when `rich` is installed

---

## 9. Further reading

- [../README.md](../README.md) — complete reference documentation
- [IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md) — architecture and technical details
- `python3 -m ctprobe --help` — full, authoritative option list
- `tests/test_scanner.py` — worked examples of every module's behavior

---

## 10. Responsible use

Only run `ctprobe` against domains and systems you own or are explicitly
authorized to test. Keep TLS verification enabled unless you have a specific,
authorized reason to disable it. Respect `HTTP 429` responses and `Retry-After`
headers; use `--stealth` to reduce load.
