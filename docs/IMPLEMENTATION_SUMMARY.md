# ctprobe — Implementation Summary

Technical overview of `ctprobe`, a Certificate Transparency subdomain-enumeration
and HTTP/S reconnaissance tool. This document describes the package architecture,
each module's responsibility, the data model, the testing surface, and the
project's runtime characteristics.

- **Package:** `ctprobe`
- **Version:** 1.0.0
- **Python:** 3.9+
- **Console entry point:** `ctprobe = ctprobe.main:main`
- **Module entry point:** `python3 -m ctprobe`
- **License:** GPL-3.0-or-later (see `LICENSE`)

---

## 1. Project layout

```
ctprobe/
├── ctprobe/                  # Main package (18 modules)
│   ├── __init__.py           # Package metadata
│   ├── __main__.py           # `python3 -m ctprobe` entry point
│   ├── main.py               # Scan orchestration
│   ├── cli.py                # CLI / argument parsing → ScanConfig
│   ├── models.py             # Dataclasses and enums
│   ├── domain.py             # Domain normalization & validation
│   ├── crt_client.py         # Certificate Transparency (crt.name) client
│   ├── http_client.py        # Multi-protocol HTTP abstraction (1.1/2/3)
│   ├── async_engine.py       # Asynchronous aiohttp live-testing engine
│   ├── live_test.py          # Live reachability testing engine
│   ├── network.py            # Fail-closed proxy/Tor routing configuration
│   ├── status_policy.py      # HTTP status-code parsing & classification
│   ├── threat.py             # Threat heuristics analyzer
│   ├── output.py             # Result output & export (TXT/JSON/XLSX)
│   ├── presentation.py       # Rich-enhanced progress & result display
│   ├── terminal.py           # Terminal capability & color handling
│   ├── logging_utils.py      # Logging and formatting
│   └── environment.py        # Environment checks (TLS backend)
├── tests/
│   └── test_scanner.py       # Test suite (118 tests)
├── docs/
│   ├── QUICKSTART.md         # Getting-started guide
│   └── IMPLEMENTATION_SUMMARY.md   # This document
├── debian/                   # Debian packaging metadata
├── man/                      # Man page
├── README.md                 # Complete reference documentation
├── pyproject.toml            # Build config, dependencies, entry points
├── requirements.txt          # Pinned dependency set
└── LICENSE
```

---

## 2. Module responsibilities

### `models.py` — data structures
Dataclasses and enums shared across the package:

- **`LiveTestResult`** — full result for a single tested subdomain: `domain`,
  `live`, `status_code`, `scheme`, `final_url`, `http_version`, `response_time_ms`,
  `error`, `error_type`, `redirect_count`, `server`, `content_type`,
  `timestamp`, `threat_score`, `threat_level`, `threat_indicators`.
- **`ScanConfig`** — a scan session's fully-resolved configuration (every CLI
  option, normalized).
- **`ScanSummary`** — aggregate statistics for a completed scan.
- **`ErrorType`** enum — `DNS_ERROR`, `CONNECTION_ERROR`, `CONNECTION_TIMEOUT`,
  `TLS_ERROR`, `HTTP_429`, `HTTP_5XX`, `PROXY_ERROR`, `INVALID_URL`,
  `UNKNOWN_ERROR`.
- **`ThreatLevel`** enum — `NONE`, `LOW`, `MEDIUM`, `HIGH`.

### `domain.py` — normalization & validation
- Lowercasing, trailing-dot removal, scheme/path/port stripping, URL parsing for
  edge cases.
- Extraction of certificate DNS names from arbitrary text; case-insensitive
  deduplication; deterministic sorting; wildcard-certificate handling;
  label-aware subdomain membership (`is_subdomain_of`) so suffix lookalikes
  such as `evil-example.com` never match the target apex.
- Validation: label length (1–63), total length (≤253), allowed characters,
  hyphen placement rules. Uses `tldextract` for public-suffix-aware apex.

### `crt_client.py` — Certificate Transparency client
- Queries the crt.name API for certificates issued to a target.
- Returns raw certificate DNS names; filtering to the target apex happens in
  the orchestration layer (`main.py`) via label-aware matching.
- Handles HTTP errors (413, 429, …), empty responses, connection errors, and
  timeouts, mapping failures to `ErrorType` classifications.

### `http_client.py` — protocol abstraction
- Unified API over **HTTP/1.1** (`requests`), **HTTP/2** (`httpx`), and
  **HTTP/3** (`curl` subprocess).
- Auto-negotiation (HTTP/3 → HTTP/2 → HTTP/1.1) or explicit selection; `--force`
  disables fallback.
- Proxy/Tor routing, TLS verification control, custom headers/User-Agent,
  response-time measurement, redirect tracking, server-header extraction.

### `async_engine.py` — asynchronous engine
- `aiohttp`-based concurrent live-testing engine driving high-throughput scans
  with bounded concurrency.

### `live_test.py` — reachability testing
- HTTPS-first strategy with HTTP fallback; per-subdomain timeouts.
- Concurrent testing with configurable workers (default 30; stealth reduces it).
- Failure isolation — one failed subdomain never aborts the scan.
- Classifies each result as reachable or not, with detailed error context.

### `network.py` — routing configuration
- Unified, **fail-closed** proxy and Tor configuration: if a requested route
  (e.g. Tor/SOCKS) cannot be honored, requests fail rather than leaking over a
  direct connection.

### `status_policy.py` — status classification
- Parses `--match-code` / `--filter-code` expressions (single codes, ranges,
  comma-separated lists, `all`).
- Centralized classification of every response as `MATCHED`, `FILTERED`, or
  `NOT_MATCHED`. `--filter-code` takes precedence over `--match-code`; removing
  every match code is rejected before scanning.
- Default match set: `200-299,301,302,307,401,403,405,500`.

### `threat.py` — threat heuristics
- Indicators: suspicious TLDs, suspicious keywords (login, verify, secure,
  wallet, payment, …), very long names (>50 chars), excessive hyphens (≥3),
  long digit runs, excessive subdomain depth (>4).
- Score-based `ThreatLevel` classification. Heuristic only — not authoritative.

### `output.py` — export
- Formats: **TXT** (one subdomain per line, sorted), **JSON** (structured with
  metadata), **XLSX** (spreadsheet via `openpyxl`).
- File naming: live runs produce `NAME.ALL-output.ext` + `NAME.LIVE-output.ext`;
  discovery-only runs produce `NAME.output.ext`. Custom basename and output
  directory supported; directories auto-created.
- **Atomic writes** — write to a temp file then atomically replace, so an
  interrupted run never leaves a corrupt output.

### `presentation.py` / `terminal.py` — display
- `presentation.py`: `rich`-enhanced progress and result rendering (degrades
  gracefully to plain text when `rich` is absent).
- `terminal.py`: terminal capability detection and color-output handling.

### `logging_utils.py` — logging
- Verbosity levels (info/warning/error/verbose/debug), quiet mode, stdout vs
  stderr routing, non-spammy status/progress updates.
- **Credential redaction** — proxy URLs and sensitive header values are redacted
  in debug output; passwords/tokens are never printed.

### `environment.py` — environment checks
- Detects the TLS backend (OpenSSL/LibreSSL) and emits a compatibility warning,
  then continues. The backend is fixed by the Python build, not by `requests`.

### `cli.py` / `main.py` — CLI & orchestration
- `cli.py`: full `argparse` interface; transforms args into a validated
  `ScanConfig` (header parsing, proxy/Tor conflict detection, stealth checks,
  status-code policy validation).
- `main.py`: the workflow —
  1. Resolve and validate the target domain
  2. Check the TLS environment
  3. Fetch certificates from crt.name
  4. Normalize, deduplicate, and filter names to the target apex (label-aware)
  5. Decide on live testing (`--live` / `--no-live` / `--match-code`, else prompt)
  6. Run live testing (optional)
  7. Apply threat analysis (optional)
  8. Save results atomically
  9. Print a scan summary
- Graceful failure handling, meaningful errors, keyboard-interrupt handling, and
  a `--debug` path for troubleshooting.

---

## 3. Dependencies

Declared in `pyproject.toml`.

**Core (required):**
- `requests[socks] >= 2.28.0` — HTTP/1.1 and fail-closed SOCKS/Tor
- `urllib3 >= 1.26.0`
- `tldextract >= 5.1.0` — public-suffix-aware apex
- `aiohttp >= 3.8, < 4` — asynchronous live-testing engine

**Optional extras (feature degrades gracefully without each):**
- `http2` → `httpx[http2] >= 0.24.0` — explicit `--http-version 2`
- `xlsx` → `openpyxl >= 3.10.0` — `--output xlsx`
- `rich` → `rich >= 13.0.0` — enhanced terminal UI
- `dev` → `pytest >= 7.0.0`, `pytest-cov >= 4.0.0`, `pytest-mock >= 3.10.0`

**External (optional):** `curl` built with HTTP/3 support for `--http-version 3`.

---

## 4. Test coverage

`tests/test_scanner.py` contains **118 tests**. Network calls are mocked, so the
suite runs without external dependencies. Coverage spans:

- **Domain handling** — normalization, URL parsing, validation, extraction,
  deduplication, wildcard handling, label-aware subdomain membership.
- **Status policy** — match/filter parsing (codes, ranges, `all`),
  precedence rules, and response classification.
- **Threat analysis** — TLD/keyword/length/hyphen/digit/depth indicators and
  level classification.
- **Output** — filename sanitization, TXT/JSON/XLSX writing, path generation,
  atomicity.
- **Models** — construction and dictionary serialization.
- **Error classification** — timeout, DNS, TLS, proxy, connection mappings.
- **Logging** — quiet/verbose/debug modes and credential redaction.
- **Networking** — fail-closed proxy/Tor configuration.
- **Integration** — end-to-end discovery workflow.

Run the suite:

```bash
pip install -e '.[dev]'
pytest tests/
pytest tests/ --cov=ctprobe --cov-report=html
```

---

## 5. Live-classification semantics

A subdomain is reported `LIVE` only when its HTTP response is **matched** by the
effective status-code policy (`status_policy.py`) — not on HTTP 200 alone:

- A response is classified `MATCHED`, `FILTERED`, or `NOT_MATCHED`.
- `--filter-code` takes precedence over `--match-code`.
- Removing every match code is rejected before the scan starts.
- DNS, TLS, timeout, proxy, and connection failures have no HTTP status and are
  reported as network failures (see `ErrorType`), never as live.

---

## 6. Security considerations

- ✅ TLS verification enabled by default; `--bypass-tls` is opt-in for
  authorized testing only.
- ✅ Credential redaction for proxy URLs and headers in debug output.
- ✅ Safe, sanitized output filenames.
- ✅ Fail-closed routing — Tor/proxy failures do not silently fall back to a
  direct connection.
- ✅ Timeouts guard against hung requests; redirect limits guard against loops.
- ✅ No arbitrary command execution (the HTTP/3 path invokes `curl` with fixed,
  validated arguments).

---

## 7. Known limitations

1. **crt.name rate limiting** — targets with thousands of certificates may be
   rate-limited by the CT source.
2. **Protocol negotiation** — the reported HTTP version reflects the underlying
   client library and may not be perfectly precise.
3. **Threat analysis** — heuristic only; not a substitute for real threat
   intelligence.
4. **Redirect limits** — bounded (typically ~30) to prevent loops.
5. **Very large sets** — 10,000+ subdomains may benefit from further memory/CPU
   tuning.

---

## 8. Related documentation

- [../README.md](../README.md) — complete reference documentation
- [QUICKSTART.md](QUICKSTART.md) — installation and first-run guide
- `python3 -m ctprobe --help` — authoritative, full option list
- `tests/test_scanner.py` — executable specification of module behavior
