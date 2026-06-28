# Spot Phishing Domains Automatically (Phish-Detect)

A modular, production-grade automated threat intelligence system written in Python to continuously monitor and assess newly registered typosquatted or phishing domains imitating a target legitimate company brand domain.

---

## Features

- **Permutation Permutator**: Generates hundreds of variations of a legitimate domain name using character omission, repetition, transposition, keyboard proximity swaps, unicode homoglyphs, brand keyword prefixes/suffixes, and alternative TLD extensions.
- **DNS Inspector**: Checks A, AAAA, MX, NS, TXT, and CNAME records to flag low-redundancy name servers, missing email configurations, or suspicious mail server mappings.
- **WHOIS Registration Status**: Normalizes creation, expiration, registrar, organization, and country fields. Gracefully handles redacted or missing records.
- **Active Webpage Inspection**: Fetches HTTP/HTTPS endpoints, traces redirection chains, and parses titles, metadata, forms, password inputs, and phishing keywords.
- **Brand Impersonation Detection**: Computes a webpage content similarity score (using SequenceMatcher) and identifies asset hotlinking to the legitimate target domain.
- **Automated Web Screenshots**: Spawns a headless browser to capture screenshots of active domains (handling TLS validation overrides).
- **Weighted Scoring Engine**: Allocates numeric weights across multiple indicators to produce a risk score (0-100) and categorizes severity (Low, Medium, High, Critical).
- **Comparison Engine**: Calculates changes between consecutive runs to identify new registrations, removed domains, and escalated risks.
- **Multi-Format Export**: Writes reporting outputs to JSON, CSV, interactive HTML dashboards, and clean executive summary PDFs.

---

## Directory Structure

```text
Phish-Detect/
├── config.toml           # General configurations, thresholds, and weights
├── requirements.txt      # External python libraries
├── README.md             # Usage documentation
└── src/
    ├── __init__.py
    ├── config.py         # Loads and validates TOML configuration
    ├── logger.py         # Configures file and console logging outputs
    ├── generator.py      # Typo variation generator (homoglyphs, transposition)
    ├── whois_checker.py  # Performs registration queries and date normalizations
    ├── dns_checker.py    # Resolves standard DNS records and maps flags
    ├── ssl_checker.py    # Grabs socket TLS details, self-signed detection
    ├── website_checker.py# HTTP request fetch and BeautifulSoup content parsing
    ├── brand_detector.py # Compares brand name keywords and text similarity
    ├── screenshot_manager.py # Captures page screenshots using Playwright
    ├── risk_engine.py    # Calculates risk levels and weights
    ├── database.py       # SQLite tracking and delta scan comparisons
    ├── report_generator.py # Formats JSON, CSV, HTML, and PDF reports
    └── main.py           # Program orchestration CLI entrypoint
```

---

## Installation

### Prerequisites

- Python 3.12+
- Node.js (for Playwright browser engines, or automatically handled via pip installation)

### Automatic Setup (Windows)
Double-click `setup.bat` in the root folder, or run it in your terminal:
```powershell
.\setup.bat
```
This script automatically sets up the python virtual environment, installs dependencies, and provisions Playwright browser binaries.

### Manual Setup
1. **Navigate to the folder**:
   ```bash
   cd Phish-Detect
   ```
2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
3. **Install Playwright Chromium**:
   ```bash
   python -m playwright install chromium
   ```

---

## Configuration

Modify `config.toml` to customize domain scanning behavior:

```toml
[general]
target_domain = "google.com" # Brand domain to monitor
max_domains = 500            # Limits generated variants (0 for unlimited)
output_dir = "output"        # Target outputs folder
timeout = 10                 # Timeout in seconds
concurrency = 15             # Scanning worker threads
enable_screenshots = true    # Headless browser screenshot captures
```

---

## Usage

### Run Scan with default config
Executes Permutation, WHOIS, DNS, HTML Analysis, Screenshots, database check, and outputs reports under the `output/` directory:
```bash
python src/main.py
```

### Run Scan against a specific domain (Command override)
```bash
python src/main.py --domain example.com
```

### Disable screenshots (fast scan)
```bash
python src/main.py --no-screenshots
```

### Start Clean Interactive Mode
Launches a responsive command line shell inside your terminal to analyze single domain inputs interactively on the spot (skipping slow bulk permutation operations and screenshots):
```bash
python src/main.py --interactive
```

