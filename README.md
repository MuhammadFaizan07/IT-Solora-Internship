# ReconForge — Modular Reconnaissance Tool

**ITsolera PVT LTD — Summer Internship Task (Offensive Security / Tool Development)**
**Author:** Muhammad Faizan — B.S. Cybersecurity, MUET Jamshoro

A lightweight, modular CLI reconnaissance tool built in Python for the passive
and active information-gathering phases of an authorized penetration test.
Every capability is implemented as an independent module and wired into the
CLI through command-line flags, so individual modules can be run alone or
combined.

> ⚠️ **Authorized use only.** This tool performs active port scanning and
> banner grabbing. Only run it against domains/hosts you own or have
> explicit written permission to test.

---

## Features

| Category | Capability | Flag |
|---|---|---|
| Passive Recon | WHOIS lookup | `--whois` |
| Passive Recon | DNS enumeration (A, MX, TXT, NS) | `--dns` |
| Passive Recon | Subdomain enumeration (crt.sh + AlienVault OTX) | `--subdomains` |
| Active Recon | TCP port scanning (socket-based, threaded) | `--ports` |
| Active Recon | Banner grabbing on open ports | `--banner` |
| Active Recon | Web technology detection (header/HTML signatures) | `--techdetect` |
| Reporting | Generates `.txt` and/or `.html` report with timestamps and IP resolution | `--format` |
| Modularity | Each module runs independently with leveled logging (`-v`, `-vv`) | n/a |

Run everything in one shot with `--all` (also the default if no module flag
is given).

---

## Architecture

```
recontool/
├── recontool.py            # CLI entrypoint (argparse, orchestration, logging)
├── modules/
│   ├── whois_lookup.py     # WHOIS (python-whois, raw socket fallback)
│   ├── dns_enum.py         # DNS records via dnspython
│   ├── subdomain_enum.py   # crt.sh + AlienVault OTX passive sources
│   ├── port_scan.py        # Threaded TCP connect() scan + banner grab
│   ├── tech_detect.py      # HTTP header / HTML signature fingerprinting
│   └── report.py           # .txt / .html report generation
├── requirements.txt
├── Dockerfile               # Bonus: containerized deployment
└── reports/                 # Generated reports land here by default
```

Each module exposes a `run(...)` function returning a plain Python `dict`,
so modules are independently testable/importable and the CLI layer stays
thin — pure orchestration and argument parsing.

---

## Installation

```bash
git clone <your-repo-url>
cd recontool
python3 -m venv venv && source venv/bin/activate   # optional but recommended
pip install -r requirements.txt
```

Dependencies:
- `dnspython` — DNS record enumeration
- `python-whois` — WHOIS parsing (the tool falls back to a raw socket WHOIS
  query on port 43 automatically if this library or the lookup itself fails)

No API keys are required — crt.sh and AlienVault OTX passive-DNS endpoints
are public, and technology detection is done via lightweight signature
matching against headers/HTML rather than a paid Wappalyzer API.

---

## Usage

```bash
# Run every module against a target
python recontool.py example.com --all

# Run only passive recon
python recontool.py example.com --whois --dns --subdomains

# Port scan a custom range + grab banners, verbose
python recontool.py example.com --ports --ports-range 1-1000 --banner -v

# Full run, HTML-only report, custom output directory
python recontool.py example.com --all --format html --outdir my_reports

# Debug-level logging
python recontool.py example.com --all -vv
```

### CLI Reference

```
usage: recontool [-h] [--whois] [--dns] [--subdomains] [--ports]
                  [--ports-range PORTS_RANGE] [--banner] [--techdetect]
                  [--all] [--format {txt,html,both}] [--outdir OUTDIR]
                  [-v] [--version]
                  target

Passive Recon:
  --whois               Perform WHOIS lookup
  --dns                 Enumerate DNS records (A, MX, TXT, NS)
  --subdomains          Enumerate subdomains via crt.sh / OTX

Active Recon:
  --ports               Perform TCP port scan
  --ports-range RANGE   Port range to scan, e.g. 1-1024 (default: 1-1024)
  --banner              Grab service banners on open ports
  --techdetect          Detect web technologies (HTTP headers based)

General:
  --all                 Run all recon modules
  --format {txt,html,both}  Report output format (default: both)
  --outdir OUTDIR       Directory to write the report into (default: reports/)
  -v, --verbose         Increase verbosity (-v info, -vv debug)
  --version             Show tool version
```

---

## Sample Report

A sample run against `example.com` is included at:
`reports/recon_example.com_<timestamp>.txt` and `.html`

The report includes:
- Target domain and resolved IP address
- UTC timestamp of report generation
- A dedicated section per module that was run
- For port scan: scan start/finish timestamps, open ports, and detected service names

---

## Logging / Verbosity

- *(no flag)*: warnings and errors only
- `-v`: informational logs (module progress, record counts, etc.)
- `-vv`: full debug logs (per-request detail, fallback paths taken)

---

## Docker (Bonus)

```bash
docker build -t reconforge .
docker run --rm -v $(pwd)/reports:/app/reports reconforge example.com --all
```

The container mounts a local `reports/` directory so generated reports
persist outside the container.

---

## Notes on Design Choices

- **Port scanning** uses Python's `socket` + `concurrent.futures.ThreadPoolExecutor`
  for a dependency-free, portable connect() scan rather than shelling out to
  `nmap`, so the tool runs anywhere Python 3 runs without requiring nmap to
  be installed on the host.
- **Technology detection** is implemented via header/HTML signature matching
  rather than calling the whatweb/Wappalyzer APIs directly, removing the
  need for an external API key while still fulfilling the "detect
  technologies" requirement.
- **WHOIS** tries the `python-whois` library first for structured/parsed
  output, then falls back to a raw socket query against IANA's WHOIS
  referral chain if the library is unavailable or the lookup fails —
  ensuring the module degrades gracefully rather than crashing.
- **Subdomain enumeration** only queries passive/public certificate-
  transparency and passive-DNS sources (crt.sh, AlienVault OTX), so this
  module performs no active probing of the target, consistent with the
  "Passive Recon" classification in the task brief.

---

## Disclaimer

This tool is built strictly for educational and authorized
penetration-testing purposes as part of the ITsolera Offensive Security
internship task. Unauthorized scanning of systems you do not own or have
permission to test may violate computer-misuse laws in your jurisdiction.
