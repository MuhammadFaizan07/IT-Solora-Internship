"""
Subdomain Enumeration Module
Queries 4 public passive-DNS / certificate-transparency sources:
  1. crt.sh          - Certificate Transparency logs
  2. AlienVault OTX  - Passive DNS database
  3. HackerTarget    - DNS lookup API
  4. RapidDNS        - Fast subdomain search

FALLBACK: If all APIs fail, performs a DNS brute-force using a built-in
wordlist of 80+ common subdomain names (mail, vpn, ftp, admin, etc.)
This guarantees results even on restricted networks.
"""

import json
import logging
import urllib.request
import urllib.error
import ssl
import socket
import time
import concurrent.futures

# ── Common subdomain wordlist for DNS brute-force fallback ────────────────────
COMMON_SUBDOMAINS = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "m", "shop", "ftp", "api", "dev", "staging",
    "portal", "admin", "web", "email", "cloud", "test", "old", "new",
    "beta", "apps", "app", "static", "media", "images", "img", "cdn",
    "assets", "mx", "mx1", "mx2", "pop", "imap", "autodiscover",
    "support", "help", "docs", "wiki", "demo", "hr", "erp", "crm",
    "cms", "login", "auth", "sso", "id", "accounts", "my", "student",
    "staff", "faculty", "library", "lms", "elearning", "online",
    "register", "admission", "result", "exam", "fee", "finance",
    "vc", "registrar", "oas", "ems", "academic", "research",
    "conference", "events", "news", "announcements", "download",
    "files", "upload", "share", "git", "gitlab", "github", "jira",
    "monitor", "status", "health", "backup", "db", "database",
    "mysql", "postgres", "redis", "cache", "proxy", "gateway",
    "firewall", "router", "switch", "wlan", "wireless", "iot",
]


def _http_get(url: str, timeout: int = 12) -> str:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json, text/plain, */*",
    }
    req = urllib.request.Request(url, headers=headers)
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return resp.read().decode(errors="ignore")
        except urllib.error.HTTPError as e:
            if e.code in (502, 503, 504) and attempt < 2:
                time.sleep(2)
                continue
            raise
        except Exception:
            if attempt < 2:
                time.sleep(1)
                continue
            raise
    return ""


# ── Source 1: crt.sh ──────────────────────────────────────────────────────────
def query_crtsh(domain: str, logger: logging.Logger) -> set:
    found = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        raw = _http_get(url, timeout=15)
        entries = json.loads(raw)
        for entry in entries:
            for sub in entry.get("name_value", "").split("\n"):
                sub = sub.strip().lower()
                if sub.endswith(domain) and "*" not in sub:
                    found.add(sub)
        logger.info(f"[crt.sh]         Found {len(found)} subdomains")
    except urllib.error.HTTPError as e:
        logger.warning(f"[crt.sh]         HTTP {e.code} — skipping")
    except urllib.error.URLError as e:
        logger.warning(f"[crt.sh]         Network error — skipping")
    except json.JSONDecodeError:
        logger.warning("[crt.sh]         Non-JSON response — skipping")
    except Exception as e:
        logger.warning(f"[crt.sh]         Failed: {e}")
    return found


# ── Source 2: AlienVault OTX ──────────────────────────────────────────────────
def query_otx(domain: str, logger: logging.Logger) -> set:
    found = set()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    try:
        raw = _http_get(url, timeout=12)
        data = json.loads(raw)
        for record in data.get("passive_dns", []):
            hostname = record.get("hostname", "").strip().lower()
            if hostname.endswith(domain):
                found.add(hostname)
        logger.info(f"[AlienVault OTX] Found {len(found)} subdomains")
    except urllib.error.HTTPError as e:
        logger.warning(f"[AlienVault OTX] HTTP {e.code} — skipping")
    except urllib.error.URLError as e:
        logger.warning(f"[AlienVault OTX] Network error — skipping")
    except Exception as e:
        logger.warning(f"[AlienVault OTX] Failed: {e}")
    return found


# ── Source 3: HackerTarget ────────────────────────────────────────────────────
def query_hackertarget(domain: str, logger: logging.Logger) -> set:
    found = set()
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        raw = _http_get(url, timeout=12)
        if "error" in raw.lower() and len(raw) < 100:
            logger.warning(f"[HackerTarget]   API limit reached: {raw.strip()}")
            return found
        for line in raw.strip().splitlines():
            if "," in line:
                sub = line.split(",")[0].strip().lower()
            else:
                sub = line.strip().lower()
            if sub.endswith(domain) and "*" not in sub:
                found.add(sub)
        logger.info(f"[HackerTarget]   Found {len(found)} subdomains")
    except urllib.error.HTTPError as e:
        logger.warning(f"[HackerTarget]   HTTP {e.code} — skipping")
    except urllib.error.URLError as e:
        logger.warning(f"[HackerTarget]   Network error — skipping")
    except Exception as e:
        logger.warning(f"[HackerTarget]   Failed: {e}")
    return found


# ── Source 4: RapidDNS ────────────────────────────────────────────────────────
def query_rapiddns(domain: str, logger: logging.Logger) -> set:
    found = set()
    url = f"https://rapiddns.io/subdomain/{domain}?full=1&down=1"
    try:
        raw = _http_get(url, timeout=12)
        for line in raw.splitlines():
            line = line.strip().lower()
            if line.endswith(domain) and " " not in line and "*" not in line:
                found.add(line)
        logger.info(f"[RapidDNS]       Found {len(found)} subdomains")
    except urllib.error.HTTPError as e:
        logger.warning(f"[RapidDNS]       HTTP {e.code} — skipping")
    except urllib.error.URLError as e:
        logger.warning(f"[RapidDNS]       Network error — skipping")
    except Exception as e:
        logger.warning(f"[RapidDNS]       Failed: {e}")
    return found


# ── Fallback: DNS Brute-Force ─────────────────────────────────────────────────
def _resolve(sub: str):
    try:
        socket.gethostbyname(sub)
        return sub
    except socket.gaierror:
        return None


def dns_bruteforce(domain: str, logger: logging.Logger) -> set:
    """
    Tries 80+ common subdomain names via direct DNS resolution.
    Runs in parallel using threads — fast even with large wordlists.
    This always works as long as you have internet (no API needed).
    """
    found = set()
    candidates = [f"{word}.{domain}" for word in COMMON_SUBDOMAINS]
    logger.info(f"[DNS Brute-force] Trying {len(candidates)} common subdomain names...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(_resolve, c): c for c in candidates}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                found.add(result)
                logger.info(f"[DNS Brute-force] FOUND: {result}")

    logger.info(f"[DNS Brute-force] Found {len(found)} subdomains via wordlist")
    return found


# ── Main run function ─────────────────────────────────────────────────────────
def run(domain: str, logger: logging.Logger) -> dict:
    result = {
        "domain": domain,
        "subdomains": [],
        "sources": {},
        "error": None,
    }

    logger.info(f"Querying 4 API sources for subdomains of: {domain}")

    crtsh_results        = query_crtsh(domain, logger)
    otx_results          = query_otx(domain, logger)
    hackertarget_results = query_hackertarget(domain, logger)
    rapiddns_results     = query_rapiddns(domain, logger)

    api_results = crtsh_results | otx_results | hackertarget_results | rapiddns_results

    result["sources"]["crt.sh"]         = sorted(crtsh_results)
    result["sources"]["alienvault_otx"] = sorted(otx_results)
    result["sources"]["hackertarget"]   = sorted(hackertarget_results)
    result["sources"]["rapiddns"]       = sorted(rapiddns_results)

    # If ALL APIs failed → run DNS brute-force fallback automatically
    if not api_results:
        logger.warning("All APIs failed or returned no results — switching to DNS brute-force fallback...")
        brute_results = dns_bruteforce(domain, logger)
        result["sources"]["dns_bruteforce"] = sorted(brute_results)
        all_subs = brute_results
    else:
        result["sources"]["dns_bruteforce"] = []
        all_subs = api_results

    result["subdomains"] = sorted(all_subs)
    logger.info(f"Total unique subdomains found: {len(all_subs)}")

    if not all_subs:
        result["error"] = "No subdomains found even after DNS brute-force. Target may have no discoverable subdomains."
        logger.warning(result["error"])

    return result
