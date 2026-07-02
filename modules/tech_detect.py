"""
Technology Detection Module
Performs a lightweight, dependency-free fingerprint of the web stack
running on the target by inspecting HTTP response headers and simple
HTML signatures (a self-contained alternative to whatweb/Wappalyzer
API calls, avoiding extra API-key requirements for the deliverable).
"""

import logging
import urllib.request
import urllib.error
import ssl
import re

SIGNATURES = {
    "Server": {
        "nginx": "Nginx",
        "apache": "Apache HTTP Server",
        "cloudflare": "Cloudflare",
        "iis": "Microsoft IIS",
        "litespeed": "LiteSpeed",
        "gws": "Google Web Server",
    },
    "X-Powered-By": {
        "php": "PHP",
        "asp.net": "ASP.NET",
        "express": "Express.js",
        "next.js": "Next.js",
    },
    "Set-Cookie": {
        "wordpress": "WordPress",
        "wp-": "WordPress",
        "laravel_session": "Laravel",
        "phpsessid": "PHP",
        "jsessionid": "Java/JSP",
    },
}

HTML_SIGNATURES = {
    "wp-content": "WordPress",
    "wp-includes": "WordPress",
    "Joomla": "Joomla",
    "Drupal.settings": "Drupal",
    "shopify": "Shopify",
    "react": "React",
    "ng-version": "Angular",
    "__NEXT_DATA__": "Next.js",
}


def _fetch(url: str, timeout: int = 10):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "ReconForge/1.0 (+security-recon)"})
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        headers = dict(resp.getheaders())
        body = resp.read(200_000).decode(errors="ignore")
        status = resp.status
    return status, headers, body


def run(domain: str, logger: logging.Logger) -> dict:
    result = {"domain": domain, "technologies": [], "headers": {}, "status_code": None, "error": None}

    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            status, headers, body = _fetch(url)
            result["status_code"] = status
            result["headers"] = headers
            result["scheme_used"] = scheme

            detected = set()

            for header_name, sig_map in SIGNATURES.items():
                header_val = headers.get(header_name, "")
                if header_val:
                    for keyword, tech in sig_map.items():
                        if keyword.lower() in header_val.lower():
                            detected.add(tech)

            for keyword, tech in HTML_SIGNATURES.items():
                if keyword.lower() in body.lower():
                    detected.add(tech)

            # Generic header presence
            if "Server" in headers:
                detected.add(f"Server header: {headers['Server']}")

            result["technologies"] = sorted(detected)
            logger.info(f"Detected {len(detected)} technology signature(s) on {url}")
            return result

        except urllib.error.URLError as e:
            logger.debug(f"{scheme}:// fetch failed for {domain}: {e}")
            continue
        except Exception as e:
            logger.debug(f"{scheme}:// fetch error for {domain}: {e}")
            continue

    result["error"] = "Could not reach target over HTTPS or HTTP for technology detection."
    logger.warning(result["error"])
    return result
