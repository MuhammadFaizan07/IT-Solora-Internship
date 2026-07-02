"""
WHOIS Lookup Module
Performs a WHOIS lookup for the target domain using the python-whois
library when available, falling back to a raw socket query against
the registrar's WHOIS server (port 43) if the library is missing.
"""

import socket
import logging


def _raw_whois(domain: str, server: str = "whois.iana.org", logger: logging.Logger = None) -> str:
    """Fallback raw WHOIS query via TCP socket on port 43."""
    try:
        with socket.create_connection((server, 43), timeout=10) as s:
            s.sendall((domain + "\r\n").encode())
            response = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
        text = response.decode(errors="ignore")

        # IANA referral pattern: find "refer:" to the actual registry WHOIS server
        for line in text.splitlines():
            if line.lower().startswith("refer:"):
                refer_server = line.split(":", 1)[1].strip()
                if refer_server and refer_server != server:
                    return _raw_whois(domain, refer_server, logger)
        return text
    except Exception as e:
        if logger:
            logger.warning(f"Raw WHOIS query against {server} failed: {e}")
        return ""


def run(domain: str, logger: logging.Logger) -> dict:
    result = {"domain": domain, "raw": "", "parsed": {}, "source": None, "error": None}

    # Try python-whois library first (richer parsed output)
    try:
        import whois as whois_lib
        w = whois_lib.whois(domain)
        if w and (w.get("domain_name") or w.text):
            result["source"] = "python-whois"
            result["raw"] = getattr(w, "text", "") or str(w)
            result["parsed"] = {
                "registrar": w.get("registrar"),
                "creation_date": str(w.get("creation_date")),
                "expiration_date": str(w.get("expiration_date")),
                "updated_date": str(w.get("updated_date")),
                "name_servers": w.get("name_servers"),
                "status": w.get("status"),
                "emails": w.get("emails"),
                "org": w.get("org"),
                "country": w.get("country"),
            }
            logger.info("WHOIS data retrieved via python-whois")
            return result
    except ImportError:
        logger.debug("python-whois not installed, falling back to raw socket WHOIS")
    except Exception as e:
        logger.warning(f"python-whois lookup failed ({e}), falling back to raw socket WHOIS")

    # Fallback: raw socket WHOIS query
    raw = _raw_whois(domain, logger=logger)
    if raw:
        result["source"] = "raw-socket"
        result["raw"] = raw
    else:
        result["error"] = "WHOIS lookup failed via both python-whois and raw socket methods."
        logger.error(result["error"])

    return result
