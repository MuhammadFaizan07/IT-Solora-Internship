"""
DNS Enumeration Module
Enumerates A, MX, TXT, and NS records for the target domain.
Uses dnspython when available; falls back to socket-based A record
resolution only if dnspython is missing.
"""

import socket
import logging


def run(domain: str, logger: logging.Logger) -> dict:
    records = {"A": [], "MX": [], "TXT": [], "NS": [], "error": None}

    try:
        import dns.resolver

        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5

        record_types = ["A", "MX", "TXT", "NS"]
        for rtype in record_types:
            try:
                answers = resolver.resolve(domain, rtype)
                for rdata in answers:
                    records[rtype].append(str(rdata).strip())
                logger.info(f"{rtype} records found: {len(records[rtype])}")
            except dns.resolver.NoAnswer:
                logger.debug(f"No {rtype} records for {domain}")
            except dns.resolver.NXDOMAIN:
                records["error"] = f"Domain {domain} does not exist (NXDOMAIN)"
                logger.error(records["error"])
                return records
            except Exception as e:
                logger.warning(f"Error resolving {rtype} for {domain}: {e}")

    except ImportError:
        logger.debug("dnspython not installed, falling back to basic socket A-record lookup")
        try:
            ip = socket.gethostbyname(domain)
            records["A"].append(ip)
        except socket.gaierror as e:
            records["error"] = f"Could not resolve {domain}: {e}"
            logger.error(records["error"])

    return records
