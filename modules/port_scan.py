"""
Active Recon Module: Port Scanning + Banner Grabbing
Implements a lightweight multi-threaded TCP connect() scan using raw
sockets (no external nmap dependency required), plus a banner-grabbing
routine that opens a TCP connection to each open port and reads the
service's initial response banner.

NOTE: Only scan hosts/domains you are authorized to test.
"""

import socket
import logging
import concurrent.futures
from datetime import datetime, timezone

COMMON_SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 21: "FTP",
}


def _parse_port_range(port_range: str):
    try:
        if "-" in port_range:
            start, end = port_range.split("-")
            return list(range(int(start), int(end) + 1))
        elif "," in port_range:
            return [int(p.strip()) for p in port_range.split(",")]
        else:
            return [int(port_range)]
    except ValueError:
        return list(range(1, 1025))


def _scan_port(ip: str, port: int, timeout: float = 1.0):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                service = COMMON_SERVICE_NAMES.get(port, "unknown")
                return {"port": port, "state": "open", "service": service}
    except Exception:
        pass
    return None


def run(domain: str, port_range: str, logger: logging.Logger, max_workers: int = 100) -> dict:
    result = {
        "target": domain,
        "ip": None,
        "scanned_range": port_range,
        "open_ports": [],
        "scan_started": datetime.now(timezone.utc).isoformat(),
        "scan_finished": None,
        "error": None,
    }

    try:
        ip = socket.gethostbyname(domain)
        result["ip"] = ip
    except socket.gaierror as e:
        result["error"] = f"Could not resolve {domain}: {e}"
        logger.error(result["error"])
        return result

    ports = _parse_port_range(port_range)
    logger.info(f"Scanning {len(ports)} ports on {ip} ({domain})...")

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_scan_port, ip, p): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                open_ports.append(res)
                logger.info(f"Open port found: {res['port']}/tcp ({res['service']})")

    open_ports.sort(key=lambda x: x["port"])
    result["open_ports"] = open_ports
    result["scan_finished"] = datetime.now(timezone.utc).isoformat()
    logger.info(f"Port scan complete: {len(open_ports)} open port(s) found")

    return result


def grab_banners(domain: str, ports: list, logger: logging.Logger, timeout: float = 2.0) -> dict:
    """Attempt to grab a service banner from each given open port."""
    banners = {}
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror as e:
        logger.error(f"Could not resolve {domain} for banner grabbing: {e}")
        return banners

    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))

                # HTTP(S)-like ports need a request to trigger a response
                if port in (80, 8080, 8000, 8888):
                    s.sendall(f"HEAD / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n".encode())

                try:
                    banner = s.recv(1024).decode(errors="ignore").strip()
                except socket.timeout:
                    banner = ""

                banners[port] = banner if banner else "(no banner / connection closed silently)"
                logger.info(f"Banner on port {port}: {banners[port][:60]}")
        except Exception as e:
            banners[port] = f"(banner grab failed: {e})"
            logger.debug(f"Banner grab failed on port {port}: {e}")

    return banners
