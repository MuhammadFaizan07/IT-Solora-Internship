#!/usr/bin/env python3
"""
ReconForge - Modular Reconnaissance Tool
ITsolera SOC/Offensive Security Internship - Task 1

Author: Muhammad Faizan
Description:
    A lightweight, modular CLI reconnaissance tool for the passive and
    active information-gathering phase of a penetration test.

    Each capability (whois, dns, subdomains, ports, banners, techdetect)
    is implemented as an independent module under modules/ and is wired
    into this CLI via argparse flags, exactly as required by the task:
        --whois, --dns, --subdomains, --ports, --banner, --techdetect, --all

Usage:
    python recontool.py example.com --all
    python recontool.py example.com --whois --dns -v
    python recontool.py example.com --ports --ports-range 1-1024 --format html
"""

import argparse
import logging
import sys
import socket
from datetime import datetime, timezone

from modules import whois_lookup, dns_enum, subdomain_enum, port_scan, tech_detect, report

VERSION = "1.0.0"


def build_parser():
    parser = argparse.ArgumentParser(
        prog="recontool",
        description="ReconForge - Modular Reconnaissance Tool for Penetration Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python recontool.py example.com --all
  python recontool.py example.com --whois --dns
  python recontool.py example.com --subdomains -v
  python recontool.py example.com --ports --ports-range 1-1000 --format html
  python recontool.py example.com --ports --banner --techdetect -vv
""",
    )
    parser.add_argument("target", help="Target domain (e.g., example.com)")

    passive = parser.add_argument_group("Passive Recon")
    passive.add_argument("--whois", action="store_true", help="Perform WHOIS lookup")
    passive.add_argument("--dns", action="store_true", help="Enumerate DNS records (A, MX, TXT, NS)")
    passive.add_argument("--subdomains", action="store_true", help="Enumerate subdomains via crt.sh / OTX")

    active = parser.add_argument_group("Active Recon")
    active.add_argument("--ports", action="store_true", help="Perform TCP port scan")
    active.add_argument("--ports-range", default="1-1024", help="Port range to scan, e.g. 1-1024 (default: 1-1024)")
    active.add_argument("--banner", action="store_true", help="Grab service banners on open ports")
    active.add_argument("--techdetect", action="store_true", help="Detect web technologies (HTTP headers based)")

    misc = parser.add_argument_group("General")
    misc.add_argument("--all", action="store_true", help="Run all recon modules")
    misc.add_argument("--format", choices=["txt", "html", "both"], default="both",
                       help="Report output format (default: both)")
    misc.add_argument("--outdir", default="reports", help="Directory to write the report into (default: reports/)")
    misc.add_argument("-v", "--verbose", action="count", default=0,
                       help="Increase verbosity (-v info, -vv debug)")
    misc.add_argument("--version", action="version", version=f"ReconForge {VERSION}")

    return parser


def configure_logging(verbosity: int):
    if verbosity >= 2:
        level = logging.DEBUG
    elif verbosity == 1:
        level = logging.INFO
    else:
        level = logging.WARNING

    # logging.basicConfig() is IGNORED if any handler already exists (e.g. PyCharm).
    # Instead, force-set the level on the root logger and all existing handlers,
    # then add a StreamHandler if none exist yet.
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    formatter = logging.Formatter(
        fmt="[%(asctime)s] [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    if root_logger.handlers:
        # Update every existing handler's level and formatter
        for handler in root_logger.handlers:
            handler.setLevel(level)
            handler.setFormatter(formatter)
    else:
        # No handlers at all — create one
        handler = logging.StreamHandler()
        handler.setLevel(level)
        handler.setFormatter(formatter)
        root_logger.addHandler(handler)


def resolve_target_ip(target: str, logger: logging.Logger):
    try:
        ip = socket.gethostbyname(target)
        logger.info(f"Resolved {target} -> {ip}")
        return ip
    except socket.gaierror as e:
        logger.error(f"Could not resolve target {target}: {e}")
        return None


def main():
    parser = build_parser()
    args = parser.parse_args()
    configure_logging(args.verbose)
    logger = logging.getLogger("recontool")

    # If no specific module flag given and --all not set, default to --all
    any_module = any([args.whois, args.dns, args.subdomains, args.ports, args.banner, args.techdetect])
    if not any_module:
        args.all = True

    target = args.target.strip().lower().replace("http://", "").replace("https://", "").rstrip("/")

    print(f"\n{'='*60}")
    print(f"  ReconForge v{VERSION} — Reconnaissance Report")
    print(f"  Target: {target}")
    print(f"  Started: {datetime.now(timezone.utc).isoformat()} UTC")
    print(f"{'='*60}\n")

    results = {
        "target": target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ip_resolution": None,
        "whois": None,
        "dns": None,
        "subdomains": None,
        "ports": None,
        "banners": None,
        "techdetect": None,
    }

    ip = resolve_target_ip(target, logger)
    results["ip_resolution"] = ip

    if args.whois or args.all:
        logger.info("Running WHOIS module...")
        results["whois"] = whois_lookup.run(target, logger)

    if args.dns or args.all:
        logger.info("Running DNS enumeration module...")
        results["dns"] = dns_enum.run(target, logger)

    if args.subdomains or args.all:
        logger.info("Running subdomain enumeration module...")
        results["subdomains"] = subdomain_enum.run(target, logger)

    open_ports = []
    if args.ports or args.all or args.banner:
        logger.info("Running port scan module...")
        port_results = port_scan.run(target, args.ports_range, logger)
        results["ports"] = port_results
        open_ports = [p["port"] for p in port_results.get("open_ports", [])]

    if args.banner or args.all:
        logger.info("Running banner grabbing module...")
        if not open_ports and results["ports"] is None:
            # banner requested without ports scan explicitly - do a quick common-port scan
            port_results = port_scan.run(target, "1-1024", logger)
            results["ports"] = port_results
            open_ports = [p["port"] for p in port_results.get("open_ports", [])]
        results["banners"] = port_scan.grab_banners(target, open_ports, logger)

    if args.techdetect or args.all:
        logger.info("Running technology detection module...")
        results["techdetect"] = tech_detect.run(target, logger)

    # Generate report
    outpaths = report.generate(results, args.outdir, args.format, logger)

    print(f"\n{'='*60}")
    print("  Recon complete.")
    for p in outpaths:
        print(f"  Report saved: {p}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    try:
        # ↓ PyCharm fix — remove this line when running from CMD
        sys.argv = ["recontool.py", "eccouncil.org", "--all", "-v"]
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        sys.exit(1)
