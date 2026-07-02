"""
Reporting Module
Aggregates results from all recon modules into a structured summary
report in .txt and/or .html format, including timestamps and IP
resolution details as required by the task spec.
"""

import os
import logging
from datetime import datetime, timezone
from html import escape


def _section_title(title: str) -> str:
    bar = "=" * len(title)
    return f"\n{title}\n{bar}\n"


def _build_txt(results: dict) -> str:
    lines = []
    lines.append("RECONFORGE - RECONNAISSANCE REPORT")
    lines.append("=" * 40)
    lines.append(f"Target            : {results['target']}")
    lines.append(f"Generated (UTC)   : {results['timestamp']}")
    lines.append(f"Resolved IP       : {results.get('ip_resolution') or 'N/A'}")
    lines.append("=" * 40)

    if results.get("whois"):
        lines.append(_section_title("WHOIS LOOKUP"))
        w = results["whois"]
        if w.get("error"):
            lines.append(f"[!] {w['error']}")
        else:
            lines.append(f"Source: {w.get('source')}")
            if w.get("parsed"):
                for k, v in w["parsed"].items():
                    if v:
                        lines.append(f"  {k}: {v}")
            else:
                raw = w.get("raw", "")
                lines.append(raw[:3000] + ("...[truncated]" if len(raw) > 3000 else ""))

    if results.get("dns"):
        lines.append(_section_title("DNS ENUMERATION"))
        d = results["dns"]
        if d.get("error"):
            lines.append(f"[!] {d['error']}")
        for rtype in ["A", "MX", "TXT", "NS"]:
            vals = d.get(rtype, [])
            lines.append(f"{rtype} records ({len(vals)}):")
            for v in vals:
                lines.append(f"  - {v}")

    if results.get("subdomains"):
        lines.append(_section_title("SUBDOMAIN ENUMERATION"))
        s = results["subdomains"]
        if s.get("error"):
            lines.append(f"[!] {s['error']}")
        lines.append(f"Total unique subdomains found: {len(s.get('subdomains', []))}")
        for sub in s.get("subdomains", []):
            lines.append(f"  - {sub}")

    if results.get("ports"):
        lines.append(_section_title("PORT SCAN"))
        p = results["ports"]
        if p.get("error"):
            lines.append(f"[!] {p['error']}")
        else:
            lines.append(f"Target IP        : {p.get('ip')}")
            lines.append(f"Scanned range    : {p.get('scanned_range')}")
            lines.append(f"Scan started     : {p.get('scan_started')}")
            lines.append(f"Scan finished    : {p.get('scan_finished')}")
            lines.append(f"Open ports found : {len(p.get('open_ports', []))}")
            for op in p.get("open_ports", []):
                lines.append(f"  - {op['port']}/tcp  open  {op['service']}")

    if results.get("banners"):
        lines.append(_section_title("BANNER GRABBING"))
        for port, banner in results["banners"].items():
            lines.append(f"Port {port}:")
            lines.append(f"  {banner[:300]}")

    if results.get("techdetect"):
        lines.append(_section_title("TECHNOLOGY DETECTION"))
        t = results["techdetect"]
        if t.get("error"):
            lines.append(f"[!] {t['error']}")
        else:
            lines.append(f"Scheme used   : {t.get('scheme_used')}")
            lines.append(f"HTTP status   : {t.get('status_code')}")
            lines.append("Technologies detected:")
            for tech in t.get("technologies", []):
                lines.append(f"  - {tech}")

    lines.append("\n" + "=" * 40)
    lines.append("End of report.")
    return "\n".join(lines)


def _build_html(results: dict) -> str:
    target = escape(results["target"])

    def kv_table(d: dict) -> str:
        rows = "".join(
            f"<tr><td class='k'>{escape(str(k))}</td><td>{escape(str(v))}</td></tr>"
            for k, v in d.items() if v
        )
        return f"<table>{rows}</table>" if rows else "<p class='muted'>No data.</p>"

    sections = []

    # WHOIS
    if results.get("whois"):
        w = results["whois"]
        if w.get("error"):
            body = f"<p class='err'>{escape(w['error'])}</p>"
        elif w.get("parsed"):
            body = kv_table(w["parsed"])
        else:
            body = f"<pre>{escape(w.get('raw', '')[:3000])}</pre>"
        sections.append(("WHOIS Lookup", body))

    # DNS
    if results.get("dns"):
        d = results["dns"]
        rows = ""
        for rtype in ["A", "MX", "TXT", "NS"]:
            vals = d.get(rtype, [])
            for v in vals:
                rows += f"<tr><td class='k'>{rtype}</td><td>{escape(v)}</td></tr>"
        body = f"<table>{rows}</table>" if rows else "<p class='muted'>No DNS records found.</p>"
        if d.get("error"):
            body += f"<p class='err'>{escape(d['error'])}</p>"
        sections.append(("DNS Enumeration", body))

    # Subdomains
    if results.get("subdomains"):
        s = results["subdomains"]
        subs = s.get("subdomains", [])
        body = f"<p>Total unique subdomains found: <b>{len(subs)}</b></p>"
        if subs:
            body += "<ul class='subdomain-list'>" + "".join(f"<li>{escape(x)}</li>" for x in subs) + "</ul>"
        if s.get("error"):
            body += f"<p class='err'>{escape(s['error'])}</p>"
        sections.append(("Subdomain Enumeration", body))

    # Ports
    if results.get("ports"):
        p = results["ports"]
        if p.get("error"):
            body = f"<p class='err'>{escape(p['error'])}</p>"
        else:
            rows = "".join(
                f"<tr><td>{op['port']}/tcp</td><td class='open'>open</td><td>{escape(op['service'])}</td></tr>"
                for op in p.get("open_ports", [])
            )
            body = (
                f"<p>Target IP: <b>{escape(str(p.get('ip')))}</b> &nbsp;|&nbsp; "
                f"Range: {escape(p.get('scanned_range'))} &nbsp;|&nbsp; "
                f"Started: {escape(p.get('scan_started'))} &nbsp;|&nbsp; "
                f"Finished: {escape(p.get('scan_finished'))}</p>"
                f"<table><tr><th>Port</th><th>State</th><th>Service</th></tr>{rows}</table>"
                if rows else "<p class='muted'>No open ports found in range.</p>"
            )
        sections.append(("Port Scan", body))

    # Banners
    if results.get("banners"):
        rows = "".join(
            f"<tr><td class='k'>Port {port}</td><td><pre>{escape(banner[:300])}</pre></td></tr>"
            for port, banner in results["banners"].items()
        )
        body = f"<table>{rows}</table>" if rows else "<p class='muted'>No banners grabbed.</p>"
        sections.append(("Banner Grabbing", body))

    # Tech detect
    if results.get("techdetect"):
        t = results["techdetect"]
        if t.get("error"):
            body = f"<p class='err'>{escape(t['error'])}</p>"
        else:
            techs = t.get("technologies", [])
            body = (
                f"<p>Scheme: {escape(str(t.get('scheme_used')))} &nbsp;|&nbsp; "
                f"HTTP Status: {escape(str(t.get('status_code')))}</p>"
                + ("<ul>" + "".join(f"<li>{escape(x)}</li>" for x in techs) + "</ul>" if techs else "<p class='muted'>No signatures matched.</p>")
            )
        sections.append(("Technology Detection", body))

    sections_html = "".join(
        f"<div class='card'><h2>{escape(title)}</h2>{body}</div>" for title, body in sections
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ReconForge Report - {target}</title>
<style>
  :root {{
    --bg: #0b0f14; --card: #131a22; --accent: #4fd1c5; --text: #e6edf3;
    --muted: #8b98a5; --border: #1f2a35; --err: #ff6b6b; --open: #4fd1c5;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    background: var(--bg); color: var(--text);
    font-family: 'Segoe UI', Consolas, monospace;
    margin: 0; padding: 0 0 60px 0;
  }}
  header {{
    background: linear-gradient(135deg, #0d1b2a, #122a3a);
    padding: 32px 40px; border-bottom: 2px solid var(--accent);
  }}
  header h1 {{ margin: 0 0 6px 0; font-size: 26px; color: var(--accent); }}
  header p {{ margin: 2px 0; color: var(--muted); font-size: 14px; }}
  .container {{ max-width: 980px; margin: 30px auto; padding: 0 20px; }}
  .card {{
    background: var(--card); border: 1px solid var(--border);
    border-radius: 8px; padding: 20px 24px; margin-bottom: 20px;
  }}
  .card h2 {{
    margin-top: 0; color: var(--accent); font-size: 18px;
    border-bottom: 1px solid var(--border); padding-bottom: 8px;
  }}
  table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
  td, th {{ padding: 6px 10px; border-bottom: 1px solid var(--border); text-align: left; vertical-align: top; }}
  td.k {{ color: var(--accent); width: 220px; font-weight: 600; }}
  td.open {{ color: var(--open); font-weight: 600; }}
  .muted {{ color: var(--muted); font-style: italic; }}
  .err {{ color: var(--err); }}
  pre {{ white-space: pre-wrap; word-break: break-word; margin: 0; font-size: 12.5px; color: #c8d3dc; }}
  ul.subdomain-list {{ columns: 2; -webkit-columns: 2; font-size: 13.5px; }}
  footer {{ text-align: center; color: var(--muted); font-size: 12px; margin-top: 40px; }}
</style>
</head>
<body>
<header>
  <h1>ReconForge — Reconnaissance Report</h1>
  <p>Target: <b>{target}</b></p>
  <p>Generated (UTC): {escape(results['timestamp'])}</p>
  <p>Resolved IP: {escape(str(results.get('ip_resolution') or 'N/A'))}</p>
</header>
<div class="container">
  {sections_html}
</div>
<footer>Copyright Muhammad-Faizan 2026 — ITsolera Offensive Security Internship Task 1</footer>
</body>
</html>"""


def generate(results: dict, outdir: str, fmt: str, logger: logging.Logger) -> list:
    os.makedirs(outdir, exist_ok=True)
    safe_target = results["target"].replace(":", "_").replace("/", "_")
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    base_name = f"recon_{safe_target}_{ts}"

    paths = []

    if fmt in ("txt", "both"):
        txt_path = os.path.join(outdir, f"{base_name}.txt")
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write(_build_txt(results))
        logger.info(f"Text report written to {txt_path}")
        paths.append(txt_path)

    if fmt in ("html", "both"):
        html_path = os.path.join(outdir, f"{base_name}.html")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(_build_html(results))
        logger.info(f"HTML report written to {html_path}")
        paths.append(html_path)

    return paths
