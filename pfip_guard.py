#!/usr/bin/env python3
# PFIP Guard — Unified Detection & Enforcement Tool
# MFID: TUX-133.144~ | ENS: freq-sovereign.eth
#
# Features:
# - Scan workspace files for PFIP markers (MFID/ENS)
# - Inspect a page/response for PFIP signals (header/meta/.well-known)
# - Enforce policy: skip/denylist, create evidence package (ZIP), optional autoblock (iptables)
#
# Usage:
#   python pfip_guard.py scan --root .
#   python pfip_guard.py enforce --file ./public/index.html --ip 1.2.3.4
#   python pfip_guard.py enforce --url https://example.com --headers resp_headers.json --wellknown pfip.json
#
# Note:
# - Standard library only. No external deps.
# - Autoblocking via iptables is optional and disabled by default.

import os
import sys
import re
import json
import time
import hashlib
import zipfile
import argparse
import subprocess
from pathlib import Path
from urllib.parse import urlparse

# ---------------- CONFIG ----------------
CONFIG = {
    # Canonical identifiers
    "mfid": "TUX-133.144~",
    "ens": "freq-sovereign.eth",

    # Policy flags (for reference)
    "flags": ["no_training", "no_copy", "no_style_imitation", "no_redistribution"],

    # License/Protocol linkage (display only)
    "license_version": "1.0",       # PFIP-SL License v1.0 (first legal release)
    "protocol_version": "1.2.2",    # PFIP Protocol v1.2.2

    # Contacts & storage
    "contact_email": "tutu.oxygen.tank@gmail.com",
    "evidence_storage_dir": "./pfip_evidence",
    "denylist_file": "./pfip_denylist.txt",

    # Optional automated blocking (requires root; use carefully)
    "automatic_blocking": {
        "enabled": False,
        "method": "none"            # "none" or "iptables"
    },
}

# Quick string keys used for simple substring detection in files
FILE_SCAN_KEYS = [
    "MFID=TUX-133.144~", "mfid=TUX-133.144~",
    "ENS=freq-sovereign.eth", "ens=freq-sovereign.eth",
    '"mfid":"TUX-133.144~"', "'mfid':'TUX-133.144~'",
    '"ens":"freq-sovereign.eth"', "'ens':'freq-sovereign.eth'"
]

# ---------------- UTILS ----------------
def utc_ts() -> str:
    """UTC ISO-like timestamp."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def sha256_bytes(b: bytes) -> str:
    """SHA256 hex of bytes."""
    return hashlib.sha256(b).hexdigest()

def safe_name(s: str) -> str:
    """Filesystem-safe short name."""
    return "".join(c if c.isalnum() else "_" for c in s)[:200]

def find_meta_pfip(html: str) -> str | None:
    """Extract <meta name="pfip" content="..."> content string from HTML."""
    if not html:
        return None
    m = re.search(r'<meta[^>]*name=["\']pfip["\'][^>]*>', html, flags=re.I | re.S)
    if not m:
        return None
    c = re.search(r'content=["\']([^"\']+)["\']', m.group(0), flags=re.I)
    return c.group(1) if c else None

# ---------------- FILE SCAN ----------------
def scan_text_for_pfip_markers(text: str) -> bool:
    """Simple substring check for PFIP markers."""
    if not text:
        return False
    return any(k in text for k in FILE_SCAN_KEYS)

def scan_file_for_pfip_markers(path: Path) -> bool:
    """Read a file and check for PFIP markers."""
    try:
        data = path.read_text("utf-8", errors="ignore")
    except Exception:
        return False
    return scan_text_for_pfip_markers(data)

def scan_workspace(root: Path) -> list[str]:
    """
    Recursively scan files under `root` for PFIP markers.
    Returns a list of matched file paths.
    """
    matched: list[str] = []
    for p in root.rglob("*"):
        if p.is_file() and scan_file_for_pfip_markers(p):
            matched.append(str(p))
    return matched

# ---------------- RESPONSE INSPECTION ----------------
def parse_pfip_header(headers: dict | None) -> dict:
    """Parse PFIP or X-PFIP header into a dict of key/value pairs."""
    if not headers:
        return {}
    target_val = None
    for k, v in headers.items():
        if k.lower() in ("pfip", "x-pfip"):
            target_val = v
            break
    if not target_val:
        return {}
    out = {}
    for chunk in re.split(r'[;,]\s*', str(target_val)):
        if "=" in chunk:
            a, b = chunk.split("=", 1)
            out[a.strip().lower()] = b.strip()
    return out

def inspect_response(url: str,
                     headers: dict | None,
                     html: str | None,
                     well_known_json: dict | None) -> dict:
    """
    Inspect signals from headers, HTML meta, and .well-known JSON.
    Returns:
      {
        "pfip_match": bool,
        "matched_by": ["header","meta",".well-known"],
        "evidence": {...}
      }
    """
    matched_by: list[str] = []
    ev: dict = {"url": url, "time_utc": utc_ts()}

    # Header check
    ph = parse_pfip_header(headers)
    if ph.get("mfid") == CONFIG["mfid"] and ph.get("ens") == CONFIG["ens"]:
        matched_by.append("header")
        ev["header"] = ph

    # Meta check
    if html:
        c = find_meta_pfip(html)
        if c and (CONFIG["mfid"] in c and CONFIG["ens"] in c):
            matched_by.append("meta")
            ev["meta"] = c

    # .well-known check
    if well_known_json and isinstance(well_known_json, dict):
        if well_known_json.get("mfid") == CONFIG["mfid"] and well_known_json.get("ens") == CONFIG["ens"]:
            matched_by.append(".well-known")
            ev["well_known"] = well_known_json

    return {"pfip_match": bool(matched_by), "matched_by": matched_by, "evidence": ev}

# ---------------- EVIDENCE PACKAGING ----------------
def make_evidence_zip(url: str,
                      evidence: dict,
                      html_text: str | None = None,
                      headers: dict | None = None) -> str:
    """
    Create a ZIP evidence package with manifest + (optional) headers/page snapshot.
    Returns the ZIP file path.
    """
    base_dir = CONFIG["evidence_storage_dir"]
    os.makedirs(base_dir, exist_ok=True)

    name = f"pfip_evidence_{safe_name(url)}_{utc_ts().replace(':', '').replace('-', '')}.zip"
    path = os.path.join(base_dir, name)

    manifest = {
        "url": url,
        "timestamp_utc": utc_ts(),
        "detector_evidence": evidence,
        "files": []
    }

    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        # headers.json
        if headers:
            htxt = json.dumps(headers, ensure_ascii=False, indent=2)
            z.writestr("headers.json", htxt)
            manifest["files"].append({"name": "headers.json", "sha256": sha256_bytes(htxt.encode("utf-8"))})

        # page.html
        if html_text:
            z.writestr("page.html", html_text)
            manifest["files"].append({"name": "page.html", "sha256": sha256_bytes(html_text.encode("utf-8"))})

        # manifest.json (final)
        z.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))

    return path

# ---------------- ENFORCEMENT ----------------
def append_denylist(url: str, ip: str | None) -> None:
    """Append an entry to the local denylist file."""
    entry = {"ts": int(time.time()), "url": url, "ip": ip}
    with open(CONFIG["denylist_file"], "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

def autoblock(ip: str | None) -> dict | None:
    """
    Optional: block an IP using iptables.
    Returns a summary dict or None if disabled/no IP.
    """
    if not ip:
        return None
    ab = CONFIG["automatic_blocking"]
    if not ab.get("enabled"):
        return None
    if ab.get("method") == "iptables":
        try:
            subprocess.run(["/sbin/iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            return {"method": "iptables", "blocked": True}
        except Exception as e:
            return {"method": "iptables", "blocked": False, "error": str(e)}
    return None

def enforce(url: str,
            det_result: dict,
            html_text: str | None,
            headers: dict | None,
            offender_ip: str | None) -> dict:
    """
    Enforce PFIP upon detection:
    - Add to denylist
    - Create evidence package (ZIP)
    - Optional autoblock (iptables)
    - Return summary with takedown notice template
    """
    if not det_result.get("pfip_match"):
        return {"action": "none", "reason": "no_pfip_match"}

    append_denylist(url, offender_ip)
    ev_zip = make_evidence_zip(url, det_result["evidence"], html_text, headers)
    blk = autoblock(offender_ip)

    return {
        "action": "enforced",
        "evidence_zip": ev_zip,
        "block": blk,
        "takedown_notice": (
            f"PFIP violation at {url}. Evidence: {ev_zip}. "
            f"Contact: {CONFIG['contact_email']}."
        )
    }

# ---------------- CLI ----------------
def cmd_scan(args) -> None:
    """CLI: scan workspace for PFIP markers."""
    root = Path(args.root).resolve()
    hits = scan_workspace(root)
    if hits:
        print(f"[PFIP] Detected {len(hits)} file(s) with PFIP markers:")
        for h in hits:
            print(" -", h)
        sys.exit(1 if not args.soft else 0)
    else:
        print("[PFIP] No PFIP markers found.")
        sys.exit(0)

def cmd_enforce(args) -> None:
    """CLI: enforce PFIP on given input (file/url with optional headers/.well-known)."""
    html_text = Path(args.file).read_text("utf-8", errors="ignore") if args.file else None
    headers = json.load(open(args.headers, "r", encoding="utf-8")) if args.headers else None
    wellk = json.load(open(args.wellknown, "r", encoding="utf-8")) if args.wellknown else None
    url = args.url or (Path(args.file).as_uri() if args.file else "file://local")

    det = inspect_response(url, headers, html_text, wellk)
    if not det["pfip_match"]:
        print("[PFIP] No PFIP match. Nothing to enforce.")
        sys.exit(0)

    result = enforce(url, det, html_text, headers, args.ip)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    # exit 1 to signal a blocking condition if integrated in CI
    sys.exit(1)

def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="PFIP Guard (MFID=TUX-133.144~ | ENS=freq-sovereign.eth)"
    )
    sub = p.add_subparsers(dest="cmd")

    # scan
    sc = sub.add_parser("scan", help="Scan repo/workspace for PFIP markers")
    sc.add_argument("--root", default=".", help="Root directory to scan")
    sc.add_argument("--soft", action="store_true", help="Soft mode (exit 0 even if markers found)")
    sc.set_defaults(func=cmd_scan)

    # enforce
    en = sub.add_parser("enforce", help="Enforce PFIP policy on a given input")
    en.add_argument("--url", help="Label URL (optional)")
    en.add_argument("--file", help="Path to HTML/JSON to inspect")
    en.add_argument("--headers", help="Path to JSON file of response headers")
    en.add_argument("--wellknown", help="Path to JSON file of /.well-known/pfip.json")
    en.add_argument("--ip", help="Offender IP for optional autoblocking")
    en.set_defaults(func=cmd_enforce)

    return p

def main() -> None:
    parser = build_argparser()
    args = parser.parse_args()
    if not args.cmd:
        parser.print_help()
        return
    args.func(args)

if __name__ == "__main__":
    main()
