#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_amides_events_from_report.py

Convert Sysmon-for-Linux XML logs referenced by Report_*.csv into AMIDES-compatible
MATCH / EVASION event JSON files.

Key points:
- Extract <Event ...>...</Event> blocks from log text
- Parse Sysmon XML with namespace-agnostic tags ({*}System, {* }EventData)
- Select best EventID=1 based on token overlap with the original command
- Normalize output JSON: Sysmon flat fields + ECS-ish process.*
- Output filenames (AMIDES style):
    <queried_event_type>_Match_0001.json
    <queried_event_type>_Evasion_0001.json
- Output folder (AMIDES style):
    sigma/events/<platform>/process_creation/<rule_dir_name>/
- properties.yml (AMIDES style YAML mapping, NOT a list)
"""

from __future__ import annotations

import argparse
import csv
import html
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Tuple


EVENT_RE = re.compile(r"(<Event\b.*?</Event>)", flags=re.DOTALL)

SAFE = re.compile(r"[^a-zA-Z0-9._-]+")
B64_RE = re.compile(r"[A-Za-z0-9+/=]{20,}")


def safe_name(s: str) -> str:
    s = (s or "").strip()
    s = SAFE.sub("_", s)
    return s[:120] if len(s) > 120 else s


def write_properties_yml_amides(
    rule_dir: Path,
    queried_event_type: str,
    evasion_possible: str,
    edited_fields: List[str],
):
    """
    AMIDES properties.yml format (mapping), like:
      queried_event_types:
        - Microsoft-Windows-Sysmon_1
      evasion_possible: yes
      broken_rule: no
      edited_fields:
        - CommandLine
        - Image
        - ParentImage
    """
    # Deduplicate while preserving order
    seen = set()
    ef = []
    for x in edited_fields:
        x = (x or "").strip()
        if x and x not in seen:
            ef.append(x)
            seen.add(x)

    lines = []
    lines.append("queried_event_types:")
    lines.append(f"  - {queried_event_type}")
    lines.append(f"evasion_possible: {evasion_possible}")
    lines.append("broken_rule: no")
    lines.append("edited_fields:")
    for f in ef:
        lines.append(f"  - {f}")

    (rule_dir / "properties.yml").write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_sysmon_event_xml(xml_str: str) -> Optional[Tuple[str, Optional[str], Optional[str], Dict[str, str]]]:
    """Return (event_id, system_time, computer, eventdata_dict) or None. Namespace-agnostic."""
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return None

    system = root.find("{*}System")
    if system is None:
        return None

    event_id = system.findtext("{*}EventID") or ""
    time_created = system.find("{*}TimeCreated")
    ts = time_created.attrib.get("SystemTime") if time_created is not None else None
    computer = system.findtext("{*}Computer")

    ed = root.find("{*}EventData")
    data: Dict[str, str] = {}
    if ed is not None:
        for d in ed.findall("{*}Data"):
            k = d.attrib.get("Name")
            if not k:
                continue
            v = d.text or ""
            data[k] = html.unescape(v)

    return event_id, ts, computer, data


def extract_process_create_events(log_path: Path) -> List[Dict[str, str]]:
    """Extract EventID=1 events from a Sysmon-for-Linux log file."""
    text = log_path.read_text(encoding="utf-8", errors="ignore")
    blocks = EVENT_RE.findall(text)

    out: List[Dict[str, str]] = []
    for b in blocks:
        parsed = parse_sysmon_event_xml(b)
        if not parsed:
            continue
        event_id, ts, computer, d = parsed
        if str(event_id) != "1":
            continue
        ev = {"SystemTime": ts, "Computer": computer}
        ev.update(d)
        out.append(ev)
    return out


def parse_sha256(m: Dict[str, str]) -> Optional[str]:
    sha = m.get("SHA256")
    if isinstance(sha, str) and sha.strip():
        return sha.strip().lower()

    hashes = m.get("Hashes")
    if isinstance(hashes, str):
        for part in hashes.split(","):
            part = part.strip()
            if part.upper().startswith("SHA256="):
                return part.split("=", 1)[1].strip().lower()
    return None


def basename(p: Optional[str]) -> Optional[str]:
    if not p:
        return None
    p = p.replace("\\", "/")
    return p.split("/")[-1]


def _to_int_if_digits(x):
    if isinstance(x, str) and x.isdigit():
        try:
            return int(x)
        except ValueError:
            return x
    return x


def normalize_event_for_amides(
    m: Dict[str, str],
    rule_title: str,
    rule_id: Optional[str],
    attack_id: str,
    original_cmd: str,
    log_file: str,
    queried_event_type: str,
) -> Dict:
    """Normalize to AMIDES-friendly JSON (flat Sysmon + ECS-ish process.*)."""
    sha256 = parse_sha256(m)

    proc_exe = m.get("Image")
    cmd = m.get("CommandLine")
    cwd = m.get("CurrentDirectory")
    parent_exe = m.get("ParentImage")

    out = {
        "@timestamp": m.get("SystemTime") or m.get("UtcTime"),
        "message": "Process Create (Sysmon for Linux)",

        # Sysmon-like flat fields
        "CommandLine": cmd,
        "Image": proc_exe,
        "ParentImage": parent_exe,
        "CurrentDirectory": cwd,

        # ECS-ish
        "event": {"code": 1, "provider": "Linux-Sysmon", "category": ["process"], "type": ["start"], "action": "Process Create"},
        "host": {"hostname": m.get("Computer")} if m.get("Computer") else {},
        "user": {"name": m.get("User")} if m.get("User") else {},
        "process": {
            "pid": _to_int_if_digits(m.get("ProcessId")),
            "entity_id": m.get("ProcessGuid"),
            "executable": proc_exe,
            "name": basename(proc_exe),
            "command_line": cmd,
            "working_directory": cwd,
            "hash": {"sha256": sha256} if sha256 else {},
            "parent": {
                "pid": _to_int_if_digits(m.get("ParentProcessId")),
                "entity_id": m.get("ParentProcessGuid"),
                "executable": parent_exe,
                "name": basename(parent_exe),
                "command_line": m.get("ParentCommandLine"),
            },
        },

        "labels": {
            "sigma_rule_title": rule_title,
            "sigma_rule_id": rule_id,
            "attack_id": attack_id,
            "original_command": original_cmd,
            "log_file": log_file,
            "queried_event_type": queried_event_type,
        },

        "sysmon": {"linux_event_data": m},
    }

    if out.get("host") == {}:
        out.pop("host", None)
    if out.get("user") == {}:
        out.pop("user", None)
    if isinstance(out.get("process"), dict) and out["process"].get("hash") == {}:
        out["process"].pop("hash", None)

    return out


def _tokenize(s: str) -> List[str]:
    s = s or ""
    toks = []
    for t in s.lower().split():
        t = t.strip().strip("'\"")
        if t:
            toks.append(t)
    return toks


def best_event_for_command(events: List[Dict[str, str]], command: str):
    """Pick EventID=1 event whose CommandLine best matches the command."""
    cmd = command or ""
    cmd_l = cmd.lower()

    anchors = sorted(set(B64_RE.findall(cmd)), key=len, reverse=True)[:3]

    cmd_tokens = set(_tokenize(cmd))
    generic = {"sudo", "env", "sh", "bash", "dash", "zsh", "-c", "--", "|", "&&", ";"}
    cmd_tokens = {t for t in cmd_tokens if t not in generic}

    best = None
    best_score = -10_000

    for ev in events:
        cl = (ev.get("CommandLine") or "")
        cl_l = cl.lower()
        ev_tokens = set(_tokenize(cl))
        ev_tokens = {t for t in ev_tokens if t not in generic}

        overlap = len(cmd_tokens & ev_tokens)
        score = overlap * 3

        for a in anchors:
            if a and a in cl:
                score += 10 if len(a) > 40 else 6

        if "bash" in cmd_l and ("bash" in cl_l or "/bin/bash" in cl_l):
            score += 2
        if "sh" in cmd_l and ("/bin/sh" in cl_l or " sh " in f" {cl_l} "):
            score += 1
        if "base64" in cmd_l and "base64" in cl_l:
            score += 2

        score -= abs(len(cl) - len(cmd)) * 0.002

        if score > best_score:
            best_score = score
            best = ev

    return best, best_score, anchors


def is_summary_or_invalid_row(row: dict) -> bool:
    """Skip SUMMARY REPORT / invalid rows in Report_*.csv."""
    rid = (row.get("ID") or "").strip()
    log_file = (row.get("Log File") or "").strip()
    result = (row.get("Result") or "").strip()

    if "SUMMARY REPORT" in result.upper():
        return True
    if not rid.isdigit():
        return True
    if not log_file or log_file.lower() in ("nan", "none"):
        return True
    return False


def classify_result(result: str) -> Tuple[bool, bool]:
    """Returns (is_trigger, is_bypass) using robust contains-match."""
    r = (result or "").strip().lower()
    return ("trigger" in r), ("bypass" in r)


def parse_edited_fields_arg(s: str) -> List[str]:
    # allow: "CommandLine,Image,ParentImage"
    return [x.strip() for x in (s or "").split(",") if x.strip()]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", required=True, help="Report_*.csv path")
    ap.add_argument("--logs-dir", required=True, help="logs_output/<RuleFolder> directory")

    # If you want folder = rule-id (UUID), pass that as --rule-dir-name
    ap.add_argument("--rule-dir-name", required=True, help="Folder name under sigma/events/<platform>/process_creation/")
    ap.add_argument("--rule-title", required=True, help="Sigma rule title (for labels)")
    ap.add_argument("--rule-id", default=None, help="Sigma rule id (optional, for labels)")

    ap.add_argument("--out-root", default=".", help="Project root containing sigma/ (default: .)")
    ap.add_argument("--platform", choices=["linux", "windows"], default="linux", help="sigma/events/<platform>/... (default: linux)")

    ap.add_argument("--max-match", type=int, default=999999)
    ap.add_argument("--max-evasion", type=int, default=999999)

    ap.add_argument("--queried-event-type", default="Microsoft-Windows-Sysmon_1",
                    help="Value written into properties.yml -> queried_event_types[0]")

    ap.add_argument("--evasion-possible", default="yes", choices=["yes", "no", "unknown"],
                    help="Value written into properties.yml (default: yes)")

    ap.add_argument("--index-width", type=int, default=4,
                    help="Zero-padding width for Match/Evasion index (default: 4 -> 0001).")

    # IMPORTANT: make properties.yml match AMIDES: CommandLine, Image, ParentImage
    ap.add_argument("--edited-fields", default="CommandLine,Image,ParentImage",
                    help="Comma-separated edited_fields written to properties.yml (default: CommandLine,Image,ParentImage)")

    ap.add_argument("--force-properties", action="store_true",
                    help="Overwrite properties.yml even if it already exists")

    args = ap.parse_args()

    report = Path(args.report)
    logs_dir = Path(args.logs_dir)
    out_root = Path(args.out_root)

    rule_dir_name = args.rule_dir_name
    rule_title = args.rule_title
    rule_id = args.rule_id

    out_rule_dir = out_root / "sigma" / "events" / args.platform / "process_creation" / rule_dir_name
    out_rule_dir.mkdir(parents=True, exist_ok=True)

    prop = out_rule_dir / "properties.yml"
    if args.force_properties or (not prop.exists()):
        write_properties_yml_amides(
            out_rule_dir,
            queried_event_type=args.queried_event_type,
            evasion_possible=args.evasion_possible,
            edited_fields=parse_edited_fields_arg(args.edited_fields),
        )

    file_prefix = safe_name(args.queried_event_type)
    w = max(1, int(args.index_width))

    def fmt_idx(i: int) -> str:
        return f"{i:0{w}d}"

    match_i = 0
    evas_i = 0
    skipped_summary = 0
    skipped_missing_logs = 0
    skipped_no_events = 0
    skipped_no_best = 0

    with report.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if is_summary_or_invalid_row(row):
                skipped_summary += 1
                continue

            rid = (row.get("ID") or "").strip()
            cmd = (row.get("Command") or "").strip()
            log_file = (row.get("Log File") or "").strip()
            result = (row.get("Result") or "").strip()

            log_path = logs_dir / log_file
            if not log_path.exists() or not log_path.is_file():
                skipped_missing_logs += 1
                continue

            events = extract_process_create_events(log_path)
            if not events:
                skipped_no_events += 1
                continue

            ev_raw, score, anchors = best_event_for_command(events, cmd)
            if not ev_raw:
                skipped_no_best += 1
                continue

            ev_norm = normalize_event_for_amides(
                ev_raw,
                rule_title=rule_title,
                rule_id=rule_id,
                attack_id=rid,
                original_cmd=cmd,
                log_file=log_file,
                queried_event_type=args.queried_event_type,
            )

            is_trigger, is_bypass = classify_result(result)

            if is_trigger and match_i < args.max_match:
                match_i += 1
                out_file = out_rule_dir / f"{file_prefix}_Match_{fmt_idx(match_i)}.json"
                out_file.write_text(json.dumps(ev_norm, ensure_ascii=False, indent=2), encoding="utf-8")

            elif is_bypass and evas_i < args.max_evasion:
                evas_i += 1
                out_file = out_rule_dir / f"{file_prefix}_Evasion_{fmt_idx(evas_i)}.json"
                out_file.write_text(json.dumps(ev_norm, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"[+] Wrote MATCH={match_i}, EVASION={evas_i} into: {out_rule_dir}")
    print(f"[i] Skipped summary/invalid rows: {skipped_summary}")
    print(f"[i] Skipped missing/non-file logs: {skipped_missing_logs}")
    print(f"[i] Skipped logs with no EventID=1: {skipped_no_events}")
    print(f"[i] Skipped rows with no best event: {skipped_no_best}")
    print(f"[!] Next required step: create sigma/rules/{args.platform}/process_creation/<rule_dir_name>.yml (same rule_dir_name).")


if __name__ == "__main__":
    main()
