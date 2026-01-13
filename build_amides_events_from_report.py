#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import html
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

# --- Sysmon Linux: extract <Event>...</Event> blocks from syslog/journal text ---
EVENT_RE = re.compile(r"(<Event\b.*?</Event>)", flags=re.DOTALL)


SAFE = re.compile(r"[^a-zA-Z0-9._-]+")
B64_RE = re.compile(r"[A-Za-z0-9+/=]{20,}")


def safe_name(s: str) -> str:
    s = (s or "").strip()
    s = SAFE.sub("_", s)
    return s[:120] if len(s) > 120 else s


def write_properties_yml(rule_dir: Path, queried_event_type: str, evasion_possible: str):
    """
    IMPORTANT for AMIDES:
      - properties.yml must be a YAML LIST (starts with "-")
      - queried_event_types[0] must be an event-name known to AMIDES mapping
    """
    # Align with AMIDES sample structure
    content = (
        "- queried_event_types:\n"
        f"    - {queried_event_type}\n"
        f"  evasion_possible: {evasion_possible}\n"
        "  broken_rule: no\n"
        "  edited_fields:\n"
        "    - CommandLine\n"
        "    - Image\n"
        "    - CurrentDirectory\n"
    )
    (rule_dir / "properties.yml").write_text(content, encoding="utf-8")


def parse_sysmon_event_xml(xml_str: str):
    """Return (event_id, system_time, computer, eventdata_dict) or None."""
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return None

    system = root.find("System")
    if system is None:
        return None

    event_id = system.findtext("EventID")
    time_created = system.find("TimeCreated")
    ts = time_created.attrib.get("SystemTime") if time_created is not None else None
    computer = system.findtext("Computer")

    ed = root.find("EventData")
    data = {}
    if ed is not None:
        for d in ed.findall("Data"):
            k = d.attrib.get("Name")
            if not k:
                continue
            v = d.text or ""
            data[k] = html.unescape(v)

    return event_id, ts, computer, data


def extract_process_create_events(log_path: Path):
    """Extract EventID=1 events from a Sysmon-for-Linux log file."""
    text = log_path.read_text(encoding="utf-8", errors="ignore")
    blocks = EVENT_RE.findall(text)
    out = []
    for b in blocks:
        parsed = parse_sysmon_event_xml(b)
        if not parsed:
            continue
        event_id, ts, computer, d = parsed
        if str(event_id) != "1":
            continue
        out.append({
            "SystemTime": ts,
            "Computer": computer,
            **d
        })
    return out


def parse_sha256(m: dict):
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


def basename(p: str | None):
    if not p:
        return None
    p = p.replace("\\", "/")
    return p.split("/")[-1]


def normalize_event_for_amides(
    m: dict,
    rule_title: str,
    rule_id: str | None,
    attack_id: str,
    original_cmd: str,
    log_file: str,
    queried_event_type: str,
):
    """
    Output event contains:
      - ECS-ish: process.command_line (payload), process.executable, process.working_directory, etc.
      - Sysmon-like top-level duplicates: CommandLine, Image, CurrentDirectory
    This makes it compatible with AMIDES edited_fields and rule filters that expect Sysmon fields.
    """
    sha256 = parse_sha256(m)

    proc_exe = m.get("Image")
    cmd = m.get("CommandLine")
    cwd = m.get("CurrentDirectory")
    parent_exe = m.get("ParentImage")

    out = {
        "@timestamp": m.get("SystemTime") or m.get("UtcTime"),
        "message": "Process Create (Sysmon for Linux)",

        # --- Sysmon-like flat fields (to match edited_fields in properties.yml) ---
        "CommandLine": cmd,
        "Image": proc_exe,
        "CurrentDirectory": cwd,

        # --- ECS-ish structure ---
        "event": {
            "code": 1,
            "provider": "Linux-Sysmon",
            "category": ["process"],
            "type": ["start", "process_start"],
            "action": "Process Create",
        },
        "host": {"hostname": m.get("Computer")} if m.get("Computer") else {},
        "user": {"name": m.get("User")} if m.get("User") else {},
        "process": {
            "pid": int(m["ProcessId"]) if isinstance(m.get("ProcessId"), str) and m["ProcessId"].isdigit() else m.get("ProcessId"),
            "entity_id": m.get("ProcessGuid"),
            "executable": proc_exe,
            "name": basename(proc_exe),
            "command_line": cmd,  # <-- payload chính bạn cần
            "working_directory": cwd,
            "hash": {"sha256": sha256} if sha256 else {},
            "parent": {
                "pid": int(m["ParentProcessId"]) if isinstance(m.get("ParentProcessId"), str) and m["ParentProcessId"].isdigit() else m.get("ParentProcessId"),
                "entity_id": m.get("ParentProcessGuid"),
                "executable": parent_exe,
                "name": basename(parent_exe),
                "command_line": m.get("ParentCommandLine"),
            },
        },

        # provenance
        "labels": {
            "sigma_rule_title": rule_title,
            "sigma_rule_id": rule_id,
            "attack_id": attack_id,
            "original_command": original_cmd,
            "log_file": log_file,
            "queried_event_type": queried_event_type,
        },

        # keep raw
        "sysmon": {"linux_event_data": m},
    }

    # clean empties
    if out.get("host") == {}:
        out.pop("host", None)
    if out.get("user") == {}:
        out.pop("user", None)
    if out["process"].get("hash") == {}:
        out["process"].pop("hash", None)

    return out


def best_event_for_command(events: list[dict], command: str):
    """
    Heuristic: find EventID=1 event whose CommandLine best matches the command.
    Uses base64 anchor(s) if present, else uses a few keyword anchors.
    """
    cmd = command or ""
    anchors = sorted(set(B64_RE.findall(cmd)), key=len, reverse=True)[:3]
    if not anchors:
        for tok in ["base64", "bash", "sh -c", "dash", "python", "curl", "wget", "perl", "python3", "php"]:
            if tok in cmd:
                anchors.append(tok)

    best = None
    best_score = -1
    for ev in events:
        cl = ev.get("CommandLine") or ""
        score = 0
        for a in anchors:
            if a and a in cl:
                score += 5 if len(a) > 10 else 1
        if "bash -c" in cl or "/bin/bash -c" in cl:
            score += 1
        if "sh -c" in cl or "/bin/sh -c" in cl:
            score += 1
        if score > best_score:
            best_score = score
            best = ev

    return best, best_score, anchors


def is_summary_or_invalid_row(row: dict) -> bool:
    """
    Skip SUMMARY REPORT / invalid rows in Report_*.csv.
    We keep only rows that have:
      - numeric ID
      - non-empty Log File
    """
    rid = (row.get("ID") or "").strip()
    log_file = (row.get("Log File") or "").strip()
    result = (row.get("Result") or "").strip()

    # explicit summary marker
    if "SUMMARY REPORT" in result.upper():
        return True

    # keep only numeric ID rows
    if not rid.isdigit():
        return True

    # log file must exist-like
    if not log_file or log_file.lower() in ("nan", "none"):
        return True

    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", required=True, help="Report_*.csv path")
    ap.add_argument("--logs-dir", required=True, help="logs_output/<RuleFolder> directory")
    ap.add_argument("--rule-dir-name", required=True, help="Folder name under sigma/events/process_creation/ AND rules/process_creation/<name>.yml")
    ap.add_argument("--rule-title", required=True, help="Sigma rule title (for labels)")
    ap.add_argument("--rule-id", default=None, help="Sigma rule id (optional, for labels)")
    ap.add_argument("--out-root", default=".", help="Project root containing sigma/ (default: .)")
    ap.add_argument("--max-match", type=int, default=999999)
    ap.add_argument("--max-evasion", type=int, default=999999)

    # IMPORTANT: event type name must be recognized by AMIDES mapping.
    # Safest default: match AMIDES windows dataset.
    ap.add_argument("--queried-event-type", default="Microsoft-Windows-Sysmon_1",
                    help="Value to write into properties.yml -> queried_event_types[0] (default: Microsoft-Windows-Sysmon_1)")

    # If you are generating evasion files, set yes; else you can set no/unknown.
    ap.add_argument("--evasion-possible", default="yes", choices=["yes", "no", "unknown"],
                    help="Value to write into properties.yml (default: yes)")
    args = ap.parse_args()

    report = Path(args.report)
    logs_dir = Path(args.logs_dir)
    out_root = Path(args.out_root)

    rule_dir_name = args.rule_dir_name
    rule_title = args.rule_title
    rule_id = args.rule_id

    out_rule_dir = out_root / "sigma" / "events" / "process_creation" / rule_dir_name
    out_rule_dir.mkdir(parents=True, exist_ok=True)

    prop = out_rule_dir / "properties.yml"
    if not prop.exists():
        write_properties_yml(out_rule_dir, args.queried_event_type, args.evasion_possible)

    match_i = 0
    evas_i = 0
    skipped_summary = 0
    skipped_missing_logs = 0

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

            # must be a file, not a directory
            if not log_path.exists() or not log_path.is_file():
                skipped_missing_logs += 1
                continue

            events = extract_process_create_events(log_path)
            if not events:
                continue

            ev_raw, score, anchors = best_event_for_command(events, cmd)
            if not ev_raw:
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

            # classify
            is_trigger = result.startswith("Trigger")
            is_bypass = result.strip() == "Bypass Target Rule"

            if is_trigger and match_i < args.max_match:
                match_i += 1
                out_file = out_rule_dir / f"{rule_dir_name}_Match_{match_i:04d}.json"
                out_file.write_text(json.dumps(ev_norm, ensure_ascii=False, indent=2), encoding="utf-8")

            elif is_bypass and evas_i < args.max_evasion:
                evas_i += 1
                out_file = out_rule_dir / f"{rule_dir_name}_Evasion_Bypass_{evas_i:04d}.json"
                out_file.write_text(json.dumps(ev_norm, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"[+] Wrote MATCH={match_i}, EVASION={evas_i} into: {out_rule_dir}")
    print(f"[i] Skipped summary/invalid rows: {skipped_summary}")
    print(f"[i] Skipped missing/non-file logs: {skipped_missing_logs}")
    print("[!] Next required step: create sigma/rules/process_creation/<rule_dir_name>.yml (same rule_dir_name).")


if __name__ == "__main__":
    main()
