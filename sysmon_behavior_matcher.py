#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations
import argparse
import csv
import html
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set
import xml.etree.ElementTree as ET


# --------- Sysmon XML extraction ---------
XML_EVENT_RE = re.compile(r"(<Event\b.*?</Event>)", re.DOTALL)
CMD_LINE_RE = re.compile(r"^\[.*?\]\s+CMD\s+(\d+):\s+(.*)$")
PROCESS_CREATE_EID = "1"


# --------- Defaults tuned for your pipeline noise ---------
DEFAULT_WRAPPERS = {
    "sudo", "su",
    "sh", "bash", "dash", "zsh",
    "env",
}

DEFAULT_IGNORE_IMAGES = {
    "systemd-tty-ask-password-agent",
    "journalctl",
    "systemctl",
    "ps", "cat", "sed", "grep", "awk", "tail", "head", "tee",
    "sleep",
    "git",
    "python", "python3",
}

DEFAULT_NOISE_CMD_REGEX = r"(journalctl\s+--vacuum|journalctl\s+-u\s+sysmon|systemctl\s+restart\s+sysmon)"


@dataclass
class ProcCreate:
    time: str
    event_id: str
    process_guid: str
    parent_process_guid: str
    image: str
    command_line: str
    parent_image: str
    user: str


def basename(p: str) -> str:
    return Path(p.strip()).name.lower() if p else ""


def normalize_cmdline(s: str) -> str:
    if not s:
        return ""
    s = html.unescape(s).strip()
    s = s.replace("\\", "")
    s = s.replace("`", "")
    s = s.replace('"', "")
    s = s.replace("'", "")
    s = re.sub(r"\s+", " ", s)
    return s.strip().lower()


def parse_sysmon_event_xml(xml_text: str) -> Optional[ProcCreate]:
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return None

    eid_node = root.find("./System/EventID")
    if eid_node is None or not (eid_node.text or "").strip():
        return None
    event_id = (eid_node.text or "").strip()

    time = ""
    tc = root.find("./System/TimeCreated")
    if tc is not None:
        time = tc.attrib.get("SystemTime", "") or tc.attrib.get("systemtime", "") or ""

    data: Dict[str, str] = {}
    for d in root.findall("./EventData/Data"):
        name = d.attrib.get("Name", "")
        val = (d.text or "").strip()
        if name:
            data[name] = val

    return ProcCreate(
        time=time,
        event_id=event_id,
        process_guid=data.get("ProcessGuid", ""),
        parent_process_guid=data.get("ParentProcessGuid", ""),
        image=data.get("Image", ""),
        command_line=data.get("CommandLine", ""),
        parent_image=data.get("ParentImage", ""),
        user=data.get("User", data.get("UserName", "")),
    )


def iter_proc_create_events_from_file(log_path: Path) -> List[ProcCreate]:
    text = log_path.read_text(encoding="utf-8", errors="replace")
    events: List[ProcCreate] = []
    for m in XML_EVENT_RE.finditer(text):
        ev = parse_sysmon_event_xml(m.group(1))
        if not ev:
            continue
        if str(ev.event_id) != PROCESS_CREATE_EID:
            continue
        events.append(ev)
    return events


def extract_cmd_header(log_path: Path) -> str:
    try:
        for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines()[:150]:
            m = CMD_LINE_RE.match(line.strip())
            if m:
                return m.group(2).strip()
    except Exception:
        pass
    return ""


def load_commands(path: Path) -> List[str]:
    return [ln.strip() for ln in path.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()]


def infer_rule_name_from_logs_dir(logs_dir: Path) -> str:
    return logs_dir.name


def build_action_set(
    events: List[ProcCreate],
    wrappers: Set[str],
    ignore_images: Set[str],
    noise_cmd_re: Optional[re.Pattern],
    keep_images: Set[str],
) -> Set[str]:
    """
    Action set = behavior tokens after filtering noise/wrappers.
    Token: image_basename|normalized_commandline
    """
    out: Set[str] = set()
    for e in events:
        img = basename(e.image)
        cmdn = normalize_cmdline(e.command_line)

        if img in ignore_images and img not in keep_images:
            continue
        if img in wrappers and img not in keep_images:
            continue
        if noise_cmd_re and noise_cmd_re.search(cmdn):
            continue
        if not cmdn:
            continue

        out.add(f"{img}|{cmdn}")
    return out


def jaccard(a: Set[str], b: Set[str]) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def coverage(baseline: Set[str], cand: Set[str]) -> float:
    if not baseline:
        return 0.0
    return len(baseline & cand) / len(baseline)


def main():
    ap = argparse.ArgumentParser(
        description="Match per-command Sysmon logs to baseline behavior using ACTION events; copy matched logs to logs_output/<rule>_checklog; and write matched commands to attack_commands/<rule>_checklog.txt."
    )
    ap.add_argument("--baseline-log", required=True)
    ap.add_argument("--logs-dir", required=True)
    ap.add_argument("--success-commands", default=None, help="List of commands (one per line), used if log header lacks CMD line")
    ap.add_argument("--rule-name", default=None)

    ap.add_argument("--wrappers", default=",".join(sorted(DEFAULT_WRAPPERS)))
    ap.add_argument("--ignore-images", default=",".join(sorted(DEFAULT_IGNORE_IMAGES)))
    ap.add_argument("--keep-images", default="", help="Comma-separated images to FORCE keep (override ignore/wrapper).")
    ap.add_argument("--noise-cmd-regex", default=DEFAULT_NOISE_CMD_REGEX)

    ap.add_argument("--cov-thr", type=float, default=0.90)
    ap.add_argument("--jac-thr", type=float, default=0.50)

    ap.add_argument("--out-csv", default="matched_by_sysmon.csv")
    ap.add_argument("--out-final", default="final_Sucess.txt")

    ap.add_argument("--copy-to-checklog", action="store_true")
    ap.add_argument("--checklog-root", default=None, help="Root that contains logs_output. Default: logs-dir parent.")

    ap.add_argument(
        "--out-attack-checklog",
        default=None,
        help="Output file path under attack_commands for matched commands. Default: attack_commands/<rule>_checklog.txt",
    )

    args = ap.parse_args()

    baseline_log = Path(args.baseline_log)
    logs_dir = Path(args.logs_dir)

    wrappers = {x.strip().lower() for x in args.wrappers.split(",") if x.strip()}
    ignore_images = {x.strip().lower() for x in args.ignore_images.split(",") if x.strip()}
    keep_images = {x.strip().lower() for x in args.keep_images.split(",") if x.strip()}
    noise_cmd_re = re.compile(args.noise_cmd_regex) if args.noise_cmd_regex else None

    success_cmds: List[str] = []
    if args.success_commands:
        success_cmds = load_commands(Path(args.success_commands))

    rule_name = args.rule_name or infer_rule_name_from_logs_dir(logs_dir)

    # Baseline action-set
    base_events = iter_proc_create_events_from_file(baseline_log)
    base_action = build_action_set(base_events, wrappers, ignore_images, noise_cmd_re, keep_images)
    if not base_action:
        raise SystemExit(
            "Baseline action-set is empty after filtering. Try: --keep-images kmod (or relax ignore/wrapper/noise filters)."
        )

    # Candidate logs
    log_files = sorted([p for p in logs_dir.glob("*") if p.is_file()])

    # logs_output/<rule>_checklog
    checklog_root = Path(args.checklog_root) if args.checklog_root else logs_dir.parent
    checklog_dir = checklog_root / f"{rule_name}_checklog"

    rows = []
    matched_logs: List[Path] = []
    matched_cmds: List[str] = []

    for idx, lf in enumerate(log_files):
        evs = iter_proc_create_events_from_file(lf)
        cand_action = build_action_set(evs, wrappers, ignore_images, noise_cmd_re, keep_images)

        cov = coverage(base_action, cand_action)
        jac = jaccard(base_action, cand_action)

        status = "MATCH" if (cov >= args.cov_thr and jac >= args.jac_thr) else "NO_MATCH"

        cmd = extract_cmd_header(lf)
        if not cmd and idx < len(success_cmds):
            cmd = success_cmds[idx]

        rows.append({
            "log_file": lf.name,
            "status": status,
            "action_coverage": f"{cov:.3f}",
            "action_jaccard": f"{jac:.3f}",
            "baseline_action_size": str(len(base_action)),
            "cand_action_size": str(len(cand_action)),
            "intersection_size": str(len(base_action & cand_action)),
            "mapped_command": cmd,
        })

        if status == "MATCH":
            matched_logs.append(lf)
            if cmd:
                matched_cmds.append(cmd)

    # Write CSV
    out_csv = Path(args.out_csv)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["log_file"])
        w.writeheader()
        for r in rows:
            w.writerow(r)

    # Write final_Sucess.txt
    out_final = Path(args.out_final)
    out_final.parent.mkdir(parents=True, exist_ok=True)
    out_final.write_text("\n".join(matched_cmds) + ("\n" if matched_cmds else ""), encoding="utf-8")

    # Copy matched logs to logs_output/<rule>_checklog
    copied = 0
    if args.copy_to_checklog:
        checklog_dir.mkdir(parents=True, exist_ok=True)
        for src in matched_logs:
            shutil.copy2(src, checklog_dir / src.name)
            copied += 1

    # Write matched commands to attack_commands/<rule>_checklog.txt
    if args.out_attack_checklog:
        out_attack = Path(args.out_attack_checklog)
    else:
        # default: sibling folder "attack_commands" next to logs_output
        # if your project layout differs, pass --out-attack-checklog explicitly
        project_root = logs_dir.parent.parent if logs_dir.parent.name == "logs_output" else Path(".")
        out_attack = project_root / "attack_commands" / f"{rule_name}_checklog.txt"

    out_attack.parent.mkdir(parents=True, exist_ok=True)
    out_attack.write_text("\n".join(matched_cmds) + ("\n" if matched_cmds else ""), encoding="utf-8")

    # Summary
    print(f"Baseline: {baseline_log}")
    print(f"Rule: {rule_name}")
    print(f"Baseline action tokens: {len(base_action)}")
    print(f"Scanned logs: {len(log_files)} | matched: {len(matched_logs)}")
    print(f"CSV  : {out_csv.resolve()}")
    print(f"FINAL: {out_final.resolve()}")
    print(f"ATTACK_CHECKLOG: {out_attack.resolve()}")
    if args.copy_to_checklog:
        print(f"CHECKLOG DIR: {checklog_dir.resolve()} | copied: {copied}")


if __name__ == "__main__":
    main()
