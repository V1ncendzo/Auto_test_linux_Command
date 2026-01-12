#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations
import argparse
import html
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set
import xml.etree.ElementTree as ET

# --------- Sysmon XML extraction ---------
XML_EVENT_RE = re.compile(r"(<Event\b.*?</Event>)", re.DOTALL)
PROCESS_CREATE_EID = "1"

# --------- Defaults tuned for pipeline noise ---------
DEFAULT_WRAPPERS = {"sudo", "su", "sh", "bash", "dash", "zsh", "env"}

DEFAULT_IGNORE_IMAGES = {
    "systemd-tty-ask-password-agent",
    "journalctl",
    "systemctl",
    "ps", "cat", "sed", "grep", "awk", "tail", "head", "tee",
    "sleep",
    "git",
    "python", "python3",
}

# noise filter mặc định (bạn có thể override)
DEFAULT_NOISE_CMD_REGEX = r"(journalctl\s+--vacuum|journalctl\s+-u\s+sysmon|systemctl\s+restart\s+sysmon)"


@dataclass
class ProcCreate:
    time: str
    event_id: str
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


def infer_rule_name(logs_path: Path) -> str:
    return logs_path.name if logs_path.is_dir() else logs_path.stem


def build_action_set(
    events: List[ProcCreate],
    wrappers: Set[str],
    ignore_images: Set[str],
    noise_cmd_re: Optional[re.Pattern],
    keep_images: Set[str],
) -> Set[str]:
    """
    Action token = image_basename|normalized_commandline
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
        description="Match Sysmon ProcessCreate (EventID=1) behavior of logs against a baseline; copy matched logs to logs_output/<rule>_checklog."
    )
    ap.add_argument("--baseline-log", required=True)
    ap.add_argument("--logs-dir", required=True, help="Folder containing logs, or a single log file path")
    ap.add_argument("--rule-name", default=None)

    ap.add_argument("--wrappers", default=",".join(sorted(DEFAULT_WRAPPERS)))
    ap.add_argument("--ignore-images", default=",".join(sorted(DEFAULT_IGNORE_IMAGES)))
    ap.add_argument("--keep-images", default="", help="Comma-separated images to FORCE keep (override ignore/wrapper).")

    # Nếu bạn muốn “tắt noise filter” mà khỏi sửa code/khỏi empty string:
    # truyền regex không bao giờ match, ví dụ: (?!) hoặc a^
    ap.add_argument("--noise-cmd-regex", default=DEFAULT_NOISE_CMD_REGEX)

    ap.add_argument("--cov-thr", type=float, default=0.90)
    ap.add_argument("--jac-thr", type=float, default=0.50)

    ap.add_argument("--copy-to-checklog", action="store_true")
    ap.add_argument("--checklog-root", default=None, help="Root that contains logs_output. Default: logs parent folder.")
    ap.add_argument("--verbose", action="store_true")

    args = ap.parse_args()

    baseline_log = Path(args.baseline_log)
    logs_path = Path(args.logs_dir)

    wrappers = {x.strip().lower() for x in args.wrappers.split(",") if x.strip()}
    ignore_images = {x.strip().lower() for x in args.ignore_images.split(",") if x.strip()}
    keep_images = {x.strip().lower() for x in args.keep_images.split(",") if x.strip()}

    noise_cmd_re = re.compile(args.noise_cmd_regex) if args.noise_cmd_regex else None

    rule_name = args.rule_name or infer_rule_name(logs_path)

    # Baseline
    base_events = iter_proc_create_events_from_file(baseline_log)
    base_action = build_action_set(base_events, wrappers, ignore_images, noise_cmd_re, keep_images)
    if not base_action:
        raise SystemExit(
            "Baseline action-set is empty after filtering. "
            "Gợi ý: --keep-images journalctl và tắt noise bằng --noise-cmd-regex '(?!)'"
        )

    # Candidates
    if logs_path.is_file():
        log_files = [logs_path]
        logs_parent = logs_path.parent
    else:
        log_files = sorted([p for p in logs_path.glob("*") if p.is_file()])
        logs_parent = logs_path.parent

    checklog_root = Path(args.checklog_root) if args.checklog_root else logs_parent
    checklog_dir = checklog_root / f"{rule_name}_checklog"

    matched_logs: List[Path] = []

    for lf in log_files:
        evs = iter_proc_create_events_from_file(lf)
        cand_action = build_action_set(evs, wrappers, ignore_images, noise_cmd_re, keep_images)

        cov = coverage(base_action, cand_action)
        jac = jaccard(base_action, cand_action)

        ok = (cov >= args.cov_thr and jac >= args.jac_thr)
        if ok:
            matched_logs.append(lf)

        if args.verbose:
            status = "MATCH" if ok else "NO_MATCH"
            print(f"{lf.name}: {status} | cov={cov:.3f} jac={jac:.3f} | base={len(base_action)} cand={len(cand_action)}")

    copied = 0
    if args.copy_to_checklog:
        checklog_dir.mkdir(parents=True, exist_ok=True)
        for src in matched_logs:
            shutil.copy2(src, checklog_dir / src.name)
            copied += 1

    print(f"Baseline: {baseline_log}")
    print(f"Rule: {rule_name}")
    print(f"Baseline action tokens: {len(base_action)}")
    print(f"Scanned logs: {len(log_files)} | matched: {len(matched_logs)}")
    if args.copy_to_checklog:
        print(f"CHECKLOG DIR: {checklog_dir.resolve()} | copied: {copied}")


if __name__ == "__main__":
    main()
