#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations
import argparse
import html
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
import xml.etree.ElementTree as ET

# --------- Sysmon XML extraction ---------
XML_EVENT_RE = re.compile(r"(<Event\b.*?</Event>)", re.DOTALL)
PROCESS_CREATE_EID = "1"

# Lấy số attackNNN từ filename
ATTACK_ID_RE = re.compile(r"attack(\d+)", re.IGNORECASE)

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


def load_commands(path: Path) -> List[str]:
    return [ln.strip() for ln in path.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()]


def attack_index_from_filename(name: str) -> Optional[int]:
    """
    Return 1-based attack id from filename like *_attack21.log -> 21
    """
    m = ATTACK_ID_RE.search(name)
    if not m:
        return None
    try:
        return int(m.group(1))
    except Exception:
        return None


def map_command_for_log(lf: Path, commands: List[str], fallback_zero_based: int) -> Tuple[Optional[int], str]:
    """
    Prefer mapping by attackNNN in filename (1-based line number).
    Fallback: by enumeration index.
    """
    if not commands:
        return (attack_index_from_filename(lf.name), "")

    aid = attack_index_from_filename(lf.name)
    if aid is not None:
        idx = aid - 1
        if 0 <= idx < len(commands):
            return (aid, commands[idx])

    # fallback by order
    if 0 <= fallback_zero_based < len(commands):
        return (aid, commands[fallback_zero_based])

    return (aid, "")


def default_out_command_checklog(logs_path: Path, rule_name: str) -> Path:
    """
    Default: <project_root>/attack_commands/<rule>_checklog.txt
    Heuristic: if logs_path is logs_output/<rule> then project_root = logs_output/..
    """
    if logs_path.is_dir() and logs_path.parent.name == "logs_output":
        project_root = logs_path.parent.parent
    else:
        # if given a file: .../logs_output/<rule>/<file>.log
        if logs_path.is_file() and logs_path.parent.parent.name == "logs_output":
            project_root = logs_path.parent.parent.parent
        else:
            project_root = Path(".")
    return project_root / "attack_commands" / f"{rule_name}_checklog.txt"


def main():
    ap = argparse.ArgumentParser(
        description="Match Sysmon ProcessCreate (EventID=1) behavior of logs against a baseline; copy matched logs to logs_output/<rule>_checklog; and optionally write matched commands to attack_commands/<rule>_checklog.txt."
    )
    ap.add_argument("--baseline-log", required=True)
    ap.add_argument("--logs-dir", required=True, help="Folder containing logs, or a single log file path")
    ap.add_argument("--rule-name", default=None)

    ap.add_argument("--wrappers", default=",".join(sorted(DEFAULT_WRAPPERS)))
    ap.add_argument("--ignore-images", default=",".join(sorted(DEFAULT_IGNORE_IMAGES)))
    ap.add_argument("--keep-images", default="", help="Comma-separated images to FORCE keep (override ignore/wrapper).")

    # Nếu bạn muốn tắt noise filter trên PowerShell, dùng: --noise-cmd-regex "(?!)" hoặc "a^"
    ap.add_argument("--noise-cmd-regex", default=DEFAULT_NOISE_CMD_REGEX)

    ap.add_argument("--cov-thr", type=float, default=0.90)
    ap.add_argument("--jac-thr", type=float, default=0.50)

    ap.add_argument("--copy-to-checklog", action="store_true")
    ap.add_argument("--checklog-root", default=None, help="Root that contains logs_output. Default: logs parent folder.")
    ap.add_argument("--verbose", action="store_true")

    # NEW: output matched commands file
    ap.add_argument("--commands-file", default=None, help="File containing commands (one per line). Used to output <rule>_checklog.txt")
    ap.add_argument("--out-command-checklog", default=None, help="Output path for matched commands file (default: attack_commands/<rule>_checklog.txt)")

    args = ap.parse_args()

    baseline_log = Path(args.baseline_log)
    logs_path = Path(args.logs_dir)

    wrappers = {x.strip().lower() for x in args.wrappers.split(",") if x.strip()}
    ignore_images = {x.strip().lower() for x in args.ignore_images.split(",") if x.strip()}
    keep_images = {x.strip().lower() for x in args.keep_images.split(",") if x.strip()}

    noise_cmd_re = re.compile(args.noise_cmd_regex) if args.noise_cmd_regex else None

    rule_name = args.rule_name or infer_rule_name(logs_path)

    # Load commands if provided
    commands: List[str] = []
    if args.commands_file:
        commands = load_commands(Path(args.commands_file))

    # Baseline
    base_events = iter_proc_create_events_from_file(baseline_log)
    base_action = build_action_set(base_events, wrappers, ignore_images, noise_cmd_re, keep_images)
    if not base_action:
        raise SystemExit(
            "Baseline action-set is empty after filtering. "
            "Gợi ý: nếu baseline của bạn là shred thì không cần keep journalctl. "
            "Nếu baseline có journalctl mà bị filter thì dùng --keep-images journalctl hoặc tắt noise bằng --noise-cmd-regex '(?!)'."
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
    matched_cmds_with_id: List[Tuple[Optional[int], str]] = []

    for i, lf in enumerate(log_files):
        evs = iter_proc_create_events_from_file(lf)
        cand_action = build_action_set(evs, wrappers, ignore_images, noise_cmd_re, keep_images)

        cov = coverage(base_action, cand_action)
        jac = jaccard(base_action, cand_action)

        ok = (cov >= args.cov_thr and jac >= args.jac_thr)
        if ok:
            matched_logs.append(lf)

            # map command for this log (optional)
            if commands:
                aid, cmd = map_command_for_log(lf, commands, i)
                if cmd:
                    matched_cmds_with_id.append((aid, cmd))

        if args.verbose:
            status = "MATCH" if ok else "NO_MATCH"
            print(f"{lf.name}: {status} | cov={cov:.3f} jac={jac:.3f} | base={len(base_action)} cand={len(cand_action)}")

    # Copy matched logs
    copied = 0
    if args.copy_to_checklog:
        checklog_dir.mkdir(parents=True, exist_ok=True)
        for src in matched_logs:
            shutil.copy2(src, checklog_dir / src.name)
            copied += 1

    # Write matched commands file if commands-file provided
    out_cmd_path: Optional[Path] = None
    written_cmds = 0
    if commands:
        out_cmd_path = Path(args.out_command_checklog) if args.out_command_checklog else default_out_command_checklog(logs_path, rule_name)
        out_cmd_path.parent.mkdir(parents=True, exist_ok=True)

        # Sort by attack id if available, otherwise keep original order
        def sort_key(x: Tuple[Optional[int], str]) -> int:
            return x[0] if x[0] is not None else 10**9

        matched_cmds_with_id.sort(key=sort_key)
        matched_cmds = [cmd for _, cmd in matched_cmds_with_id]

        out_cmd_path.write_text("\n".join(matched_cmds) + ("\n" if matched_cmds else ""), encoding="utf-8")
        written_cmds = len(matched_cmds)

    print(f"Baseline: {baseline_log}")
    print(f"Rule: {rule_name}")
    print(f"Baseline action tokens: {len(base_action)}")
    print(f"Scanned logs: {len(log_files)} | matched: {len(matched_logs)}")
    if args.copy_to_checklog:
        print(f"CHECKLOG DIR: {checklog_dir.resolve()} | copied: {copied}")
    if out_cmd_path:
        print(f"COMMAND_CHECKLOG: {out_cmd_path.resolve()} | commands_written: {written_cmds}")


if __name__ == "__main__":
    main()
