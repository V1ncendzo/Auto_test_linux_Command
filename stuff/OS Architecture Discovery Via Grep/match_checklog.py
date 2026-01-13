#!/usr/bin/env python3
# match_checklog.py
#
# Find commands whose Output/Error matches the baseline CMD (default: CMD 1)
# and write matched commands to: <foldername>_checklog.txt
#
# This version:
# - Supports both "-Output:" and "-Error:" blocks (your logs include -Error)  ✅
# - Finds attack_commands/ by walking up parent dirs (your attack_commands is at workspace root) ✅
#
# Usage:
#   cd "stuff/OS Architecture Discovery Via Grep"
#   python3 match_checklog.py --request request.txt --output "output_requests_OS Architecture Discovery Via Grep.txt" --baseline-cmd 2
#
# Modes:
#   --mode sorted (default): ignore ordering of lines
#   --mode strict: exact line-by-line

import argparse
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

SEP_RE = re.compile(r"^#{10,}\s*$")
CMD_RE = re.compile(r"^\[(.*?)\]\s*CMD\s+(\d+):\s*(.*)\s*$")
OUT_MARK_RE = re.compile(r"^\s*-Output:\s*$")
ERR_MARK_RE = re.compile(r"^\s*-Error:\s*$")


def normalize_lines(lines: List[str]) -> List[str]:
    # strip trailing spaces; trim leading/trailing empty lines
    cleaned = [ln.rstrip("\r\n").rstrip() for ln in lines]
    while cleaned and cleaned[0] == "":
        cleaned.pop(0)
    while cleaned and cleaned[-1] == "":
        cleaned.pop()
    return cleaned


def parse_output_log(text: str) -> List[Dict]:
    """
    Parse blocks like:
    ##################################################
    [2026-01-12 20:44:01] CMD 2: uname -a | grep x86_64 --color=auto
    -Output:
    Linux ...
    OR
    -Error:
    grep: ...
    """
    lines = text.splitlines(True)  # keep \n
    blocks: List[List[str]] = []
    cur: List[str] = []

    for ln in lines:
        if SEP_RE.match(ln.strip()):
            if cur:
                blocks.append(cur)
                cur = []
            continue
        cur.append(ln)
    if cur:
        blocks.append(cur)

    parsed = []
    for b in blocks:
        raw = [x.rstrip("\n") for x in b]

        cmd_line_idx: Optional[int] = None
        marker_idx: Optional[int] = None
        marker_kind: Optional[str] = None  # "output" or "error"

        for i, ln in enumerate(raw):
            if cmd_line_idx is None and CMD_RE.match(ln.strip()):
                cmd_line_idx = i
            if OUT_MARK_RE.match(ln.strip()):
                marker_idx = i
                marker_kind = "output"
                break
            if ERR_MARK_RE.match(ln.strip()):
                marker_idx = i
                marker_kind = "error"
                break

        if cmd_line_idx is None:
            continue

        m = CMD_RE.match(raw[cmd_line_idx].strip())
        ts, cmd_no, cmd = m.group(1), int(m.group(2)), m.group(3)

        body_lines: List[str] = []
        if marker_idx is not None:
            body_lines = raw[marker_idx + 1 :]
        else:
            # no marker => treat as empty output (won't match baseline unless baseline is empty w/ no marker)
            marker_kind = "output"
            body_lines = []

        parsed.append(
            {
                "ts": ts,
                "cmd_no": cmd_no,
                "cmd": cmd,
                "kind": marker_kind,  # "output" or "error"
                "lines": normalize_lines(body_lines),
            }
        )
    return parsed


def load_request_commands(path: Path) -> List[str]:
    cmds = []
    for ln in path.read_text(encoding="utf-8", errors="replace").splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        cmds.append(s)
    return cmds


def compare_lines(a: List[str], b: List[str], mode: str) -> bool:
    if mode == "strict":
        return a == b
    return sorted(a) == sorted(b)


def safe_name(name: str) -> str:
    # keep it close to folder name but file-safe; spaces -> underscore
    name = name.strip().replace(" ", "_")
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name)
    return name.strip("_") or "checklog"


def find_attack_commands_dir(start_dir: Path) -> Optional[Path]:
    """
    Walk upwards to find a folder named 'attack_commands'.
    This fixes your structure: rule folder is under stuff/... but attack_commands is at workspace root.
    """
    cur = start_dir.resolve()
    for _ in range(10):  # climb up to 10 levels
        candidate = cur / "attack_commands"
        if candidate.is_dir():
            return candidate
        if cur.parent == cur:
            break
        cur = cur.parent
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--request", required=True, help="Path to request.txt (list of commands)")
    ap.add_argument("--output", required=True, help="Path to output_*.txt (captured outputs)")
    ap.add_argument("--baseline-cmd", type=int, default=1, help="Which CMD number to use as baseline (default: 1)")
    ap.add_argument(
        "--mode",
        choices=["sorted", "strict"],
        default="sorted",
        help="Compare body lines as sorted (default) or strict line-by-line",
    )
    ap.add_argument(
        "--out",
        default=None,
        help="Output file path (default: attack_commands/<folder>_checklog.txt if found, else ./<folder>_checklog.txt)",
    )
    args = ap.parse_args()

    req_path = Path(args.request)
    out_path = Path(args.output)

    if not req_path.is_file():
        raise SystemExit(f"[!] request file not found: {req_path}")
    if not out_path.is_file():
        raise SystemExit(f"[!] output file not found: {out_path}")

    request_cmds = load_request_commands(req_path)
    log_entries = parse_output_log(out_path.read_text(encoding="utf-8", errors="replace"))

    if not log_entries:
        raise SystemExit("[!] No CMD blocks parsed from output log. Check the output format.")

    baseline_entry = next((e for e in log_entries if e["cmd_no"] == args.baseline_cmd), None)
    if baseline_entry is None:
        raise SystemExit(f"[!] Baseline CMD {args.baseline_cmd} not found in output log.")

    baseline_kind = baseline_entry["kind"]          # "output" or "error"
    baseline_lines = baseline_entry["lines"]        # normalized body lines

    # Map command -> (kind, lines) from log (if duplicated commands, keep first)
    cmd_to_result: Dict[str, Tuple[str, List[str]]] = {}
    for e in log_entries:
        cmd_to_result.setdefault(e["cmd"], (e["kind"], e["lines"]))

    matched: List[str] = []
    missing_in_log = 0

    for cmd in request_cmds:
        if cmd not in cmd_to_result:
            missing_in_log += 1
            continue
        kind, lines = cmd_to_result[cmd]

        # must match both kind (Output/Error) and content
        if kind == baseline_kind and compare_lines(lines, baseline_lines, args.mode):
            matched.append(cmd)

    # Decide output destination
    if args.out:
        dest = Path(args.out)
    else:
        folder_name = safe_name(Path.cwd().name)
        default_name = f"{folder_name}_checklog.txt"

        attack_dir = find_attack_commands_dir(Path.cwd())
        if attack_dir:
            dest = attack_dir / default_name
        else:
            dest = Path.cwd() / default_name

    dest.write_text("\n".join(matched) + ("\n" if matched else ""), encoding="utf-8")

    print("=== MATCH CHECKLOG ===")
    print(f"Request commands : {len(request_cmds)}")
    print(f"Parsed CMD blocks: {len(log_entries)}")
    print(f"Baseline CMD     : {args.baseline_cmd} ({baseline_kind}, lines={len(baseline_lines)})")
    print(f"Compare mode     : {args.mode}")
    print(f"Matched          : {len(matched)}")
    print(f"Missing in log   : {missing_in_log}")
    print(f"Output written   : {dest}")


if __name__ == "__main__":
    main()
