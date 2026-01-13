#!/usr/bin/env python3
# match_checklog.py
#
# Find commands whose output matches the baseline output (CMD 1 by default)
# and write matched commands to attack_commands/<RuleFolder>_checklog.txt
#
# Folder layout (your case):
#   stuff/
#     File and Directory Discovery/
#       match_checklog.py
#       request.txt
#       output_*.txt
#   attack_commands/
#     ...
#
# Usage:
#   cd "stuff/File and Directory Discovery"
#   python3 match_checklog.py --request request.txt --output output_2026-01-04-19-24-52.txt
#
# Or from workspace root:
#   python3 "stuff/File and Directory Discovery/match_checklog.py" \
#     --request "stuff/File and Directory Discovery/request.txt" \
#     --output  "stuff/File and Directory Discovery/output_2026-01-04-19-24-52.txt"
#
# Notes:
# - Default compare mode is "sorted" (ignore ordering of output lines), good for find(1).
# - Use --mode strict to require exact same order.

import argparse
import re
from pathlib import Path
from typing import Dict, List


SEP_RE = re.compile(r"^#{10,}\s*$")
CMD_RE = re.compile(r"^\[(.*?)\]\s*CMD\s+(\d+):\s*(.*)\s*$")
OUT_MARK_RE = re.compile(r"^\s*-Output:\s*$")


def normalize_lines(lines: List[str]) -> List[str]:
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
    [2026-01-04 19:24:52] CMD 1: <command>
    -Output:
    <many lines>
    """
    lines = text.splitlines(True)  # keep '\n'
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
        cmd_line_idx = None
        out_idx = None

        for i, ln in enumerate(raw):
            if cmd_line_idx is None and CMD_RE.match(ln.strip()):
                cmd_line_idx = i
            if OUT_MARK_RE.match(ln.strip()):
                out_idx = i
                break

        if cmd_line_idx is None:
            continue

        m = CMD_RE.match(raw[cmd_line_idx].strip())
        ts, cmd_no, cmd = m.group(1), int(m.group(2)), m.group(3)

        if out_idx is not None:
            output_lines = raw[out_idx + 1 :]
        else:
            # no "-Output:" marker -> treat as empty (will rarely match baseline)
            output_lines = []

        parsed.append(
            {
                "ts": ts,
                "cmd_no": cmd_no,
                "cmd": cmd,
                "output": normalize_lines(output_lines),
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


def compare_outputs(a: List[str], b: List[str], mode: str) -> bool:
    if mode == "strict":
        return a == b
    # default: ignore ordering
    return sorted(a) == sorted(b)


def safe_stem(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_") or "checklog"


def find_workspace_root(start: Path) -> Path:
    """
    Walk up from 'start' to find a directory that contains 'attack_commands'.
    """
    for p in [start] + list(start.parents):
        if (p / "attack_commands").is_dir():
            return p
    return Path.cwd()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--request", required=True, help="Path to request.txt (list of commands)")
    ap.add_argument("--output", required=True, help="Path to output_*.txt (captured outputs)")
    ap.add_argument("--baseline-cmd", type=int, default=1, help="Which CMD number to use as baseline (default: 1)")
    ap.add_argument(
        "--mode",
        choices=["sorted", "strict"],
        default="sorted",
        help="Compare outputs as sorted lines (default) or strict line-by-line",
    )
    ap.add_argument(
        "--out",
        default=None,
        help="Optional output path. If set, overrides default attack_commands/<RuleFolder>_checklog.txt",
    )
    args = ap.parse_args()

    req_path = Path(args.request).resolve()
    out_path = Path(args.output).resolve()

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
    baseline_output = baseline_entry["output"]

    # Map command -> output from log (keep first occurrence)
    cmd_to_output: Dict[str, List[str]] = {}
    for e in log_entries:
        cmd_to_output.setdefault(e["cmd"], e["output"])

    matched: List[str] = []
    missing_in_log = 0
    for cmd in request_cmds:
        if cmd not in cmd_to_output:
            missing_in_log += 1
            continue
        if compare_outputs(cmd_to_output[cmd], baseline_output, args.mode):
            matched.append(cmd)

    # Output destination (fixed for your folder structure)
    if args.out:
        dest = Path(args.out).resolve()
        dest.parent.mkdir(parents=True, exist_ok=True)
        rule_folder = req_path.parent.name
        workspace_root = find_workspace_root(req_path.parent)
    else:
        rule_folder = req_path.parent.name  # e.g. "File and Directory Discovery"
        workspace_root = find_workspace_root(req_path.parent)
        out_name = f"{safe_stem(rule_folder)}_checklog.txt"
        dest = (workspace_root / "attack_commands" / out_name).resolve()
        dest.parent.mkdir(parents=True, exist_ok=True)

    dest.write_text("\n".join(matched) + ("\n" if matched else ""), encoding="utf-8")

    print("=== MATCH CHECKLOG ===")
    print(f"Rule folder      : {rule_folder}")
    print(f"Workspace root   : {workspace_root}")
    print(f"Request commands : {len(request_cmds)}")
    print(f"Parsed CMD blocks: {len(log_entries)}")
    print(f"Baseline CMD     : {args.baseline_cmd} (lines={len(baseline_output)})")
    print(f"Compare mode     : {args.mode}")
    print(f"Matched          : {len(matched)}")
    print(f"Missing in log   : {missing_in_log}")
    print(f"Output written   : {dest}")


if __name__ == "__main__":
    main()
