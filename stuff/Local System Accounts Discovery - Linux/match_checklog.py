#!/usr/bin/env python3
# match_checklog.py
#
# Parse output log blocks:
#   ##################################################
#   [TS] CMD N: <command>
#   -Output: / -Error:
#   <lines...>
#
# Then: take baseline (CMD --baseline-cmd), and find commands in request.txt
# whose (Output/Error kind + content) match baseline.
#
# Output:
#   attack_commands/<RuleFolder>_checklog.txt
# where RuleFolder is the folder containing request.txt.
#
# Usage (PowerShell / Windows):
#   py -3 .\match_checklog.py --request .\request.txt --output ".\output_requests_XXX.txt" --baseline-cmd 360
#
# Usage (Linux/macOS):
#   python3 match_checklog.py --request request.txt --output output_requests_XXX.txt --baseline-cmd 360

import argparse
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

SEP_RE = re.compile(r"^#{10,}\s*$")
CMD_RE = re.compile(r"^\[(.*?)\]\s*CMD\s+(\d+):\s*(.*)\s*$")
OUT_MARK_RE = re.compile(r"^\s*-\s*Output:\s*$", re.IGNORECASE)
ERR_MARK_RE = re.compile(r"^\s*-\s*Error:\s*$", re.IGNORECASE)


def normalize_lines(lines: List[str]) -> List[str]:
    """Trim trailing spaces and remove leading/trailing blank lines."""
    cleaned = [ln.rstrip("\r\n").rstrip() for ln in lines]
    while cleaned and cleaned[0] == "":
        cleaned.pop(0)
    while cleaned and cleaned[-1] == "":
        cleaned.pop()
    return cleaned


def normalize_cmd(cmd: str) -> str:
    """
    Normalize command string for matching:
    - strip surrounding quotes
    - collapse multiple spaces
    """
    s = cmd.strip()
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        s = s[1:-1].strip()
    s = re.sub(r"\s+", " ", s)
    return s


def parse_output_log(text: str) -> List[Dict]:
    """
    Return list of dict entries:
      {cmd_no:int, cmd:str, kind:'output'|'error', lines:[...], ts:str}
    """
    lines = text.splitlines(True)  # keep newline chars
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

    parsed: List[Dict] = []
    for b in blocks:
        raw = [x.rstrip("\n") for x in b]

        cmd_line_idx: Optional[int] = None
        marker_idx: Optional[int] = None
        kind: Optional[str] = None

        for i, ln in enumerate(raw):
            if cmd_line_idx is None and CMD_RE.match(ln.strip()):
                cmd_line_idx = i
            if OUT_MARK_RE.match(ln.strip()):
                marker_idx = i
                kind = "output"
                break
            if ERR_MARK_RE.match(ln.strip()):
                marker_idx = i
                kind = "error"
                break

        if cmd_line_idx is None:
            continue

        m = CMD_RE.match(raw[cmd_line_idx].strip())
        ts = m.group(1)
        cmd_no = int(m.group(2))
        cmd = normalize_cmd(m.group(3))

        body_lines: List[str] = []
        if marker_idx is not None:
            body_lines = raw[marker_idx + 1 :]
        else:
            # no marker => treat as empty output
            kind = "output"
            body_lines = []

        parsed.append(
            {
                "ts": ts,
                "cmd_no": cmd_no,
                "cmd": cmd,
                "kind": kind,
                "lines": normalize_lines(body_lines),
            }
        )

    return parsed


def load_request_commands(path: Path) -> List[str]:
    cmds: List[str] = []
    for ln in path.read_text(encoding="utf-8", errors="replace").splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        cmds.append(normalize_cmd(s))
    return cmds


def compare_lines(a: List[str], b: List[str], mode: str) -> bool:
    if mode == "strict":
        return a == b
    return sorted(a) == sorted(b)


def safe_name(name: str) -> str:
    name = name.strip().replace(" ", "_")
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name)
    return name.strip("_") or "checklog"


def find_attack_commands_dir(start_dir: Path) -> Optional[Path]:
    """Walk upwards to find attack_commands/ folder."""
    cur = start_dir.resolve()
    for _ in range(30):
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
    ap.add_argument("--baseline-cmd", type=int, default=1, help="CMD number to use as baseline (default: 1)")
    ap.add_argument("--mode", choices=["sorted", "strict"], default="sorted",
                    help="Compare lines as sorted (default) or strict")
    ap.add_argument("--out", default=None,
                    help="Optional output file path (override default attack_commands/<RuleFolder>_checklog.txt)")
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
        raise SystemExit("[!] No CMD blocks parsed from output log. Check your output file format.")

    baseline = next((e for e in log_entries if e["cmd_no"] == args.baseline_cmd), None)
    if baseline is None:
        raise SystemExit(f"[!] Baseline CMD {args.baseline_cmd} not found in output log.")

    baseline_kind = baseline["kind"]     # output/error
    baseline_lines = baseline["lines"]

    # command -> (kind, lines) from log (keep first occurrence)
    cmd_map: Dict[str, Tuple[str, List[str]]] = {}
    for e in log_entries:
        cmd_map.setdefault(e["cmd"], (e["kind"], e["lines"]))

    matched: List[str] = []
    missing_in_log = 0
    for cmd in request_cmds:
        if cmd not in cmd_map:
            missing_in_log += 1
            continue
        kind, lines = cmd_map[cmd]
        if kind == baseline_kind and compare_lines(lines, baseline_lines, args.mode):
            matched.append(cmd)

    # Output destination
    rule_folder = req_path.parent.name  # folder containing request.txt
    if args.out:
        dest = Path(args.out).resolve()
        dest.parent.mkdir(parents=True, exist_ok=True)
    else:
        attack_dir = find_attack_commands_dir(req_path.parent)
        out_name = f"{safe_name(rule_folder)}_checklog.txt"
        if attack_dir:
            dest = (attack_dir / out_name).resolve()
            dest.parent.mkdir(parents=True, exist_ok=True)
        else:
            dest = (req_path.parent / out_name).resolve()

    dest.write_text("\n".join(matched) + ("\n" if matched else ""), encoding="utf-8")

    print("=== MATCH CHECKLOG ===")
    print(f"Rule folder      : {rule_folder}")
    print(f"Request commands : {len(request_cmds)}")
    print(f"Parsed CMD blocks: {len(log_entries)}")
    print(f"Baseline CMD     : {args.baseline_cmd} ({baseline_kind}, lines={len(baseline_lines)})")
    print(f"Compare mode     : {args.mode}")
    print(f"Matched          : {len(matched)}")
    print(f"Missing in log   : {missing_in_log}")
    print(f"Output written   : {dest}")


if __name__ == "__main__":
    main()
