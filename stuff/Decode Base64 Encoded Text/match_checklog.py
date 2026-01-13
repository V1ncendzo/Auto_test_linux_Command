#!/usr/bin/env python3
# match_checklog.py
#
# CMD-number based matcher.
# NEW: supports "contains" mode to match by required substrings instead of full output equality.
#
# Examples:
#   # strict/full match:
#   py -3 .\match_checklog.py --request .\request.txt --output .\output_xxx.txt --baseline-cmd 32 --match equal --mode strict
#
#   # contains match: only require some tokens exist in output (no need full identical):
#   py -3 .\match_checklog.py --request .\request.txt --output .\output_xxx.txt --baseline-cmd 32 --match contains `
#     --need "/home/bkcs/openssl/Configurations/50-vms-x86_64.conf" `
#     --need "/home/bkcs/openssl/Configurations/50-win-hybridcrt.conf"

import argparse
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

SEP_RE = re.compile(r"^#{10,}\s*$")
LOG_CMD_RE = re.compile(r"^\[(.*?)\]\s*CMD\s+(\d+):\s*(.*)\s*$")
REQ_CMD_RE = re.compile(r"^(?:\[(.*?)\]\s*)?CMD\s+(\d+):\s*(.*)\s*$", re.IGNORECASE)

OUT_MARK_RE = re.compile(r"^\s*-\s*Output:\s*$", re.IGNORECASE)
ERR_MARK_RE = re.compile(r"^\s*-\s*Error:\s*$", re.IGNORECASE)


def normalize_lines(lines: List[str]) -> List[str]:
    cleaned = [ln.rstrip("\r\n").rstrip() for ln in lines]
    while cleaned and cleaned[0] == "":
        cleaned.pop(0)
    while cleaned and cleaned[-1] == "":
        cleaned.pop()
    return cleaned


def normalize_cmd_text(cmd: str) -> str:
    return cmd.strip()


def parse_output_log(text: str) -> Dict[int, Dict]:
    lines = text.splitlines(True)
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

    out: Dict[int, Dict] = {}
    for b in blocks:
        raw = [x.rstrip("\n") for x in b]

        cmd_line_idx: Optional[int] = None
        marker_idx: Optional[int] = None
        kind: Optional[str] = None  # output/error

        for i, ln in enumerate(raw):
            if cmd_line_idx is None and LOG_CMD_RE.match(ln.strip()):
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

        m = LOG_CMD_RE.match(raw[cmd_line_idx].strip())
        ts = m.group(1)
        cmd_no = int(m.group(2))
        cmd = normalize_cmd_text(m.group(3))

        if marker_idx is not None:
            body_lines = raw[marker_idx + 1 :]
        else:
            kind = "output"
            body_lines = []

        out[cmd_no] = {
            "ts": ts,
            "cmd_no": cmd_no,
            "cmd": cmd,
            "kind": kind,
            "lines": normalize_lines(body_lines),
        }

    return out


def parse_request_commands(req_text: str) -> Dict[int, str]:
    cmd_map: Dict[int, str] = {}
    auto_no = 1

    for ln in req_text.splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue

        m = REQ_CMD_RE.match(s)
        if m:
            cmd_no = int(m.group(2))
            cmd = normalize_cmd_text(m.group(3))
            cmd_map[cmd_no] = cmd
        else:
            cmd_map[auto_no] = normalize_cmd_text(s)
            auto_no += 1

    return cmd_map


def compare_equal(a: List[str], b: List[str], mode: str) -> bool:
    if mode == "strict":
        return a == b
    return sorted(a) == sorted(b)


def compare_contains(lines: List[str], needles: List[str], require_all: bool = True) -> bool:
    """
    Return True if output contains required substrings.
    - If require_all=True: all needles must appear somewhere in joined output.
    """
    hay = "\n".join(lines)
    hits = [n for n in needles if n in hay]
    return (len(hits) == len(needles)) if require_all else (len(hits) > 0)


def safe_name(name: str) -> str:
    name = name.strip().replace(" ", "_")
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name)
    return name.strip("_") or "checklog"


def find_attack_commands_dir(start_dir: Path) -> Optional[Path]:
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
    ap.add_argument("--request", required=True, help="Path to request.txt")
    ap.add_argument("--output", required=True, help="Path to output_*.txt")
    ap.add_argument("--baseline-cmd", type=int, default=1, help="CMD number used as baseline")
    ap.add_argument("--mode", choices=["sorted", "strict"], default="strict",
                    help="For --match equal only: strict (default) or sorted")

    # NEW matching strategy
    ap.add_argument("--match", choices=["equal", "contains"], default="equal",
                    help="equal: compare full output; contains: require substrings in output")
    ap.add_argument("--need", action="append", default=[],
                    help="(Use with --match contains) Required substring. Can be repeated.")
    ap.add_argument("--need-from-baseline", action="store_true",
                    help="(Use with --match contains) Auto-use baseline lines as needles (non-empty lines).")
    ap.add_argument("--need-all", action="store_true", default=True,
                    help="(Use with --match contains) Require ALL needles (default).")
    ap.add_argument("--need-any", action="store_true",
                    help="(Use with --match contains) Require ANY needle (OR) instead of ALL.")

    ap.add_argument("--out", default=None, help="Override output path")
    args = ap.parse_args()

    req_path = Path(args.request).resolve()
    out_path = Path(args.output).resolve()

    if not req_path.is_file():
        raise SystemExit(f"[!] request file not found: {req_path}")
    if not out_path.is_file():
        raise SystemExit(f"[!] output file not found: {out_path}")

    req_cmds = parse_request_commands(req_path.read_text(encoding="utf-8", errors="replace"))
    out_cmds = parse_output_log(out_path.read_text(encoding="utf-8", errors="replace"))

    if args.baseline_cmd not in out_cmds:
        raise SystemExit(f"[!] Baseline CMD {args.baseline_cmd} not found in output log.")

    baseline_kind = out_cmds[args.baseline_cmd]["kind"]
    baseline_lines = out_cmds[args.baseline_cmd]["lines"]

    # determine needles for contains-match
    needles: List[str] = []
    if args.match == "contains":
        if args.need_from_baseline:
            needles = [ln for ln in baseline_lines if ln.strip()]
        else:
            needles = list(args.need or [])

        if not needles:
            raise SystemExit("[!] --match contains requires --need ... (repeatable) OR --need-from-baseline")

    require_all = True
    if args.need_any:
        require_all = False
    elif args.need_all:
        require_all = True

    matched: List[str] = []
    missing_output = 0

    for cmd_no in sorted(req_cmds.keys()):
        if cmd_no not in out_cmds:
            missing_output += 1
            continue

        kind = out_cmds[cmd_no]["kind"]
        lines = out_cmds[cmd_no]["lines"]

        if kind != baseline_kind:
            continue

        ok = False
        if args.match == "equal":
            ok = compare_equal(lines, baseline_lines, args.mode)
        else:
            ok = compare_contains(lines, needles, require_all=require_all)

        if ok:
            matched.append(req_cmds[cmd_no])

    rule_folder = req_path.parent.name
    if args.out:
        dest = Path(args.out).resolve()
        dest.parent.mkdir(parents=True, exist_ok=True)
    else:
        out_name = f"{safe_name(rule_folder)}_checklog.txt"
        attack_dir = find_attack_commands_dir(req_path.parent)
        if attack_dir:
            dest = (attack_dir / out_name).resolve()
            dest.parent.mkdir(parents=True, exist_ok=True)
        else:
            dest = (req_path.parent / out_name).resolve()

    dest.write_text("\n".join(matched) + ("\n" if matched else ""), encoding="utf-8")

    print("=== MATCH CHECKLOG (CMD-NUMBER BASED) ===")
    print(f"Rule folder      : {rule_folder}")
    print(f"Request CMDs     : {len(req_cmds)}")
    print(f"Output CMDs      : {len(out_cmds)}")
    print(f"Baseline CMD     : {args.baseline_cmd} ({baseline_kind}, lines={len(baseline_lines)})")
    print(f"Match strategy   : {args.match}")
    if args.match == "contains":
        print(f"Needles          : {len(needles)} ({'ALL' if require_all else 'ANY'})")
    else:
        print(f"Compare mode     : {args.mode}")
    print(f"Matched          : {len(matched)}")
    print(f"Missing output   : {missing_output}")
    print(f"Output written   : {dest}")


if __name__ == "__main__":
    main()
