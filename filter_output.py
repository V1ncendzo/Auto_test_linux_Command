#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations
import argparse
import csv
import json
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple


SEPARATOR = "##################################################"
CMD_LINE_RE = re.compile(r"^\[\d{4}-\d{2}-\d{2} .*?\]\s+CMD\s+(\d+):\s+(.*)$")
OUTPUT_MARK = "-Output:"
ERROR_MARK = "-Error:"


# Output mẫu thành công (dùng khi chạy --strict)
# (Bạn đưa ví dụ: Linux bkcs-virtual-machine ... GNU/Linux) :contentReference[oaicite:2]{index=2}
EXPECTED_STRICT = """Linux bkcs-virtual-machine 5.15.0-139-generic #149~20.04.1-Ubuntu SMP Wed Apr 16 08:29:56 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
"""

# Chế độ "linh hoạt": output phải có dòng Linux ... GNU/Linux
UNAME_OK_RE = re.compile(r"^Linux\s+.*GNU/Linux\s*$")


def normalize_text(s: str) -> str:
    """Chuẩn hóa để so khớp ổn định hơn (bỏ dòng trống, strip phải)."""
    lines = [ln.rstrip() for ln in s.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    lines = [ln for ln in lines if ln.strip() != ""]
    return "\n".join(lines).strip()


@dataclass
class CmdResult:
    cmd_id: Optional[int]
    command: str
    found: bool
    ok: bool
    verdict: str  # OK / WRONG / MISSING
    reason: str
    output: str
    error: str


def parse_success_commands(path: Path) -> List[str]:
    """Mỗi dòng (không rỗng) trong success file là 1 command."""
    cmds: List[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line:
            cmds.append(line)
    return cmds


def split_blocks(text: str) -> List[str]:
    """Tách log theo separator."""
    parts = [p.strip("\n") for p in text.split(SEPARATOR)]
    return [p for p in parts if p.strip()]


def parse_output_log(path: Path) -> Dict[str, Tuple[int, str, str]]:
    """
    Trả về dict: command -> (cmd_id, output_text, error_text)

    output file gồm nhiều block:
      [time] CMD n: <command>
      -Output: ...
      -Error: ...
      ##################################################
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    blocks = split_blocks(text)

    out: Dict[str, Tuple[int, str, str]] = {}

    for blk in blocks:
        lines = blk.splitlines()
        cmd_id: Optional[int] = None
        cmd: Optional[str] = None

        # tìm dòng CMD
        for ln in lines:
            m = CMD_LINE_RE.match(ln.strip())
            if m:
                cmd_id = int(m.group(1))
                cmd = m.group(2).strip()
                break

        if not cmd:
            continue

        full = "\n".join(lines)

        output_txt = ""
        error_txt = ""

        # lấy output
        if OUTPUT_MARK in full:
            output_txt = full.split(OUTPUT_MARK, 1)[1]
            # nếu output phần sau lỡ có chứa -Error: (hiếm), cắt ra
            if ERROR_MARK in output_txt:
                output_txt, tail = output_txt.split(ERROR_MARK, 1)
                error_txt = tail
            output_txt = output_txt.strip("\n")

        # lấy error (ưu tiên phần sau -Error: nếu có)
        if ERROR_MARK in full:
            error_txt = full.split(ERROR_MARK, 1)[1].strip("\n")

        # nếu command xuất hiện nhiều lần, giữ bản ghi cuối cùng
        out[cmd] = (cmd_id if cmd_id is not None else -1, output_txt, error_txt)

    return out


def is_ok(output_txt: str, error_txt: str, strict: bool) -> Tuple[bool, str]:
    """
    Tiêu chí cho Linux Shell Pipe to Shell:
      - Có error => WRONG
      - Output rỗng => WRONG
      - strict:
          output normalize phải đúng y hệt EXPECTED_STRICT
        else:
          output phải có ít nhất 1 dòng match: ^Linux ... GNU/Linux$
    """
    if normalize_text(error_txt) != "":
        return False, "Has error output"

    norm_out = normalize_text(output_txt)
    if norm_out == "":
        return False, "Empty output"

    if strict:
        if norm_out == normalize_text(EXPECTED_STRICT):
            return True, "Strict match"
        return False, "Output != expected (strict)"
    else:
        for ln in norm_out.splitlines():
            if UNAME_OK_RE.match(ln.strip()):
                return True, "Matched uname pattern (Linux ... GNU/Linux)"
        return False, "Missing uname line 'Linux ... GNU/Linux'"


def pick_first(glob_list: List[Path], label: str) -> Path:
    """Chọn file mới nhất theo mtime để tránh nhặt nhầm."""
    if not glob_list:
        raise FileNotFoundError(f"Không tìm thấy file {label} theo pattern mặc định.")
    glob_list.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return glob_list[0]


def resolve_default_paths(rule_dir: Path) -> Tuple[Path, Path]:
    """
    Tự suy ra path theo cấu trúc thư mục:
      <rule_dir>/success/success_requests_*.txt
      <rule_dir>/output/output_requests_*.txt
    Fallback: tìm ngay trong rule_dir nếu không có subfolder.
    """
    success_candidates = list((rule_dir / "success").glob("success_requests_*.txt"))
    output_candidates = list((rule_dir / "output").glob("output_requests_*.txt"))

    if not success_candidates:
        success_candidates = list(rule_dir.glob("success_requests_*.txt"))
    if not output_candidates:
        output_candidates = list(rule_dir.glob("output_requests_*.txt"))

    success_path = pick_first(success_candidates, "success_requests_*.txt")
    output_path = pick_first(output_candidates, "output_requests_*.txt")
    return success_path, output_path


def main():
    rule_dir_default = Path(__file__).resolve().parent

    ap = argparse.ArgumentParser(
        description="Map success commands to output log and judge correctness (+ export final_Sucess.txt)."
    )
    ap.add_argument(
        "--rule-dir",
        default=str(rule_dir_default),
        help="Thư mục rule (mặc định là thư mục chứa filter.py).",
    )
    ap.add_argument("--success", default=None, help="Path file success_requests_*.txt (optional).")
    ap.add_argument("--output", default=None, help="Path file output_requests_*.txt (optional).")
    ap.add_argument("--out-csv", default=None, help="Output CSV path (optional).")
    ap.add_argument("--out-json", default=None, help="Output JSON path (optional).")
    ap.add_argument(
        "--out-final-success",
        default=None,
        help="File chứa các command OK (mỗi dòng 1 command). Default: <out_dir>/final_Sucess.txt",
    )
    ap.add_argument("--strict", action="store_true", help="Strict output comparison")
    args = ap.parse_args()

    rule_dir = Path(args.rule_dir).resolve()

    # chọn input files
    if args.success and args.output:
        success_path = Path(args.success).resolve()
        output_path = Path(args.output).resolve()
    else:
        success_path, output_path = resolve_default_paths(rule_dir)

    # output dir: ưu tiên <rule_dir>/output nếu có
    out_dir = (rule_dir / "output") if (rule_dir / "output").exists() else rule_dir

    out_csv = Path(args.out_csv).resolve() if args.out_csv else (out_dir / "mapped_results.csv")
    out_json = Path(args.out_json).resolve() if args.out_json else (out_dir / "mapped_results.json")
    out_final = (
        Path(args.out_final_success).resolve()
        if args.out_final_success
        else (out_dir / "final_Sucess.txt")
    )

    # parse
    success_cmds = parse_success_commands(success_path)
    output_map = parse_output_log(output_path)

    results: List[CmdResult] = []

    for cmd in success_cmds:
        if cmd not in output_map:
            results.append(
                CmdResult(
                    cmd_id=None,
                    command=cmd,
                    found=False,
                    ok=False,
                    verdict="MISSING",
                    reason="Command not found in output log",
                    output="",
                    error="",
                )
            )
            continue

        cmd_id, out_txt, err_txt = output_map[cmd]
        ok, reason = is_ok(out_txt, err_txt, strict=args.strict)

        results.append(
            CmdResult(
                cmd_id=cmd_id,
                command=cmd,
                found=True,
                ok=ok,
                verdict="OK" if ok else "WRONG",
                reason=reason,
                output=out_txt,
                error=err_txt,
            )
        )

    # write CSV
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["cmd_id", "command", "found", "verdict", "reason", "output", "error"])
        for r in results:
            w.writerow([r.cmd_id, r.command, r.found, r.verdict, r.reason, r.output, r.error])

    # write JSON
    out_json.write_text(
        json.dumps([asdict(r) for r in results], ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    # write final_Sucess.txt: chỉ chứa command OK (đã map + output đúng)
    ok_commands = [r.command for r in results if r.verdict == "OK"]
    out_final.write_text("\n".join(ok_commands) + ("\n" if ok_commands else ""), encoding="utf-8")

    # summary
    total = len(results)
    ok_cnt = sum(1 for r in results if r.verdict == "OK")
    wrong_cnt = sum(1 for r in results if r.verdict == "WRONG")
    miss_cnt = sum(1 for r in results if r.verdict == "MISSING")

    print(f"Using success: {success_path}")
    print(f"Using output : {output_path}")
    print(f"Total: {total} | OK: {ok_cnt} | WRONG: {wrong_cnt} | MISSING: {miss_cnt}")
    print(f"CSV  : {out_csv}")
    print(f"JSON : {out_json}")
    print(f"FINAL: {out_final}")


if __name__ == "__main__":
    main()
