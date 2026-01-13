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

# Lấy số attackNNN từ filename (phục vụ map command)
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

# noise filter mặc định (bạn có thể override/tắt)
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
    """
    Normalize nhẹ để so khớp:
    - html unescape
    - bỏ backslash, backtick, quotes
    - gom whitespace
    - lower
    """
    if not s:
        return ""
    s = html.unescape(s).strip()
    s = s.replace("\\", "")
    s = s.replace("`", "")
    s = s.replace('"', "")
    s = s.replace("'", "")
    s = re.sub(r"\s+", " ", s)
    return s.strip().lower()


def normalize_cmdline_keep_quotes(s: str) -> str:
    """
    Normalize để unwrap wrapper tốt hơn (GIỮ quotes), chỉ:
    - html unescape
    - gom whitespace
    - lower
    """
    if not s:
        return ""
    s = html.unescape(s).strip()
    s = re.sub(r"\s+", " ", s)
    return s.strip().lower()


def canonicalize_first_token(cmdn: str) -> str:
    """
    Nếu command line bắt đầu bằng path (/usr/bin/crontab) -> đổi thành basename (crontab)
    """
    if not cmdn:
        return ""
    parts = cmdn.split()
    if not parts:
        return cmdn
    parts[0] = Path(parts[0]).name.lower()
    return " ".join(parts)


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


def unwrap_wrapper_command(img_base: str, raw_cmd: str) -> Optional[Tuple[str, str]]:
    """
    Trả về (inner_image_basename, inner_cmd_normalized) nếu unwrap được.
    Hỗ trợ:
      - sh|bash|dash|zsh -c <cmd>
      - sudo <cmd>
      - env <cmd>
      - su -c <cmd>  (best-effort)
    """
    if not raw_cmd:
        return None

    raw = normalize_cmdline_keep_quotes(raw_cmd)

    # sh|bash|dash|zsh -c <cmd>
    if img_base in {"sh", "bash", "dash", "zsh"}:
        m = re.search(r"\s-c\s+(.+)$", raw)
        if m:
            inner = m.group(1).strip()
            inner_norm = canonicalize_first_token(normalize_cmdline(inner))
            if inner_norm:
                inner_img = Path(inner_norm.split()[0]).name.lower()
                return inner_img, inner_norm

    # su -c <cmd>
    if img_base == "su":
        m = re.search(r"\s-c\s+(.+)$", raw)
        if m:
            inner = m.group(1).strip()
            inner_norm = canonicalize_first_token(normalize_cmdline(inner))
            if inner_norm:
                inner_img = Path(inner_norm.split()[0]).name.lower()
                return inner_img, inner_norm

    # sudo <cmd>  (bỏ sudo và các option kiểu -E/-u... best-effort)
    if img_base == "sudo":
        parts = raw.split()
        if len(parts) >= 2:
            # bỏ "sudo"
            rest = parts[1:]
            # bỏ flags sudo đơn giản
            while rest and rest[0].startswith("-"):
                # nếu gặp "-u user" thì bỏ luôn 2 token
                if rest[0] in {"-u", "-g"} and len(rest) >= 2:
                    rest = rest[2:]
                else:
                    rest = rest[1:]
            inner = " ".join(rest).strip()
            inner_norm = canonicalize_first_token(normalize_cmdline(inner))
            if inner_norm:
                inner_img = Path(inner_norm.split()[0]).name.lower()
                return inner_img, inner_norm

    # env <cmd>  (bỏ env và VAR=... ở đầu)
    if img_base == "env":
        parts = raw.split()
        if len(parts) >= 2:
            rest = parts[1:]
            # bỏ VAR=VALUE ở đầu
            while rest and "=" in rest[0] and not rest[0].startswith("/"):
                rest = rest[1:]
            inner = " ".join(rest).strip()
            inner_norm = canonicalize_first_token(normalize_cmdline(inner))
            if inner_norm:
                inner_img = Path(inner_norm.split()[0]).name.lower()
                return inner_img, inner_norm

    return None


def action_tokens_for_event(
    img: str,
    cmd_raw: str,
    wrappers: Set[str],
    ignore_images: Set[str],
    noise_cmd_re: Optional[re.Pattern],
    keep_images: Set[str],
    unwrap_wrappers: bool,
    cmd_prefix_tokens: int,
) -> Set[str]:
    """
    Sinh token hành vi cho 1 event.
    - Nếu wrapper và unwrap_wrappers=True: dùng inner (image + cmd)
    - Tạo 2 loại token:
        * full:  image|full_cmd
        * prefix: image|first_N_tokens (giúp baseline 'crontab -r' match 'crontab -r --force')
    """
    out: Set[str] = set()
    img_base = basename(img)

    # unwrap wrapper -> inner
    eff_img = img_base
    eff_cmdn = canonicalize_first_token(normalize_cmdline(cmd_raw))

    if unwrap_wrappers and img_base in wrappers and img_base not in keep_images:
        uw = unwrap_wrapper_command(img_base, cmd_raw)
        if uw:
            eff_img, eff_cmdn = uw

    # filter image ignore/wrapper (sau unwrap)
    if eff_img in ignore_images and eff_img not in keep_images:
        return out
    if eff_img in wrappers and eff_img not in keep_images:
        # wrapper mà unwrap fail -> bỏ
        return out

    if noise_cmd_re and noise_cmd_re.search(eff_cmdn):
        return out
    if not eff_cmdn:
        return out

    # full token
    out.add(f"{eff_img}|{eff_cmdn}")

    # prefix token
    if cmd_prefix_tokens and cmd_prefix_tokens > 0:
        parts = eff_cmdn.split()
        prefix = " ".join(parts[:cmd_prefix_tokens]) if parts else eff_cmdn
        out.add(f"{eff_img}|{prefix}")

    return out


def build_action_set(
    events: List[ProcCreate],
    wrappers: Set[str],
    ignore_images: Set[str],
    noise_cmd_re: Optional[re.Pattern],
    keep_images: Set[str],
    unwrap_wrappers: bool,
    cmd_prefix_tokens: int,
) -> Set[str]:
    out: Set[str] = set()
    for e in events:
        out |= action_tokens_for_event(
            img=e.image,
            cmd_raw=e.command_line,
            wrappers=wrappers,
            ignore_images=ignore_images,
            noise_cmd_re=noise_cmd_re,
            keep_images=keep_images,
            unwrap_wrappers=unwrap_wrappers,
            cmd_prefix_tokens=cmd_prefix_tokens,
        )
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
        if logs_path.is_file() and logs_path.parent.parent.name == "logs_output":
            project_root = logs_path.parent.parent.parent
        else:
            project_root = Path(".")
    return project_root / "attack_commands" / f"{rule_name}_checklog.txt"


def main():
    ap = argparse.ArgumentParser(
        description=(
            "Match Sysmon ProcessCreate (EventID=1) behavior of logs against a baseline; "
            "copy matched logs to logs_output/<rule>_checklog; "
            "and write matched commands to attack_commands/<rule>_checklog.txt (optional)."
        )
    )
    ap.add_argument("--baseline-log", required=True)
    ap.add_argument("--logs-dir", required=True, help="Folder containing logs, or a single log file path")
    ap.add_argument("--rule-name", default=None)

    ap.add_argument("--wrappers", default=",".join(sorted(DEFAULT_WRAPPERS)))
    ap.add_argument("--ignore-images", default=",".join(sorted(DEFAULT_IGNORE_IMAGES)))
    ap.add_argument("--keep-images", default="", help="Comma-separated images to FORCE keep (override ignore/wrapper).")

    # PowerShell-friendly:
    # - default: dùng DEFAULT_NOISE_CMD_REGEX
    # - tắt noise: truyền --noise-cmd-regex (không value)  hoặc --noise-cmd-regex "(?!)"
    ap.add_argument("--noise-cmd-regex", nargs="?", const="", default=DEFAULT_NOISE_CMD_REGEX)

    ap.add_argument("--cov-thr", type=float, default=0.90)
    ap.add_argument("--jac-thr", type=float, default=0.50)

    ap.add_argument("--unwrap-wrappers", action="store_true", help="Unwrap sh/bash/dash -c ..., sudo ..., env ... into inner command")
    ap.add_argument("--cmd-prefix-tokens", type=int, default=2, help="Also emit prefix token: first N tokens of commandline (default 2)")

    ap.add_argument("--copy-to-checklog", action="store_true")
    ap.add_argument("--checklog-root", default=None, help="Root that contains logs_output. Default: logs parent folder.")
    ap.add_argument("--verbose", action="store_true")

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

    commands: List[str] = []
    if args.commands_file:
        commands = load_commands(Path(args.commands_file))

    # Baseline
    base_events = iter_proc_create_events_from_file(baseline_log)
    base_action = build_action_set(
        base_events, wrappers, ignore_images, noise_cmd_re, keep_images,
        unwrap_wrappers=args.unwrap_wrappers,
        cmd_prefix_tokens=args.cmd_prefix_tokens,
    )
    if not base_action:
        raise SystemExit(
            "Baseline action-set is empty after filtering.\n"
            "Gợi ý:\n"
            "  - Nếu baseline là journalctl mà bị ignore: dùng --keep-images journalctl\n"
            "  - Nếu baseline bị noise filter: tắt noise bằng --noise-cmd-regex hoặc --noise-cmd-regex '(?!)'\n"
            "  - Nếu baseline nằm trong wrapper '-c': bật --unwrap-wrappers\n"
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
        cand_action = build_action_set(
            evs, wrappers, ignore_images, noise_cmd_re, keep_images,
            unwrap_wrappers=args.unwrap_wrappers,
            cmd_prefix_tokens=args.cmd_prefix_tokens,
        )

        cov = coverage(base_action, cand_action)
        jac = jaccard(base_action, cand_action)
        ok = (cov >= args.cov_thr and jac >= args.jac_thr)

        if ok:
            matched_logs.append(lf)
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

    # Write matched commands file
    out_cmd_path: Optional[Path] = None
    written_cmds = 0
    if commands:
        out_cmd_path = Path(args.out_command_checklog) if args.out_command_checklog else default_out_command_checklog(logs_path, rule_name)
        out_cmd_path.parent.mkdir(parents=True, exist_ok=True)

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
