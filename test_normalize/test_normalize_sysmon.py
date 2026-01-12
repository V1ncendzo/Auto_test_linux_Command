#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test-normalize Sysmon-for-Linux 'match events' into an ECS-ish JSON

Input (Linux): a JSON file like result_Linux_*.json that contains a list of rule objects,
              each with a 'matches' list (rows) from Sysmon.
Input (Windows): a single ECS-like Sysmon event JSON (optional reference), used for field sanity checks.

Outputs are written into the SAME folder as this script (test_normalize/).

Usage examples:
  # 1) Preview all Linux EventID=1 matches (show short summary)
  python3 test_normalize/test_normalize_sysmon.py --mode preview

  # 2) Preview only commands containing a substring (test từng lệnh)
  python3 test_normalize/test_normalize_sysmon.py --mode preview --contains "base64 -d"

  # 3) Dump one normalized event by global index
  python3 test_normalize/test_normalize_sysmon.py --mode dump --idx 0

  # 4) Batch normalize all EventID=1 matches to JSONL
  python3 test_normalize/test_normalize_sysmon.py --mode batch

  # 5) Batch normalize only events containing substring
  python3 test_normalize/test_normalize_sysmon.py --mode batch --contains "journalctl"

  # 6) Compare Linux normalized event keys against Windows sample
  python3 test_normalize/test_normalize_sysmon.py --mode compare --idx 0
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


HERE = Path(__file__).resolve().parent
DEFAULT_LINUX = HERE / "linux_matches_rules.json"
DEFAULT_WINDOWS = HERE / "windows_sysmon_event.json"


def _safe_int(v: Any) -> Any:
    if v is None:
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str) and v.isdigit():
        try:
            return int(v)
        except Exception:
            return v
    return v


def _basename(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    # handle both Windows and Linux separators
    p = path.replace('\\', '/')
    return p.split('/')[-1] if '/' in p else p


def _parse_sha256(match: Dict[str, Any]) -> Optional[str]:
    # Prefer explicit SHA256 field, else parse from Hashes like "SHA256=..."
    sha = match.get("SHA256")
    if isinstance(sha, str) and sha.strip():
        return sha.strip().lower()

    hashes = match.get("Hashes")
    if not isinstance(hashes, str) or not hashes:
        return None

    # Accept comma-separated or single
    for part in hashes.split(','):
        part = part.strip()
        if part.upper().startswith("SHA256="):
            return part.split("=", 1)[1].strip().lower()
    return None


def load_linux_rules(path: Path) -> List[Dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("Linux input must be a JSON list of rule objects")
    return data


def iter_linux_matches(rules: List[Dict[str, Any]]) -> Iterable[Tuple[Dict[str, Any], Dict[str, Any]]]:
    """Yield (rule_obj, match_row)."""
    for rule in rules:
        matches = rule.get("matches")
        if not isinstance(matches, list):
            continue
        for m in matches:
            if isinstance(m, dict):
                yield rule, m


def normalize_linux_match(rule: Dict[str, Any], m: Dict[str, Any]) -> Dict[str, Any]:
    """Map the Linux match-row to an ECS-ish event similar to the Windows sample."""

    # Timestamps: prefer SystemTime (already ISOZ). Fall back to UtcTime if present.
    ts = m.get("SystemTime")
    if not ts:
        # UtcTime in your data looks like 'YYYY-MM-DD HH:MM:SS.mmm'
        # we keep as-is if no SystemTime.
        ts = m.get("UtcTime")

    provider = m.get("Provider_Name") or "Linux-Sysmon"

    # NOTE: Your Linux export does not include the created process id field "ProcessId" (EventData).
    # It includes "ProcessID" from the System section (often Sysmon service PID).
    # We'll use ProcessId if present, else fall back to ProcessID.
    created_pid = m.get("ProcessId")
    if created_pid is None:
        created_pid = m.get("ProcessID")

    proc_exe = m.get("Image")
    cmd = m.get("CommandLine")

    parent_pid = m.get("ParentProcessId")

    sha256 = _parse_sha256(m)

    out: Dict[str, Any] = {
        "@timestamp": ts,
        "message": "Process Create (Sysmon for Linux)",
        "event": {
            "code": _safe_int(m.get("EventID")),
            "provider": provider,
            "category": ["process"],
            "type": ["start", "process_start"],
            "action": "Process Create",
        },
        "host": {
            "hostname": m.get("Computer"),
        } if m.get("Computer") else {},
        "user": {
            "name": m.get("User"),
        } if m.get("User") else {},
        "process": {
            "pid": _safe_int(created_pid),
            "entity_id": m.get("ProcessGuid"),
            "executable": proc_exe,
            "name": _basename(proc_exe),
            "command_line": cmd,
            "working_directory": m.get("CurrentDirectory"),
            "hash": {"sha256": sha256} if sha256 else {},
            "parent": {
                "pid": _safe_int(parent_pid),
                "entity_id": m.get("ParentProcessGuid"),
                "executable": m.get("ParentImage"),
                "name": _basename(m.get("ParentImage")),
                "command_line": m.get("ParentCommandLine"),
            },
        },
        # Keep some provenance
        "labels": {
            "sigma_rule_title": rule.get("title"),
            "sigma_rule_id": rule.get("id"),
            "match_row_id": m.get("row_id"),
        },
        # Keep raw for troubleshooting
        "sysmon": {
            "linux_match": m,
        },
    }

    # Remove empty dicts for cleaner output
    if out.get("host") == {}:
        out.pop("host", None)
    if out.get("user") == {}:
        out.pop("user", None)
    if out["process"].get("hash") == {}:
        out["process"].pop("hash", None)

    return out


def preview(rules: List[Dict[str, Any]], contains: Optional[str], limit: int) -> List[Tuple[Dict[str, Any], Dict[str, Any]]]:
    """Print short summary and return list of (rule, match) in the shown order."""
    shown: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
    for rule, m in iter_linux_matches(rules):
        if str(m.get("EventID")) != "1":
            continue
        cmd = m.get("CommandLine") or ""
        if contains and contains not in cmd:
            continue

        ts = m.get("SystemTime") or m.get("UtcTime")
        img = m.get("Image")
        title = rule.get("title")
        row_id = m.get("row_id")
        print(f"[{len(shown)}] row_id={row_id} | {ts} | {img} | {cmd[:120]}" + ("…" if len(cmd) > 120 else ""))
        print(f"      rule: {title}")
        shown.append((rule, m))
        if len(shown) >= limit:
            break

    if not shown:
        print("Không có match EventID=1 phù hợp điều kiện lọc.")
    return shown


def dump_one(rules: List[Dict[str, Any]], idx: int, contains: Optional[str]) -> Dict[str, Any]:
    # Build a deterministic list (all or filtered) then index into it
    pool: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
    for rule, m in iter_linux_matches(rules):
        if str(m.get("EventID")) != "1":
            continue
        cmd = m.get("CommandLine") or ""
        if contains and contains not in cmd:
            continue
        pool.append((rule, m))

    if not pool:
        raise SystemExit("Không có event nào để dump (EventID=1).")
    if idx < 0 or idx >= len(pool):
        raise SystemExit(f"idx={idx} ngoài phạm vi 0..{len(pool)-1}")

    rule, m = pool[idx]
    return normalize_linux_match(rule, m)


def batch(rules: List[Dict[str, Any]], contains: Optional[str], out_jsonl: Path) -> int:
    n = 0
    with out_jsonl.open("w", encoding="utf-8") as f:
        for rule, m in iter_linux_matches(rules):
            if str(m.get("EventID")) != "1":
                continue
            cmd = m.get("CommandLine") or ""
            if contains and contains not in cmd:
                continue
            ev = normalize_linux_match(rule, m)
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")
            n += 1
    return n


def flatten_keys(obj: Any, prefix: str = "") -> List[str]:
    keys: List[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{prefix}.{k}" if prefix else str(k)
            keys.append(p)
            keys.extend(flatten_keys(v, p))
    elif isinstance(obj, list):
        # Don't explode list indices; just mark list container
        return keys
    return keys


def compare_with_windows(windows_path: Path, linux_event: Dict[str, Any]) -> Dict[str, Any]:
    win = json.loads(windows_path.read_text(encoding="utf-8"))
    win_keys = set(flatten_keys(win))
    lin_keys = set(flatten_keys(linux_event))

    # Focus on the most important ECS-ish keys for process_creation
    important = [
        "@timestamp",
        "event.code",
        "event.provider",
        "host.hostname",
        "user.name",
        "process.executable",
        "process.command_line",
        "process.pid",
        "process.parent.executable",
        "process.parent.command_line",
        "process.hash.sha256",
    ]

    status = {
        "linux_has": {k: (k in lin_keys) for k in important},
        "windows_has": {k: (k in win_keys) for k in important},
        "linux_extra_top": sorted([k for k in lin_keys - win_keys if k.count(".") <= 2])[:50],
        "linux_missing_from_windows_top": sorted([k for k in win_keys - lin_keys if k.count(".") <= 2])[:50],
    }
    return status


def main() -> None:
    ap = argparse.ArgumentParser(description="Preview / Dump / Batch normalize Linux Sysmon matches into ECS-ish JSON")
    ap.add_argument("--linux", default=str(DEFAULT_LINUX), help="Linux matches JSON (default: test_normalize/linux_matches_rules.json)")
    ap.add_argument("--windows", default=str(DEFAULT_WINDOWS), help="Windows reference ECS JSON (default: test_normalize/windows_sysmon_event.json)")
    ap.add_argument("--mode", choices=["preview", "dump", "batch", "compare"], required=True)
    ap.add_argument("--contains", default=None, help="Filter substring in CommandLine (test từng lệnh)")
    ap.add_argument("--limit", type=int, default=30, help="Preview limit")
    ap.add_argument("--idx", type=int, default=0, help="Index for dump/compare (after filtering)")

    args = ap.parse_args()

    linux_path = Path(args.linux)
    if not linux_path.is_absolute():
        linux_path = (HERE / linux_path).resolve() if (HERE / linux_path).exists() else linux_path.resolve()
    if not linux_path.exists():
        raise SystemExit(f"Không thấy Linux file: {linux_path}")

    rules = load_linux_rules(linux_path)

    if args.mode == "preview":
        preview(rules, args.contains, args.limit)
        return

    if args.mode in ("dump", "compare"):
        ev = dump_one(rules, args.idx, args.contains)
        out_dump = HERE / "out_one_normalized.json"
        out_dump.write_text(json.dumps(ev, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[+] Wrote: {out_dump}")

        if args.mode == "compare":
            win_path = Path(args.windows)
            if not win_path.is_absolute():
                win_path = (HERE / win_path).resolve() if (HERE / win_path).exists() else win_path.resolve()
            if not win_path.exists():
                raise SystemExit(f"Không thấy Windows file: {win_path}")
            rep = compare_with_windows(win_path, ev)
            out_rep = HERE / "out_compare_report.json"
            out_rep.write_text(json.dumps(rep, ensure_ascii=False, indent=2), encoding="utf-8")
            print(f"[+] Wrote: {out_rep}")
        return

    if args.mode == "batch":
        out_jsonl = HERE / "out_linux_normalized.jsonl"
        n = batch(rules, args.contains, out_jsonl)
        print(f"[+] Wrote {n} events to: {out_jsonl}")
        return


if __name__ == "__main__":
    main()
