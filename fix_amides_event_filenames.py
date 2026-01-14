#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fix_amides_event_filenames.py

Rename Sigma event JSON files to AMIDES-compatible naming:
    <prefix>_(Match|Evasion)_<attack_id>_<num>.json

Expected input (your current structure):
    .\sigma\events\linux\process_creation\<rule_folder>\Microsoft-Windows-Sysmon_1_Match_0015.json
    .\sigma\events\linux\process_creation\<rule_folder>\Microsoft-Windows-Sysmon_1_Evasion_0044.json

Output:
    ...\Microsoft-Windows-Sysmon_1_Match_82_0015.json
    ...\Microsoft-Windows-Sysmon_1_Evasion_82_0044.json

- attack_id is read from JSON: labels.attack_id
- If attack_id missing/blank -> uses "0"
- Safe: supports --dry-run and collision handling
"""

from __future__ import annotations
import argparse
import json
import re
from pathlib import Path
from typing import Optional


PAT_NO_ATTACK = re.compile(r"^(?P<prefix>.+)_(?P<typ>Match|Evasion)_(?P<num>\d+)\.json$", re.IGNORECASE)
PAT_WITH_ATTACK = re.compile(r"^(?P<prefix>.+)_(?P<typ>Match|Evasion)_(?P<attack>[^_]+)_(?P<num>\d+)\.json$", re.IGNORECASE)


def read_attack_id(fp: Path) -> str:
    try:
        with fp.open("r", encoding="utf-8") as f:
            d = json.load(f)
    except UnicodeDecodeError:
        # fallback if file is not utf-8
        with fp.open("r", encoding="utf-8", errors="ignore") as f:
            d = json.load(f)

    attack = (((d.get("labels") or {}).get("attack_id")) or "")
    attack = str(attack).strip()
    return attack if attack else "0"


def make_unique_path(dst: Path) -> Path:
    """If dst exists, append suffix _dupN before .json to avoid overwrite."""
    if not dst.exists():
        return dst
    stem = dst.stem
    for i in range(1, 10000):
        cand = dst.with_name(f"{stem}_dup{i}{dst.suffix}")
        if not cand.exists():
            return cand
    raise RuntimeError(f"Too many collisions for: {dst}")


def rename_events(root: Path, dry_run: bool, only: Optional[str]) -> None:
    # only: "match" | "evasion" | None
    renamed = 0
    skipped = 0
    already_ok = 0
    errors = 0

    files = sorted(root.rglob("*.json"))
    for fp in files:
        name = fp.name

        m_ok = PAT_WITH_ATTACK.match(name)
        if m_ok:
            # already in AMIDES-friendly form -> leave it
            already_ok += 1
            continue

        m = PAT_NO_ATTACK.match(name)
        if not m:
            skipped += 1
            continue

        typ = m.group("typ").lower()
        if only and typ != only:
            skipped += 1
            continue

        prefix = m.group("prefix")
        num = m.group("num")

        try:
            attack_id = read_attack_id(fp)
        except Exception as e:
            errors += 1
            print(f"[ERROR] Cannot read attack_id: {fp} -> {e}")
            continue

        new_name = f"{prefix}_{m.group('typ')}_{attack_id}_{num}.json"
        dst = fp.with_name(new_name)
        dst = make_unique_path(dst)

        if dry_run:
            print(f"[DRY] {fp}  ->  {dst}")
        else:
            fp.rename(dst)

        renamed += 1

    print("\n==== SUMMARY ====")
    print(f"Root        : {root}")
    print(f"Total .json  : {len(files)}")
    print(f"Renamed     : {renamed}")
    print(f"Already OK  : {already_ok}")
    print(f"Skipped     : {skipped}")
    print(f"Errors      : {errors}")


def count_regex(root: Path) -> None:
    rxm = re.compile(r"^.+_Match_.+_\d+\.json$", re.IGNORECASE)
    rxe = re.compile(r"^.+_Evasion_.+_\d+\.json$", re.IGNORECASE)
    m = e = 0
    for fp in root.rglob("*.json"):
        b = fp.name
        m += 1 if rxm.match(b) else 0
        e += 1 if rxe.match(b) else 0
    print("\n==== REGEX COUNT (AMIDES expected) ====")
    print(f"Match  : {m}")
    print(f"Evasion: {e}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--root",
        default=r".\sigma\events\linux\process_creation",
        help=r"Root folder, default: .\sigma\events\linux\process_creation",
    )
    ap.add_argument("--dry-run", action="store_true", help="Preview rename only, do not change files")
    ap.add_argument("--only", choices=["match", "evasion"], default=None, help="Only rename Match or Evasion")
    ap.add_argument("--count", action="store_true", help="Count AMIDES regex-matched files after rename/preview")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    if not root.exists():
        raise SystemExit(f"[FATAL] root not found: {root}")

    rename_events(root=root, dry_run=args.dry_run, only=args.only)
    if args.count:
        count_regex(root)


if __name__ == "__main__":
    main()
