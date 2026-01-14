#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations
import argparse
from pathlib import Path

PROPERTIES_YML = """queried_event_types:
  - Microsoft-Windows-Sysmon_1
evasion_possible: no
broken_rule: no
edited_fields:
"""

def list_rule_names(rules_dir: Path) -> set[str]:
    rule_files = []
    for ext in ("*.yml", "*.yaml"):
        rule_files.extend(rules_dir.glob(ext))
    return {p.stem for p in rule_files if p.is_file()}

def list_event_folder_names(events_dir: Path) -> set[str]:
    if not events_dir.exists():
        return set()
    return {p.name for p in events_dir.iterdir() if p.is_dir()}

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Create missing AMIDES-style event folders for linux/process_creation rules."
    )
    ap.add_argument("--rules-dir", required=True, help="sigma/rules/linux/process_creation")
    ap.add_argument("--events-dir", required=True, help="sigma/events/linux/process_creation")
    ap.add_argument("--force", action="store_true", help="Overwrite properties.yml if exists")
    ap.add_argument("--dry-run", action="store_true", help="Only print actions, do not write")
    args = ap.parse_args()

    rules_dir = Path(args.rules_dir)
    events_dir = Path(args.events_dir)

    if not rules_dir.exists():
        raise SystemExit(f"[!] rules-dir not found: {rules_dir}")

    rule_names = list_rule_names(rules_dir)
    if not rule_names:
        raise SystemExit(f"[!] No .yml/.yaml found in: {rules_dir}")

    existing_event_folders = list_event_folder_names(events_dir)
    missing = sorted(rule_names - existing_event_folders)

    print(f"[i] Rules found: {len(rule_names)}")
    print(f"[i] Event folders existing: {len(existing_event_folders)}")
    print(f"[i] Missing folders to create: {len(missing)}")

    if not missing:
        print("[+] Nothing to do.")
        return

    if not args.dry_run:
        events_dir.mkdir(parents=True, exist_ok=True)

    for name in missing:
        out_dir = events_dir / name
        props_path = out_dir / "properties.yml"

        if args.dry_run:
            print(f"[DRY] mkdir: {out_dir}")
            if props_path.exists() and not args.force:
                print(f"[DRY] skip properties.yml (exists): {props_path}")
            else:
                print(f"[DRY] write properties.yml: {props_path}")
            continue

        out_dir.mkdir(parents=True, exist_ok=True)

        if props_path.exists() and not args.force:
            print(f"[-] Skip (properties exists): {props_path}")
        else:
            props_path.write_text(PROPERTIES_YML, encoding="utf-8")
            print(f"[+] Wrote: {props_path}")

    print("[+] Done.")

if __name__ == "__main__":
    main()
