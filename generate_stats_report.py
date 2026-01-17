import os
import glob
from pathlib import Path

BASE_DIR = Path("linux_data/sigma/events/linux/process_creation")
REPORT_FILE = "/home/vincenzolog/.gemini/antigravity/brain/86b85456-2c0e-4f13-ad08-615139748d75/linux_data_report.md"

def main():
    if not BASE_DIR.exists():
        print(f"Error: {BASE_DIR} not found.")
        return

    stats = []
    
    # Get all subdirectories
    dirs = sorted([d for d in BASE_DIR.iterdir() if d.is_dir()])
    
    total_rules = 0
    total_events = 0
    
    for d in dirs:
        json_files = list(d.glob("*.json"))
        count = len(json_files)
        if count > 0:
            stats.append((d.name, count))
            total_rules += 1
            total_events += count

    # Generate Markdown
    md_lines = []
    md_lines.append(f"# Linux Data Statistics Report")
    md_lines.append(f"")
    md_lines.append(f"**Date**: 2026-01-17")
    md_lines.append(f"")
    md_lines.append(f"## Summary")
    md_lines.append(f"- **Total Active Rules (with events)**: {total_rules}")
    md_lines.append(f"- **Total Event Files**: {total_events}")
    md_lines.append(f"")
    md_lines.append(f"## Detailed Breakdown")
    md_lines.append(f"| Rule Name | Event Count |")
    md_lines.append(f"|---|---|")
    
    for name, count in stats:
        md_lines.append(f"| `{name}` | {count} |")
        
    with open(REPORT_FILE, "w") as f:
        f.write("\n".join(md_lines))
        
    print(f"Report generated at {REPORT_FILE}")
    print(f"Total: {total_events} events across {total_rules} rules.")

if __name__ == "__main__":
    main()
