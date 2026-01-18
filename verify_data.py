import os
import glob
from pathlib import Path
import re

# Configuration
LINUX_DATA_BASE = "linux_data/sigma/events/linux/process_creation"
SIGMA_HQ_BASE = "process_creation_sigmahq"
LOGS_OUTPUT_BASE = "logs_output"
REPORT_BASE = "."

def get_sigma_title(yaml_path):
    title = None
    try:
        with open(yaml_path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.startswith("title:"):
                    title = line.split(":", 1)[1].strip()
                    break
    except Exception:
        pass
    return title

def normalize_name(name):
    name = re.sub(r' - Linux$', '', name, flags=re.IGNORECASE)
    name = name.replace(" ", "_")
    name = re.sub(r'[^a-zA-Z0-9_]', '', name)
    return name.lower()

def find_log_dir_by_title(title):
    if not title: return None
    norm_title = normalize_name(title)
    if os.path.exists(LOGS_OUTPUT_BASE):
        for d in os.listdir(LOGS_OUTPUT_BASE):
            if not os.path.isdir(os.path.join(LOGS_OUTPUT_BASE, d)): continue
            if norm_title == "shell_execution_via_flock" and d == "Shel_Execution_via_Flock": return d
            
            norm_d = normalize_name(d)
            if norm_d == norm_title: return d
            if len(norm_d) > 10 and len(norm_title) > 10:
                if norm_d in norm_title or norm_title in norm_d: return d
    return None

def main():
    if not os.path.exists(LINUX_DATA_BASE):
        print(f"Error: {LINUX_DATA_BASE} not found.")
        return

    # Results
    matches = []
    mismatches = []
    missing_reports = []
    
    # Iterate over rules in linux_data (The Truth we are testing)
    rules_subdirs = sorted([d for d in os.listdir(LINUX_DATA_BASE) if os.path.isdir(os.path.join(LINUX_DATA_BASE, d))])
    
    print(f"Verifying {len(rules_subdirs)} rules in linux_data...")
    print(f"{'Rule Dir':<40} | {'CSV Count':<10} | {'JSON Count':<10} | {'Status'}")
    print("-" * 80)

    for rule_dir in rules_subdirs:
        # Get JSON count
        rule_path = os.path.join(LINUX_DATA_BASE, rule_dir)
        json_count = len(glob.glob(os.path.join(rule_path, "*.json")))
        
        # If no events, skip or just note it? User wants to verify data match.
        if json_count == 0:
             continue 

        # Find corresponding Report
        sigma_path = os.path.join(SIGMA_HQ_BASE, f"proc_creation_lnx_{rule_dir}.yml")
        if not os.path.exists(sigma_path):
            missing_reports.append((rule_dir, "No Sigma File"))
            continue
            
        title = get_sigma_title(sigma_path)
        log_dir = find_log_dir_by_title(title)
        
        if not log_dir:
            missing_reports.append((rule_dir, f"No Log Dir (Title: {title})"))
            continue
            
        report_file = f"Report_{log_dir}.csv"
        if not os.path.exists(report_file):
            # Try checklog
            if os.path.exists(f"Report_{log_dir}_checklog.csv"):
                 report_file = f"Report_{log_dir}_checklog.csv"
            else:
                missing_reports.append((rule_dir, f"No Report File ({report_file})"))
                continue
                
        # Parse CSV for "Total Meaningful Logs"
        csv_meaningful = 0
        try:
            with open(report_file, 'r', encoding='utf-8') as f:
                content = f.read()
                # Look for: "Total Meaningful Logs (Denominator),334,,,"
                m = re.search(r"Total Meaningful Logs \(Denominator\),(\d+)", content)
                if m:
                    csv_meaningful = int(m.group(1))
                else:
                    # Fallback: Count rows? 4_build_all_events uses row counting but let's rely on summary first.
                    pass
        except Exception as e:
            missing_reports.append((rule_dir, f"Error Reading Report: {e}"))
            continue
            
        # Compare
        status = "MATCH"
        if json_count != csv_meaningful:
            status = "MISMATCH"
            mismatches.append((rule_dir, csv_meaningful, json_count))
        else:
            matches.append(rule_dir)
            
        print(f"{rule_dir:<40} | {csv_meaningful:<10} | {json_count:<10} | {status}")

    print("-" * 80)
    print(f"Summary: {len(matches)} Matches, {len(mismatches)} Mismatches, {len(missing_reports)} Missing/Skipped")
    
    if mismatches:
        print("\nMismatches Details:")
        for r, csv_c, json_c in mismatches:
            print(f"- {r}: CSV says {csv_c}, Found {json_c} JSONs")

if __name__ == "__main__":
    main()
