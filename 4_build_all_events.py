#!/usr/bin/env python3
import os
import sys
import subprocess
import re
import glob

# Configuration
LINUX_DATA_BASE = "linux_data/sigma/events/linux/process_creation"
SIGMA_HQ_BASE = "process_creation_sigmahq"
LOGS_OUTPUT_BASE = "logs_output"
REPORT_BASE = "." # Current directory for reports

def get_sigma_info(yaml_path):
    """
    Parses a simple Sigma YAML to extract title and id.
    Assumes 'title:' and 'id:' are on their own lines.
    """
    title = None
    rule_id = None
    try:
        with open(yaml_path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.startswith("title:"):
                    title = line.split(":", 1)[1].strip()
                elif line.startswith("id:"):
                    rule_id = line.split(":", 1)[1].strip()
                if title and rule_id:
                    break
    except Exception as e:
        print(f"[WARN] Error reading {yaml_path}: {e}")
    return title, rule_id

def normalize_name(name):
    """
    Normalize name for matching: remove special chars, lowercase.
    """
    # Remove ' - Linux' suffix common in titles
    name = re.sub(r' - Linux$', '', name, flags=re.IGNORECASE)
    # Replace spaces with underscores
    name = name.replace(" ", "_")
    # Remove non-alphanumeric (except underscore)
    name = re.sub(r'[^a-zA-Z0-9_]', '', name)
    return name.lower()

def find_log_dir_by_title(title):
    """
    Tries to find a matching directory in LOGS_OUTPUT_BASE based on the rule title.
    """
    if not title:
        return None
    
    norm_title = normalize_name(title)
    
    # Check strict match first (normalized)
    if os.path.exists(LOGS_OUTPUT_BASE):
        for d in os.listdir(LOGS_OUTPUT_BASE):
            if not os.path.isdir(os.path.join(LOGS_OUTPUT_BASE, d)):
                continue
            
            # Special case for known typo
            if norm_title == "shell_execution_via_flock" and d == "Shel_Execution_via_Flock":
                return d
            
            norm_d = normalize_name(d)
            if norm_d == norm_title:
                return d
            
            # Try fuzzy: if title is in directory name (e.g. "BPFtrace Unsafe Option" vs "BPFtrace_Unsafe_Option_Usage")
            # Or directory name in title
            if norm_d in norm_title or norm_title in norm_d:
                # Be careful with short matches, but length check might help
                if len(norm_d) > 10 and len(norm_title) > 10:
                     # prioritizing exact match, but this is a fallback candidate? 
                     # For now let's return it and see.
                     pass
                     
    return None

def main():
    if not os.path.exists(LINUX_DATA_BASE):
        print(f"[ERROR] Target base {LINUX_DATA_BASE} not found.")
        sys.exit(1)

    targets = sorted([d for d in os.listdir(LINUX_DATA_BASE) if os.path.isdir(os.path.join(LINUX_DATA_BASE, d))])
    print(f"[*] Found {len(targets)} target rules in {LINUX_DATA_BASE}")

    for target_dir in targets:
        # 1. Map to Sigma Source
        # Naming convention: proc_creation_lnx_<target_dir>.yml
        sigma_filename = f"proc_creation_lnx_{target_dir}.yml"
        sigma_path = os.path.join(SIGMA_HQ_BASE, sigma_filename)
        
        if not os.path.exists(sigma_path):
            print(f"[SKIP] {target_dir}: Corresponding Sigma file {sigma_filename} not found.")
            continue
            
        # 2. Extract Info
        title, rule_id = get_sigma_info(sigma_path)
        if not title:
            print(f"[SKIP] {target_dir}: Could not parse title from {sigma_filename}.")
            continue
            
        # 3. Find Log Directory
        log_dir_name = find_log_dir_by_title(title)
        
        # Fallback: Try mapping target_dir itself to log dir (e.g. if title is very different)
        if not log_dir_name:
             # Logic: target_dir="bpftrace_unsafe_option_usage" -> LogDir="BPFtrace_Unsafe_Option_Usage"
             # Fuzzy match again
             pass 

        if not log_dir_name:
            print(f"[SKIP] {target_dir} (Title: {title}): No matching log directory found in {LOGS_OUTPUT_BASE}.")
            continue
            
        log_dir_path = os.path.join(LOGS_OUTPUT_BASE, log_dir_name)
        
        # 4. Find Report
        # Report name convention: Report_<LogDirName>.csv OR Report_<LogDirName>_checklog.csv?
        # Based on ls output from previous turn, it seems to be Report_<LogDirName>.csv 
        # (e.g. Report_BPFtrace_Unsafe_Option_Usage.csv)
        report_file = f"Report_{log_dir_name}.csv"
        # Check if exists
        if not os.path.exists(report_file):
             # Try checklog variant just in case
             report_file_check = f"Report_{log_dir_name}_checklog.csv"
             if os.path.exists(report_file_check):
                 report_file = report_file_check
             else:
                 print(f"[SKIP] {target_dir}: Report file Report_{log_dir_name}.csv not found.")
                 continue

        # Check for evasion/bypasses in the report
        evasion_possible = "no"
        try:
            with open(report_file, 'r', encoding='utf-8') as f:
                content = f.read()
                # Simple check for 'Bypass' string or parsing CSV
                if "bypass" in content.lower():
                     # More robust check: count bypass rows?
                     # For now, if "Bypass" appears in Result column likely yes.
                     # The script build_amides... does detailed parsing, but we need flag for properties.
                     # Let's simple check: if "Bypass" count > 0 in summary lines
                     if re.search(r"Bypass.*[1-9]", content) or "Result,Bypass" in content.replace(" ", ""): 
                         # This is rough. Better:
                         pass
                     
                     # Simple logic: If the file contains "Bypass" more than just in headers
                     if content.lower().count("bypass") > 2: # Header + detailed rows
                         evasion_possible = "yes"
        except Exception:
            pass

        print(f"\n[ABC] Processing {target_dir}...")
        print(f"      Sigma: {title} ({rule_id})")
        print(f"      Logs : {log_dir_name}")
        print(f"      Report: {report_file}")
        print(f"      Evasion Possible: {evasion_possible}")

        # CLEANUP: Remove existing .json and .yml files to prevent duplication
        # root = linux_data/sigma/events/linux/process_creation/<target_dir>
        fix_root = os.path.join(LINUX_DATA_BASE, target_dir)
        if os.path.exists(fix_root):
            for old_f in glob.glob(os.path.join(fix_root, "*.json")):
                os.remove(old_f)
            if os.path.exists(os.path.join(fix_root, "properties.yml")):
                os.remove(os.path.join(fix_root, "properties.yml"))
        
        # 5. Execute build_amides_events_from_report.py
        cmd = [
            "python3", "build_amides_events_from_report.py",
            "--report", report_file,
            "--logs-dir", log_dir_path,
            "--rule-dir-name", target_dir,
            "--rule-title", title,
            "--rule-id", rule_id if rule_id else "",
            "--out-root", "linux_data",
            "--platform", "linux",
            "--evasion-possible", evasion_possible,
            "--edited-fields", "CommandLine,Image,ParentImage"
        ]
        
        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Failed to build events for {target_dir}: {e}")
            continue

        # 6. Execute fix_amides_event_filenames.py
        cmd_fix = [
            "python3", "fix_amides_event_filenames.py",
            "--root", fix_root
        ]
        try:
            subprocess.run(cmd_fix, check=True)
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Failed to fix filenames for {target_dir}: {e}")

if __name__ == "__main__":
    main()
