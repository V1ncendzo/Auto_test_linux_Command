import csv
import json
import os
import sys
import re
import difflib

# --- CONFIGURATION ---
ATTACK_DIR = "attack_commands"
LOG_BASE_DIR = "logs_output"
RESULT_BASE_DIR = "fixed_rule_detection_results"
FIXED_RULES_DIR = "fixed_rule_process_creation"
REPORT_OUTPUT_DIR = "report_fixed_rule"

def normalize_text(text):
    if not text: return ""
    # Remove special chars for comparison
    return text.lower().replace("_", "").replace("-", "").replace(" ", "").strip()

def normalize_text_loose(text):
    # Keep spaces for logic inside report (titles)
    return text.lower().replace("_", " ").replace("-", " ").strip()

def get_fixed_rule_info():
    """
    Scans FIXED_RULES_DIR for rules.
    Returns a list of dicts: {'name': dir_name, 'title': title, 'yaml_path': path}
    """
    rules = []
    
    # Iterate over directories in FIXED_RULES_DIR
    if not os.path.exists(FIXED_RULES_DIR):
        print(f"[ERROR] Fixed rules directory not found: {FIXED_RULES_DIR}")
        return rules

    for entry in os.listdir(FIXED_RULES_DIR):
        full_path = os.path.join(FIXED_RULES_DIR, entry)
        if os.path.isdir(full_path) and entry != "all":
            # Look for fixed_*.yml
            found_yaml = None
            for f in os.listdir(full_path):
                if f.startswith("fixed_") and f.endswith(".yml"):
                    found_yaml = os.path.join(full_path, f)
                    break
            
            if found_yaml:
                try:
                    title = None
                    with open(found_yaml, 'r', encoding='utf-8') as f:
                        for line in f:
                            if line.strip().startswith("title:"):
                                title = line.strip().split(":", 1)[1].strip().strip('"').strip("'")
                                break
                    if title:
                        rules.append({
                            'name': entry,
                            'title': title,
                            'yaml_path': found_yaml
                        })
                    else:
                        print(f"[WARN] No title found in {found_yaml}")
                except Exception as e:
                    print(f"[ERROR] Reading {found_yaml}: {e}")
    
    return rules

def find_matching_path(base_dir, target_name, is_file=False):
    """
    Finds a file/folder in base_dir that matches target_name (normalized).
    Returns (full_path, original_name) or (None, None).
    """
    if not os.path.exists(base_dir):
        return None, None
        
    target_norm = normalize_text(target_name)
    candidates = os.listdir(base_dir)
    
    # 1. Exact or Normalized Match
    for c in candidates:
        if is_file:
            # removing extension for comparison
            c_name = os.path.splitext(c)[0]
        else:
            c_name = c
            
        if normalize_text(c_name) == target_norm:
            return os.path.join(base_dir, c), c

    # 2. Fuzzy Match (Useful for Typos like Shel vs Shell)
    # Map normalized back to original
    cand_map = {}
    for c in candidates:
        if is_file:
            c_name = os.path.splitext(c)[0]
        else:
            c_name = c
        cand_map[normalize_text(c_name)] = c
    
    matches = difflib.get_close_matches(target_norm, cand_map.keys(), n=1, cutoff=0.8)
    if matches:
        match_orig = cand_map[matches[0]]
        print(f"[INFO] Fuzzy match: '{target_name}' -> '{match_orig}'")
        return os.path.join(base_dir, match_orig), match_orig
        
    return None, None

def generate_report(rule_info):
    rule_name = rule_info['name']
    rule_title = rule_info['title']
    
    print(f"\n--- Processing {rule_name} ---")
    print(f"[*] Target Title: {rule_title}")
    
    # 1. Find Detection Result Directory
    res_path, res_dirname = find_matching_path(RESULT_BASE_DIR, rule_name, is_file=False)
    if not res_path:
        print(f"[WARN] No detection results found for rule '{rule_name}' (Checked {RESULT_BASE_DIR})")
        return # Skip

    # 2. Find Attack Commands File
    cmd_path, cmd_filename = find_matching_path(ATTACK_DIR, rule_name, is_file=True)
    command_map = {}
    if cmd_path:
        print(f"[*] Using command file: {cmd_filename}")
        try:
            with open(cmd_path, 'r', errors='ignore') as f:
                 lines = [line.strip() for line in f if line.strip()]
                 for idx, cmd in enumerate(lines):
                      command_map[idx+1] = cmd
        except: pass
    else:
        print(f"[WARN] No command file found matching '{rule_name}'.")

    # 3. Process Results
    json_files = [f for f in os.listdir(res_path) if f.endswith(".json") and "result_" in f]
    found_ids = []
    for jf in json_files:
        m = re.search(r"attack(\d+)\.json$", jf)
        if m:
            found_ids.append(int(m.group(1)))
    found_ids.sort()
    
    print(f"[*] Found {len(found_ids)} result files in {res_dirname}.")

    report_data = []
    stats = {
        "total": 0,
        "bypass_all": 0,
        "bypass_target_rule": 0,
        "trigger_target": 0,
        "errors": 0
    }
    
    target_rule_normalized = normalize_text_loose(rule_title)

    for cmd_id in found_ids:
        stats["total"] += 1
        
        # Find filename
        json_filename = ""
        for jf in json_files:
             if f"attack{cmd_id}.json" in jf:
                 json_filename = jf
                 break
        
        full_json_path = os.path.join(res_path, json_filename)
        log_filename = f"{res_dirname}_attack{cmd_id}.log"
        
        cmd_content = command_map.get(cmd_id, f"[Command ID {cmd_id}]")
        
        final_result = "Unknown"
        detected_list = []
        
        try:
            with open(full_json_path, 'r') as jf:
                data = json.load(jf)
                titles = []
                if isinstance(data, list):
                    titles = [item.get('title') for item in data if isinstance(item, dict) and 'title' in item]
                elif isinstance(data, dict):
                    titles = [data.get('title')] if 'title' in data else []
                
                detected_list = list(set(titles))
                
                if not detected_list:
                    final_result = "Bypass All"
                    stats["bypass_all"] += 1
                else:
                    is_target_hit = False
                    hit_rule_name = ""
                    for t in detected_list:
                        t_norm = normalize_text_loose(t)
                        if target_rule_normalized in t_norm or t_norm in target_rule_normalized:
                            is_target_hit = True
                            hit_rule_name = t
                            break
                    
                    if is_target_hit:
                        final_result = f"Trigger: {hit_rule_name}"
                        stats["trigger_target"] += 1
                    else:
                        final_result = "Bypass Target Rule"
                        stats["bypass_target_rule"] += 1
                        
        except Exception as e:
            final_result = f"Error: {e}"
            stats["errors"] += 1
            
        report_data.append({
            "ID": cmd_id,
            "Command": cmd_content,
            "Log File": log_filename,
            "Result": final_result,
            "All Detected Rules": " | ".join(detected_list) if detected_list else "None"
        })

    # 4. Get Logs Filter Stats
    # Try finding folder in LOG_BASE_DIR matching rule_name or res_dirname
    # Usually matches res_dirname (detection folder name)
    log_folder_path, _ = find_matching_path(LOG_BASE_DIR, res_dirname, is_file=False)
    fs_total_kept = 0
    fs_found = False
    
    if log_folder_path:
        summary_md = os.path.join(log_folder_path, "Filter_Summary.md")
        summary_txt = os.path.join(log_folder_path, "filtered_summary.txt")
        
        content = ""
        if os.path.exists(summary_md):
            try: content = open(summary_md).read()
            except: pass
        elif os.path.exists(summary_txt):
            try: content = open(summary_txt).read()
            except: pass
            
        if content:
            # Try various patterns
            m = re.search(r"\*\*Kept\*\*: (\d+)", content)
            if not m: m = re.search(r"Filtered \(Kept\): (\d+)", content)
            if m:
                fs_total_kept = int(m.group(1))
                fs_found = True

    # 5. Write Report
    if not os.path.exists(REPORT_OUTPUT_DIR):
        os.makedirs(REPORT_OUTPUT_DIR)
    
    # Use dirname from detection results for filename consistency or rule name?
    # User said "generate report for harden/fixed linux rule".
    # I'll use the Rule Name from Fixed Rule process.
    safe_name = rule_name.replace(" ", "_").replace("-", "_")
    report_file = os.path.join(REPORT_OUTPUT_DIR, f"Report_Fixed_{safe_name}.csv")
    
    final_total_base = stats["total"]
    trig_cnt = stats["trigger_target"]
    byp_cnt = stats["bypass_all"] + stats["bypass_target_rule"]
    rate_percent = (byp_cnt / final_total_base * 100) if final_total_base > 0 else 0

    try:
        with open(report_file, 'w', newline='', encoding='utf-8') as f:
            fieldnames = ["ID", "Command", "Log File", "Result", "All Detected Rules"]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(report_data)

            writer.writerow({})
            writer.writerow({})
            writer.writerow({"ID": "=== SUMMARY REPORT ==="})
            writer.writerow({"ID": f"Target Rule", "Command": rule_title})
            writer.writerow({"ID": "Total Meaningful Logs", "Command": final_total_base})
            writer.writerow({"ID": "Triggered Target", "Command": trig_cnt})
            writer.writerow({"ID": "Bypass Logs", "Command": byp_cnt})
            writer.writerow({"ID": "BYPASS RATE", "Command": f"{byp_cnt} / {final_total_base} ({rate_percent:.2f}%)"})
            
            if fs_found and fs_total_kept != final_total_base:
                 writer.writerow({"ID": "Filter Kept", "Command": fs_total_kept})
        
        print(f"[SUCCESS] Saved: {report_file}")
        
    except Exception as e:
        print(f"[ERROR] Writing report {report_file}: {e}")

def main():
    print("Gathering fixed rules...")
    rules = get_fixed_rule_info()
    print(f"Found {len(rules)} fixed rules in {FIXED_RULES_DIR}.")
    
    for r in rules:
        generate_report(r)

if __name__ == "__main__":
    main()
