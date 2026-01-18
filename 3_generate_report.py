import csv
import json
import os
import sys
import re

# --- CẤU HÌNH ---
ATTACK_DIR = "attack_commands"
LOG_BASE_DIR = "logs_output"
RESULT_BASE_DIR = "detection_results"

def get_rule_selection():
    if not os.path.exists(RESULT_BASE_DIR):
        print("Chưa có kết quả detect nào.")
        sys.exit(1)
        
    rules = [f for f in os.listdir(RESULT_BASE_DIR) if os.path.isdir(os.path.join(RESULT_BASE_DIR, f))]
    rules.sort()
    
    if not rules:
        print("Không tìm thấy kết quả nào.")
        sys.exit(1)

    print("\n--- CHỌN RULE ĐỂ XUẤT BÁO CÁO ---")
    for idx, r in enumerate(rules):
        print(f"[{idx+1}] {r}")
        
    while True:
        try:
            choice = int(input("\nChọn số thứ tự (VD: 1): "))
            if 1 <= choice <= len(rules):
                return rules[choice-1]
        except ValueError: pass

def normalize_text(text):
    if not text: return ""
    return text.lower().replace("_", " ").replace("-", " ").strip()

def generate_report(rule_name):
    # 1. Tên sạch (bỏ _checklog) để tìm file txt
    rule_name_clean = rule_name.replace("_checklog", "") 
    
    # 2. Đường dẫn thư mục kết quả
    rule_result_dir = os.path.join(RESULT_BASE_DIR, rule_name)
    report_file = f"Report_{rule_name}.csv"
    
    # 3. Đọc file lệnh gốc (Optional - chỉ để lấy Command Text)
    # Không dùng để loop chính.
    command_map = {}
    command_file = os.path.join(ATTACK_DIR, rule_name_clean + ".txt")
    if os.path.exists(command_file):
        with open(command_file, 'r', errors='ignore') as f:
            lines = [line.strip() for line in f if line.strip()]
            for idx, cmd in enumerate(lines):
                 command_map[idx+1] = cmd
    else:
        # Try checking specific variations if needed, or ignore
        pass

    # 4. Loop qua các file JSON trong detection_results
    # format: result_{rule_name}_attack{ID}.json
    # or result_{clean_name}_attack{ID}.json
    
    json_files = [f for f in os.listdir(rule_result_dir) if f.endswith(".json") and "result_" in f]
    
    # Extract IDs
    # Regex: .*attack(\d+)\.json
    found_ids = []
    for jf in json_files:
        m = re.search(r"attack(\d+)\.json$", jf)
        if m:
            found_ids.append(int(m.group(1)))
            
    found_ids.sort()
    
    print(f"\n[*] Đang tạo báo cáo: {report_file}")
    print(f"[*] Found {len(found_ids)} detection result files.")
    
    report_data = []
    stats = {
        "total": 0,
        "bypass_all": 0,
        "bypass_target_rule": 0,
        "trigger_target": 0,
        "errors": 0
    }

    target_rule_normalized = normalize_text(rule_name_clean)

    for cmd_id in found_ids:
        stats["total"] += 1
        
        # Determine Filename
        # We need to find the specific json file name again or reconstruct it?
        # Reconstructing might be tricky if rule_name varies.
        # Let's find the file for this ID
        json_filename = ""
        for jf in json_files:
             if f"attack{cmd_id}.json" in jf and jf.endswith(".json"):
                 json_filename = jf
                 break
        
        full_json_path = os.path.join(rule_result_dir, json_filename)
        log_filename = f"{rule_name}_attack{cmd_id}.log"
        
        # Get Command Text
        cmd_content = command_map.get(cmd_id, f"[Command ID {cmd_id}]")
        
        final_result = "Unknown"
        detected_list_str = ""

        try:
            with open(full_json_path, 'r') as jf:
                data = json.load(jf)
                # Handle list or dict
                if isinstance(data, list):
                    titles = [item.get('title') for item in data if isinstance(item, dict) and 'title' in item]
                elif isinstance(data, dict):
                    titles = [data.get('title')] if 'title' in data else []
                else:
                    titles = []
                    
                titles = list(set(titles))
                
                if not titles:
                    final_result = "Bypass All"
                    stats["bypass_all"] += 1
                else:
                    is_target_hit = False
                    hit_rule_name = ""
                    for t in titles:
                        t_norm = normalize_text(t)
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

                detected_list_str = " | ".join(titles) if titles else "None"

        except Exception as e:
            final_result = f"Log Error (JSON Invalid: {e})"
            stats["errors"] += 1
            
        report_data.append({
            "ID": cmd_id,
            "Command": cmd_content,
            "Log File": log_filename,
            "Result": final_result,
            "All Detected Rules": detected_list_str 
        })

    # --- ĐỌC STATS TỪ FILTERED_SUMMARY.TXT HOẶC FILTER_SUMMARY.MD ---
    # Prioritize MD
    # Check logs_output/RuleName/Filter_Summary.md then stuff/RuleName/Filter_Summary.md
    summary_md_path = os.path.join(LOG_BASE_DIR, rule_name, "Filter_Summary.md")
    if not os.path.exists(summary_md_path):
         summary_md_path = os.path.join("stuff", rule_name, "Filter_Summary.md")
    
    summary_txt_path = os.path.join(LOG_BASE_DIR, rule_name, "filtered_summary.txt")
    
    fs_total_kept = 0
    fs_found = False

    if os.path.exists(summary_md_path):
        try:
            with open(summary_md_path, 'r') as f:
                content = f.read()
                m = re.search(r"\*\*Kept\*\*: (\d+)", content)
                if m:
                    fs_total_kept = int(m.group(1))
                    fs_found = True
        except: pass
    elif os.path.exists(summary_txt_path):
        try:
            with open(summary_txt_path, 'r') as f:
                content = f.read()
                m = re.search(r"Filtered \(Kept\): (\d+)", content)
                if m:
                    fs_total_kept = int(m.group(1))
                    fs_found = True
        except: pass

    # REPORTING LOGIC
    # Base = Total JSONs found (This is the Truth from detection_results)
    # We compare this with Filtered Kept if available, but we Report what we found.
    
    final_total_base = stats["total"]
    # If filtered summary exists, we can note discrepancies, but "Total Meaningful Logs" 
    # in the CSV should probably reflect what is IN THE CSV? 
    # Or should it reflect the Filtered/Kept count?
    # User said "base on rule and stats in detection_results".
    # So "Total Meaningful" = stats["total"] (number of result files found).
    
    # If stats["total"] < fs_total_kept, we have missing results.
    
    summary_source = "(Source: Detection Results)"
    
    # Trigger/Bypass from stats
    trig_cnt = stats["trigger_target"]
    byp_cnt = stats["bypass_all"] + stats["bypass_target_rule"]
    
    rate_percent = (byp_cnt / final_total_base * 100) if final_total_base > 0 else 0

    with open(report_file, 'w', newline='', encoding='utf-8') as f:
        fieldnames = ["ID", "Command", "Log File", "Result", "All Detected Rules"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(report_data)

        writer.writerow({})
        writer.writerow({})
        writer.writerow({"ID": "=== SUMMARY REPORT ==="})
        writer.writerow({"ID": f"Calculation Base {summary_source}", "Command": ""})
        writer.writerow({"ID": "Total Meaningful Logs (Denominator)", "Command": final_total_base})
        writer.writerow({"ID": "Triggered Target (Detections)", "Command": trig_cnt})
        writer.writerow({"ID": "Bypass Logs (Numerator)", "Command": byp_cnt})
        
        summary_bypass = f"{byp_cnt} / {final_total_base} ({rate_percent:.2f}%)"
        writer.writerow({"ID": "BYPASS RATE (Bypass/Meaningful)", "Command": summary_bypass})
        
        if fs_found and fs_total_kept != final_total_base:
             writer.writerow({})
             writer.writerow({"ID": "Note: Discrepancy with Filter Summary", "Command": f"Filter kept {fs_total_kept}, but found {final_total_base} results."})

    print(f"[SUCCESS] {report_file}")
    print(f" [+] Total: {final_total_base} | Trigger: {trig_cnt} | Bypass: {byp_cnt} | Rate: {rate_percent:.2f}%")


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "all":
        if not os.path.exists(RESULT_BASE_DIR):
            print("Chưa có kết quả detect nào.")
            sys.exit(1)
        rules = sorted([f for f in os.listdir(RESULT_BASE_DIR) if os.path.isdir(os.path.join(RESULT_BASE_DIR, f))])
        print(f"Found {len(rules)} rules. Generating reports for ALL...")
        for r in rules:
            generate_report(r)
    else:
        rule_name = get_rule_selection() 
        generate_report(rule_name)

if __name__ == "__main__":
    main()