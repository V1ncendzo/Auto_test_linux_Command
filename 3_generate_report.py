import csv
import json
import os
import sys

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
    # 1. Tên sạch (bỏ _checklog) để tìm file txt và json
    rule_name_clean = rule_name.replace("_checklog", "") 
    
    # 2. Đường dẫn file lệnh gốc
    command_file = os.path.join(ATTACK_DIR, rule_name_clean + ".txt")
    
    # 3. Đường dẫn thư mục kết quả
    rule_result_dir = os.path.join(RESULT_BASE_DIR, rule_name)
    
    report_file = f"Report_{rule_name}.csv"

    # Đọc file lệnh trước để lấy số lượng
    commands = []
    if not os.path.exists(command_file):
        print(f"Cảnh báo: Không tìm thấy file lệnh gốc {command_file}.")
        return 
    else:
        with open(command_file, 'r') as f:
            commands = [line.strip() for line in f if line.strip()]

    # --- IN THÔNG TIN TRẠNG THÁI (NHƯ BẠN YÊU CẦU) ---
    print(f"\n[*] Đang tạo báo cáo: {report_file}")
    print(f"[*] Đang đọc lệnh từ: {rule_name_clean}.txt ({len(commands)} lệnh)")
    # print(f"[*] Đang quét kết quả trong: {rule_result_dir}")
    # -------------------------------------------------
    
    report_data = []
    stats = {
        "total": 0,
        "bypass_all": 0,
        "bypass_target_rule": 0,
        "trigger_target": 0,
        "errors": 0,
        "missing": 0
    }

    target_rule_normalized = normalize_text(rule_name_clean)

    for index, cmd_content in enumerate(commands):
        stats["total"] += 1
        cmd_id = index + 1
        
        # Tìm file JSON bằng tên sạch
        json_filename = f"result_{rule_name_clean}_attack{cmd_id}.json"
        full_json_path = os.path.join(rule_result_dir, json_filename)
        
        log_filename = f"{rule_name}_attack{cmd_id}.log"
        
        final_result = "Unknown"
        detected_list_str = ""

        if os.path.exists(full_json_path):
            try:
                with open(full_json_path, 'r') as jf:
                    data = json.load(jf)
                    if isinstance(data, list):
                        titles = [item.get('title') for item in data if 'title' in item]
                    else:
                        titles = [data.get('title')] if 'title' in data else []
                        
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
                final_result = "Log Error (JSON Invalid)"
                stats["errors"] += 1
        else:
            final_result = "Log Error (Result Not Found)"
            stats["missing"] += 1

        report_data.append({
            "ID": cmd_id,
            "Command": cmd_content,
            "Log File": log_filename,
            "Result": final_result,
            "All Detected Rules": detected_list_str 
        })

    # --- ĐỌC STATS TỪ FILTERED_SUMMARY.TXT (NẾU CÓ) ---
    summary_txt_path = os.path.join(LOG_BASE_DIR, rule_name, "filtered_summary.txt")
    fs_total_kept = 0
    fs_bypass_cnt = 0
    fs_trigger_cnt = 0
    fs_found = False

    if os.path.exists(summary_txt_path):
        try:
            with open(summary_txt_path, 'r') as f:
                content = f.read()
                # Parse Filtered (Kept)
                import re
                m_kept = re.search(r"Filtered \(Kept\): (\d+)", content)
                if m_kept:
                    fs_total_kept = int(m_kept.group(1))
                    
                # Parse Bypass
                m_bypass = re.search(r"Bypass \(Right Meaning.*?\): (\d+)", content)
                if m_bypass:
                    fs_bypass_cnt = int(m_bypass.group(1))
                    
                # Parse Trigger
                m_trigger = re.search(r"Trigger \(Sigma Match\): (\d+)", content)
                if m_trigger:
                    fs_trigger_cnt = int(m_trigger.group(1))

                fs_found = True
        except Exception as e:
            print(f"[WARN] Lỗi đọc filtered_summary.txt: {e}")

    # --- TÍNH TOÁN VÀ GHI FILE ---
    
    # Logic cũ
    old_total_bypass = stats["bypass_all"] + stats["bypass_target_rule"]
    old_total_cmds = stats["total"]
    
    # Logic mới
    if fs_found and fs_total_kept > 0:
        # Fallback Logic: If filtered_summary.txt didn't have explicit breakdown, infer it.
        # We assume 'Total Kept' is accurate.
        # If fs_trigger_cnt is missing (0), use the actual detection trigger count.
        if fs_trigger_cnt == 0:
             fs_trigger_cnt = stats['trigger_target']
        
        # If fs_bypass_cnt is missing (0), calculate it: Kept - Trigger
        if fs_bypass_cnt == 0:
             fs_bypass_cnt = fs_total_kept - fs_trigger_cnt
             # Sanity check: prevent negative bypasses if something is weird
             if fs_bypass_cnt < 0: fs_bypass_cnt = 0

        final_bypass_num = fs_bypass_cnt
        final_total_base = fs_total_kept
        summary_source = "(Source: filtered_summary.txt)"
        rate_percent = (final_bypass_num / final_total_base * 100)
    else:
        final_bypass_num = old_total_bypass
        final_total_base = old_total_cmds
        summary_source = "(Source: All Commands)"
        rate_percent = (final_bypass_num / final_total_base * 100) if final_total_base > 0 else 0

    ratio_val = (final_bypass_num / fs_trigger_cnt) if (fs_found and fs_trigger_cnt > 0) else 0.0

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
        writer.writerow({"ID": "Triggered Target (Detections)", "Command": fs_trigger_cnt if fs_found else stats["trigger_target"]})
        writer.writerow({"ID": "Bypass Logs (Numerator)", "Command": final_bypass_num})
        
        summary_bypass = f"{final_bypass_num} / {final_total_base} ({rate_percent:.2f}%)"
        writer.writerow({"ID": "BYPASS RATE (Bypass/Meaningful)", "Command": summary_bypass})
        
        if fs_found and fs_trigger_cnt > 0:
             writer.writerow({"ID": "BYPASS RAIO (Bypass/Detections)", "Command": f"{ratio_val:.2f}"})
        
        writer.writerow({})
        writer.writerow({"ID": "--- DETAILS (From raw scan) ---"})
        writer.writerow({"ID": "  > Bypass All (Raw)", "Command": stats["bypass_all"]})
        writer.writerow({"ID": "  > Bypass Target Rule (Raw)", "Command": stats["bypass_target_rule"]})
        
        if stats["missing"] > 0:
             writer.writerow({"ID": "Missing/Not Run", "Command": stats["missing"]})
        if stats["errors"] > 0:
             writer.writerow({"ID": "Errors", "Command": stats["errors"]})

    print(f"[SUCCESS] {report_file}")
    print(f" TỔNG KẾT ({rule_name}) {summary_source}")
    print(f" [+] Meaningful: {final_total_base} | Trigger: {fs_trigger_cnt if fs_found else stats['trigger_target']} | Bypass: {final_bypass_num} | Rate: {rate_percent:.2f}%")


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