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

def main():
    rule_name = get_rule_selection() # Tên thư mục bạn chọn
    
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
    print(f"[*] Đang quét kết quả trong: {rule_result_dir}")
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

    # --- TÍNH TOÁN VÀ GHI FILE ---
    total_bypass = stats["bypass_all"] + stats["bypass_target_rule"]
    total_cmds = stats["total"]
    rate_percent = (total_bypass / total_cmds * 100) if total_cmds > 0 else 0

    with open(report_file, 'w', newline='', encoding='utf-8') as f:
        fieldnames = ["ID", "Command", "Log File", "Result", "All Detected Rules"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(report_data)

        writer.writerow({})
        writer.writerow({})
        writer.writerow({"ID": "=== SUMMARY REPORT ==="})
        writer.writerow({"ID": "Total Commands (File)", "Command": total_cmds})
        writer.writerow({"ID": "Triggered Target", "Command": stats["trigger_target"]})
        
        summary_bypass = f"{total_bypass} / {total_cmds} ({rate_percent:.2f}%)"
        writer.writerow({"ID": "TOTAL BYPASS RATE", "Command": summary_bypass})
        
        writer.writerow({"ID": "  > Bypass All", "Command": stats["bypass_all"]})
        writer.writerow({"ID": "  > Bypass Target Rule", "Command": stats["bypass_target_rule"]})
        
        if stats["missing"] > 0:
             writer.writerow({"ID": "Missing/Not Run", "Command": stats["missing"]})
        if stats["errors"] > 0:
            writer.writerow({"ID": "Errors", "Command": stats["errors"]})

    # --- IN TỔNG KẾT RA MÀN HÌNH ---
    print(f"[SUCCESS] Đã xuất báo cáo tại: {os.path.abspath(report_file)}")
    print("-" * 40)
    print(f" TỔNG KẾT ({rule_name})")
    print("-" * 40)
    print(f" [+] Tổng số lệnh:      {total_cmds}")
    print(f" [+] Số lệnh Bypass:    {total_bypass}")
    print(f" [+] Tỉ lệ Bypass:      {total_bypass}/{total_cmds} ({rate_percent:.2f}%)")
    print("-" * 40)

if __name__ == "__main__":
    main()