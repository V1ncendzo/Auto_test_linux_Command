import csv
import json
import os
import sys

# --- CẤU HÌNH ---
ATTACK_DIR = "attack_commands"
LOG_BASE_DIR = "logs_output"
RESULT_BASE_DIR = "detection_results"

def get_rule_selection():
    # Quét folder results để xem đã có kết quả của rule nào
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

def main():
    rule_name = get_rule_selection()
    
    # File input gốc (để lấy nội dung command)
    command_file = os.path.join(ATTACK_DIR, rule_name + ".txt")
    
    # Folder kết quả json
    rule_result_dir = os.path.join(RESULT_BASE_DIR, rule_name)
    
    # Tên file báo cáo CSV output
    report_file = f"Report_{rule_name}.csv"

    if not os.path.exists(command_file):
        print(f"Cảnh báo: Không tìm thấy file gốc {command_file} để lấy nội dung lệnh.")
        commands = []
    else:
        with open(command_file, 'r') as f:
            commands = [line.strip() for line in f if line.strip()]

    print(f"\n[*] Đang tạo báo cáo: {report_file}")
    
    report_data = []

    for index, cmd_content in enumerate(commands):
        cmd_id = index + 1
        
        # Tên file quy ước
        log_filename = f"{rule_name}_attack{cmd_id}.log"
        json_filename = f"result_{rule_name}_attack{cmd_id}.json"
        
        full_json_path = os.path.join(rule_result_dir, json_filename)
        
        status = "UNKNOWN"
        triggered_rules = "N/A"

        if os.path.exists(full_json_path):
            try:
                with open(full_json_path, 'r') as jf:
                    data = json.load(jf)
                    # Lấy danh sách rule title
                    titles = [item.get('title') for item in data if 'title' in item]
                    titles = list(set(titles)) # Unique
                    
                    if titles:
                        status = "DETECTED"
                        triggered_rules = " | ".join(titles)
                    else:
                        status = "BYPASS"
                        triggered_rules = "Bypass All"
            except:
                status = "ERROR JSON"
        else:
            status = "MISSING LOG/RESULT"

        report_data.append({
            "ID": cmd_id,
            "Command": cmd_content,
            "Log File": log_filename,
            "Status": status,
            "Detected Rules": triggered_rules
        })

    # Ghi CSV
    with open(report_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=["ID", "Command", "Log File", "Status", "Detected Rules"])
        writer.writeheader()
        writer.writerows(report_data)

    print(f"[SUCCESS] File CSV đã được tạo tại: {os.path.abspath(report_file)}")

if __name__ == "__main__":
    main()