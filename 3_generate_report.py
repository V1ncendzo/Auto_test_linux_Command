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

def normalize_text(text):
    """Hàm chuẩn hóa chuỗi để so sánh tương đối"""
    if not text: return ""
    return text.lower().replace("_", " ").replace("-", " ").strip()

def main():
    rule_name = get_rule_selection()
    
    # File input gốc
    command_file = os.path.join(ATTACK_DIR, rule_name + ".txt")
    
    # Folder kết quả json
    rule_result_dir = os.path.join(RESULT_BASE_DIR, rule_name)
    
    # Tên file báo cáo CSV output
    report_file = f"Report_{rule_name}.csv"

    if not os.path.exists(command_file):
        print(f"Cảnh báo: Không tìm thấy file gốc {command_file}.")
        commands = []
    else:
        with open(command_file, 'r') as f:
            commands = [line.strip() for line in f if line.strip()]

    print(f"\n[*] Đang tạo báo cáo: {report_file}")
    
    report_data = []

    # --- KHỞI TẠO BỘ ĐẾM THỐNG KÊ ---
    stats = {
        "total": 0,
        "bypass_all": 0,          # Không bị bắt bởi bất kỳ rule nào
        "bypass_target_rule": 0,  # Bị bắt bởi rule khác, nhưng bypass rule target
        "trigger_target": 0,      # Bị bắt đúng rule target
        "errors": 0
    }

    target_rule_normalized = normalize_text(rule_name)

    for index, cmd_content in enumerate(commands):
        stats["total"] += 1
        cmd_id = index + 1
        
        log_filename = f"{rule_name}_attack{cmd_id}.log"
        json_filename = f"result_{rule_name}_attack{cmd_id}.json"
        
        full_json_path = os.path.join(rule_result_dir, json_filename)
        
        final_result = "Unknown"
        detected_list_str = ""

        if os.path.exists(full_json_path):
            try:
                with open(full_json_path, 'r') as jf:
                    data = json.load(jf)
                    titles = [item.get('title') for item in data if 'title' in item]
                    titles = list(set(titles)) # Unique
                    
                    if not titles:
                        # Case 1: Bypass All
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
                            # Case 2: Trigger Target
                            final_result = f"Trigger: {hit_rule_name}"
                            stats["trigger_target"] += 1
                        else:
                            # Case 3: Bypass Target (nhưng dính rule khác)
                            final_result = "Bypass Target Rule"
                            stats["bypass_target_rule"] += 1

                    detected_list_str = " | ".join(titles) if titles else "None"

            except Exception:
                final_result = "Log Error (JSON Invalid)"
                stats["errors"] += 1
        else:
            final_result = "Log Error (Missing Result)"
            stats["errors"] += 1

        report_data.append({
            "ID": cmd_id,
            "Command": cmd_content,
            "Log File": log_filename,
            "Result": final_result,
            "All Detected Rules": detected_list_str 
        })

    # --- GHI FILE CSV ---
    with open(report_file, 'w', newline='', encoding='utf-8') as f:
        fieldnames = ["ID", "Command", "Log File", "Result", "All Detected Rules"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(report_data)

        # --- GHI PHẦN TỔNG HỢP (SUMMARY) Ở CUỐI FILE ---
        # Tính tổng số bypass target (Bao gồm cả Bypass All và Bypass Target Rule)
        total_bypass_target = stats["bypass_all"] + stats["bypass_target_rule"]
        bypass_rate = (total_bypass_target / stats["total"] * 100) if stats["total"] > 0 else 0

        writer.writerow({}) # Dòng trống
        writer.writerow({}) # Dòng trống
        writer.writerow({"ID": "=== SUMMARY REPORT ==="})
        
        # Ghi các dòng thống kê (Lợi dụng cột ID làm nhãn, cột Command làm giá trị)
        writer.writerow({"ID": "Total Commands", "Command": stats["total"]})
        writer.writerow({"ID": "Total Triggered Target", "Command": stats["trigger_target"]})
        writer.writerow({"ID": "Total Bypass Target", "Command": f"{total_bypass_target} ({bypass_rate:.1f}%)"})
        writer.writerow({"ID": "  > Bypass All (Silent)", "Command": stats["bypass_all"]})
        writer.writerow({"ID": "  > Bypass Target Rule (Noisy)", "Command": stats["bypass_target_rule"]})
        
        if stats["errors"] > 0:
            writer.writerow({"ID": "Errors", "Command": stats["errors"]})

    print(f"[SUCCESS] File CSV đã được tạo tại: {os.path.abspath(report_file)}")
    print(f"Tổng kết: {total_bypass_target}/{stats['total']} commands đã bypass được target rule.")

if __name__ == "__main__":
    main()