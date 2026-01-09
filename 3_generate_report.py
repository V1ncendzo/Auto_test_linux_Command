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
    # Chuyển về chữ thường, thay gạch dưới/gạch ngang bằng khoảng trắng
    return text.lower().replace("_", " ").replace("-", " ").strip()

def main():
    rule_name = get_rule_selection()
    
    # File input gốc (để lấy nội dung command)
    command_file = os.path.join(ATTACK_DIR, rule_name + ".txt")
    
    # Folder kết quả json
    rule_result_dir = os.path.join(RESULT_BASE_DIR, rule_name)
    
    # Tên file báo cáo CSV output
    report_file = f"Report_{rule_name}.csv"

    if not os.path.exists(command_file):
        print(f"Cảnh báo: Không tìm thấy file gốc {command_file}. Command content sẽ trống.")
        commands = []
    else:
        with open(command_file, 'r') as f:
            commands = [line.strip() for line in f if line.strip()]

    print(f"\n[*] Đang tạo báo cáo: {report_file}")
    
    report_data = []

    # Chuẩn hóa tên Target Rule (tên folder) để so sánh
    target_rule_normalized = normalize_text(rule_name)

    for index, cmd_content in enumerate(commands):
        cmd_id = index + 1
        
        # Tên file quy ước
        log_filename = f"{rule_name}_attack{cmd_id}.log"
        json_filename = f"result_{rule_name}_attack{cmd_id}.json"
        
        full_json_path = os.path.join(rule_result_dir, json_filename)
        
        # Biến lưu kết quả cuối cùng
        final_result = "Unknown"
        detected_list_str = "" # Để lưu danh sách các rule dính (nếu cần tham khảo)

        if os.path.exists(full_json_path):
            try:
                with open(full_json_path, 'r') as jf:
                    data = json.load(jf)
                    # Lấy danh sách rule title
                    titles = [item.get('title') for item in data if 'title' in item]
                    titles = list(set(titles)) # Unique
                    
                    if not titles:
                        # Trường hợp 1: Không có rule nào bắt
                        final_result = "Bypass All"
                    else:
                        # Có rule bắt -> Kiểm tra xem có phải Target Rule không
                        is_target_hit = False
                        hit_rule_name = ""

                        for t in titles:
                            t_norm = normalize_text(t)
                            # So sánh tương đối: Nếu tên folder nằm trong tên rule hoặc ngược lại
                            if target_rule_normalized in t_norm or t_norm in target_rule_normalized:
                                is_target_hit = True
                                hit_rule_name = t
                                break
                        
                        if is_target_hit:
                            # Trường hợp 2: Bắt đúng rule target
                            final_result = f"Trigger: {hit_rule_name}"
                        else:
                            # Trường hợp 3: Bị bắt bởi rule khác, nhưng rule target lại không bắt
                            final_result = "Bypass Target Rule"
                            # (Optional) Nếu muốn ghi chú thêm là bị rule nào bắt thì dùng dòng dưới:
                            # final_result = f"Bypass Target Rule (Caught by: {', '.join(titles)})"

                    detected_list_str = " | ".join(titles) if titles else "None"

            except Exception as e:
                final_result = "Log Error (JSON Invalid)"
        else:
            final_result = "Log Error (Missing Result)"

        report_data.append({
            "ID": cmd_id,
            "Command": cmd_content,
            "Log File": log_filename,
            "Result": final_result,
            "All Detected Rules": detected_list_str 
        })

    # Ghi CSV
    with open(report_file, 'w', newline='', encoding='utf-8') as f:
        # Sửa lại header cho khớp với yêu cầu
        fieldnames = ["ID", "Command", "Log File", "Result", "All Detected Rules"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(report_data)

    print(f"[SUCCESS] File CSV đã được tạo tại: {os.path.abspath(report_file)}")
    print("Mở file CSV để xem cột 'Result' theo logic mới.")

if __name__ == "__main__":
    main()