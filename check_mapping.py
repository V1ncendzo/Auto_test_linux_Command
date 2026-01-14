import os

# --- CẤU HÌNH ĐƯỜNG DẪN ---
RULES_DIR = os.path.join('sigma', 'rules', 'linux', 'process_creation')
EVENTS_DIR = os.path.join('sigma', 'events', 'linux', 'process_creation')

def main():
    if not os.path.exists(RULES_DIR) or not os.path.exists(EVENTS_DIR):
        print("❌ Lỗi: Không tìm thấy thư mục rules hoặc events.")
        return

    print(f"--- ĐANG KIỂM TRA ĐỐI CHIẾU ---\n")

    # 1. Lấy danh sách (Bỏ đuôi .yml để so sánh)
    # Set comprehension giúp tìm kiếm nhanh hơn
    rule_names = {f.replace('.yml', '') for f in os.listdir(RULES_DIR) if f.endswith('.yml')}
    folder_names = {f for f in os.listdir(EVENTS_DIR) if os.path.isdir(os.path.join(EVENTS_DIR, f))}

    # 2. Phân loại
    # - Folder khớp đúng với Rule
    matched = folder_names.intersection(rule_names)
    
    # - Folder tồn tại nhưng KHÔNG có Rule tương ứng (Có thể do đổi tên sai, hoặc thừa folder rác)
    orphaned_folders = folder_names.difference(rule_names)
    
    # - Rule tồn tại nhưng CHƯA có Folder (Có thể bạn chưa tạo event cho rule này)
    missing_folders = rule_names.difference(folder_names)

    # 3. Báo cáo kết quả

    # --- PHẦN 1: KIỂM TRA CÁC FOLDER CỦA BẠN (QUAN TRỌNG NHẤT) ---
    print(f"📊 Tổng số folder hiện có: {len(folder_names)}")
    
    if len(orphaned_folders) == 0:
        print("✅ TUYỆT VỜI! 100% Folder của bạn đều khớp đúng với tên Rule.")
    else:
        print(f"⚠️ CẢNH BÁO: Có {len(orphaned_folders)} folder KHÔNG khớp với bất kỳ rule nào:")
        for f in orphaned_folders:
            print(f"   ❌ {f} (Kiểm tra lại xem có gõ sai tên không?)")
    
    print("-" * 30)

    # --- PHẦN 2: KIỂM TRA ĐỘ PHỦ (Rule nào chưa có folder?) ---
    print(f"📊 Tổng số Rules: {len(rule_names)}")
    print(f"✅ Đã map thành công: {len(matched)} rules.")
    
    if len(missing_folders) > 0:
        print(f"ℹ️  Hiện còn {len(missing_folders)} rules chưa có folder event tương ứng:")
        # Chỉ in tối đa 5 cái để đỡ rối, nếu muốn in hết thì bỏ dòng [:5]
        for idx, r in enumerate(sorted(list(missing_folders))):
            print(f"   ⭕ {r}")
    else:
        print("🎉 Full Coverage! Tất cả các rule đều đã có folder event.")

if __name__ == "__main__":
    main()