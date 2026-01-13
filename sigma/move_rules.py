import os
import shutil
import glob

def move_original_rules():
    # CẬP NHẬT: Đã bỏ 'sigma' ở đầu vì file này đang nằm trong folder sigma
    source_dir = os.path.join('rules', 'process_creation')
    dest_dir = os.path.join('rules', 'process_access')

    # Debug: In ra đường dẫn tuyệt đối để dễ kiểm tra nếu vẫn lỗi
    print(f"Đang tìm nguồn tại: {os.path.abspath(source_dir)}")

    # Kiểm tra thư mục nguồn
    if not os.path.exists(source_dir):
        print(f"Lỗi: Không tìm thấy thư mục nguồn: {source_dir}")
        print("Hãy chắc chắn bạn đang chạy lệnh này bên trong thư mục 'sigma'")
        return

    # Tạo thư mục đích nếu chưa có
    if not os.path.exists(dest_dir):
        os.makedirs(dest_dir)
        print(f"Đã tạo thư mục đích: {dest_dir}")

    # Tìm file
    search_pattern = os.path.join(source_dir, '*original.yml')
    files_to_move = glob.glob(search_pattern)

    if not files_to_move:
        print("Không tìm thấy file nào có đuôi 'original.yml'.")
        return

    count = 0
    for file_path in files_to_move:
        file_name = os.path.basename(file_path)
        dest_path = os.path.join(dest_dir, file_name)
        
        try:
            shutil.move(file_path, dest_path)
            print(f"Đã chuyển: {file_name}")
            count += 1
        except Exception as e:
            print(f"Lỗi khi chuyển {file_name}: {e}")

    print(f"-" * 30)
    print(f"Hoàn tất! Đã chuyển {count} file.")

if __name__ == "__main__":
    move_original_rules()