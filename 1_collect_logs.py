import subprocess
import time
import os
import sys

# --- CẤU HÌNH ---
ATTACK_DIR = "attack_commands"  # Folder chứa input
LOG_BASE_DIR = "logs_output"    # Folder chứa output log

def run_shell(cmd):
    try:
        # Chạy lệnh hệ thống, ẩn output để màn hình đỡ rối
        subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.decode().strip() if e.stderr else "No error message"
        # Bỏ qua lỗi vacuum (vì nếu không có gì để xóa nó sẽ báo lỗi, kệ nó)
        if "vacuum" not in cmd: 
            print(f"    [Warning] Cmd: {cmd} | Msg: {error_msg}")

def ensure_sysmon_running():
    """Hàm đảm bảo Sysmon đang chạy ngon lành trước khi bắt đầu"""
    print("[*] Kiểm tra trạng thái Sysmon...")
    
    # Reset bộ đếm lỗi của systemd cho chắc ăn
    subprocess.run("systemctl reset-failed sysmon", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # Kiểm tra service có active không
    try:
        subprocess.run("systemctl is-active --quiet sysmon", shell=True, check=True)
        print("    -> Sysmon đang chạy (OK).")
    except subprocess.CalledProcessError:
        print("    -> Sysmon chưa chạy. Đang khởi động...")
        try:
            subprocess.run("systemctl start sysmon", shell=True, check=True)
            time.sleep(5) # Chờ 5s cho Sysmon load config
            print("    -> Sysmon đã khởi động thành công.")
        except Exception as e:
            print(f"\n[!!!] LỖI: Không thể bật Sysmon. Hãy kiểm tra lại service.\nLỗi: {e}")
            sys.exit(1)

def main():
    if os.geteuid() != 0:
        print("CẢNH BÁO: Vui lòng chạy bằng sudo!")
        sys.exit(1)

    # 1. Đảm bảo Sysmon sống
    ensure_sysmon_running()

    # 2. Chọn file input
    if not os.path.exists(ATTACK_DIR):
        print(f"Lỗi: Thiếu folder {ATTACK_DIR}"); return
    
    files = sorted([f for f in os.listdir(ATTACK_DIR) if f.endswith(".txt")])
    if not files: print("Không có file txt."); return

    print("\n--- DANH SÁCH FILE ---")
    for i, f in enumerate(files): print(f"[{i+1}] {f}")
    
    try:
        c = int(input("\nChọn file (VD: 1): ")) - 1
        selected_file = files[c]
    except:
        print("Lỗi chọn file."); return

    rule_name = selected_file.replace(".txt", "")
    input_path = os.path.join(ATTACK_DIR, selected_file)
    rule_log_dir = os.path.join(LOG_BASE_DIR, rule_name)

    if not os.path.exists(rule_log_dir): os.makedirs(rule_log_dir)

    with open(input_path, 'r') as f:
        commands = [line.strip() for line in f if line.strip()]

    print(f"\n[*] Bắt đầu test '{rule_name}' ({len(commands)} lệnh)")
    print("[*] Chiến thuật: Keep-Alive (Không restart Sysmon)\n")

    for i, attack_cmd in enumerate(commands):
        log_file = os.path.join(rule_log_dir, f"{rule_name}_attack{i+1}.log")
        print(f"--- Cmd {i+1}: {attack_cmd} ---")

        # === BƯỚC QUAN TRỌNG: DỌN LOG CŨ ===
        # Rotate: Đóng gói log hiện tại lại
        run_shell("journalctl --rotate")
        # Vacuum: Xóa sạch các file log đã đóng gói quá 1 giây trước
        # -> Giúp file log sắp lấy chỉ chứa sự kiện mới nhất
        run_shell("journalctl --vacuum-time=1s")
        
        # Chờ 1 chút để ổ cứng xử lý xong việc xóa
        time.sleep(1)

        # === TẤN CÔNG ===
        try:
            # Sysmon đang chạy nền nên sẽ bắt được ngay
            subprocess.run(attack_cmd, shell=True, timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            print("    -> Timeout (Lệnh đã chạy/treo, tiếp tục lấy log...)")
        except Exception as e:
            print(f"    -> Error executing command: {e}")

        # Chờ Sysmon kịp ghi log vào journal (Buffer time)
        time.sleep(3)

        # === LẤY LOG ===
        # Xuất log ra file JSON/Text
        run_shell(f"journalctl -u sysmon --no-pager > {log_file}")
        print(f"    -> Saved log: ...{log_file[-20:]}")

    # === FIX QUYỀN FILE ===
    # Để bạn có thể xóa/sửa file log mà không cần sudo sau này
    if os.environ.get('SUDO_UID'):
        try:
            uid = int(os.environ.get('SUDO_UID'))
            gid = int(os.environ.get('SUDO_GID'))
            for root, dirs, f_list in os.walk(rule_log_dir):
                for d in dirs: os.chown(os.path.join(root, d), uid, gid)
                for f in f_list: os.chown(os.path.join(root, f), uid, gid)
            os.chown(rule_log_dir, uid, gid)
            print("\n[OK] Đã mở khóa quyền folder log.")
        except: pass

    print("\n[DONE] Hoàn thành.")

if __name__ == "__main__":
    main()