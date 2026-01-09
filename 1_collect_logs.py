import subprocess
import time
import os
import sys

# --- CẤU HÌNH ---
ATTACK_DIR = "attack_commands"
LOG_BASE_DIR = "logs_output"

def run_shell(cmd):
    try:
        # Chạy lệnh, nếu lỗi thì in ra nhưng không dừng chương trình ngay
        subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.decode().strip() if e.stderr else "No error message"
        # Bỏ qua lỗi vacuum vì đôi khi không có gì để xóa
        if "vacuum" not in cmd: 
            print(f"    [Warning] Cmd: {cmd} | Msg: {error_msg}")

def ensure_sysmon_running():
    """Hàm đảm bảo Sysmon chạy ổn định trước khi test"""
    print("[*] Đang kiểm tra trạng thái Sysmon...")
    
    # 1. Reset bộ đếm lỗi trước (do các lần chạy trước gây ra)
    subprocess.run("systemctl reset-failed sysmon", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # 2. Kiểm tra xem đang chạy chưa
    try:
        subprocess.run("systemctl is-active --quiet sysmon", shell=True, check=True)
        print("    -> Sysmon đang chạy (OK).")
    except subprocess.CalledProcessError:
        print("    -> Sysmon chưa chạy. Đang khởi động...")
        try:
            subprocess.run("systemctl start sysmon", shell=True, check=True)
            time.sleep(3) # Chờ load config
            print("    -> Sysmon đã khởi động thành công.")
        except Exception as e:
            print(f"\n[!!!] LỖI CHÍ TỬ: Không thể bật Sysmon. Hãy kiểm tra lại cài đặt Sysmon.\nLỗi: {e}")
            sys.exit(1)

def main():
    if os.geteuid() != 0:
        print("CẢNH BÁO: Vui lòng chạy bằng sudo!")
        sys.exit(1)

    # === BƯỚC 0: ĐẢM BẢO SYSMON SỐNG ===
    ensure_sysmon_running()

    # Chọn file
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
    print("[*] Chiến thuật: Keep-Alive Sysmon (Không restart)\n")

    for i, attack_cmd in enumerate(commands):
        log_file = os.path.join(rule_log_dir, f"{rule_name}_attack{i+1}.log")
        print(f"--- Cmd {i+1}: {attack_cmd} ---")

        # === BƯỚC 1: DỌN DẸP LOG CŨ (Không tắt Sysmon) ===
        # Rotate để đẩy log hiện tại vào kho lưu trữ
        run_shell("journalctl --rotate")
        # Vacuum để xóa sạch các log đã lưu trữ trước đó (giữ lại 1s gần nhất thôi)
        run_shell("journalctl --vacuum-time=1s")
        
        # Chờ 1 chút để việc xóa hoàn tất
        time.sleep(1)

        # === BƯỚC 2: TẤN CÔNG ===
        try:
            # Sysmon đang chạy nền nên sẽ bắt được ngay
            subprocess.run(attack_cmd, shell=True, timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            print("    -> Timeout (Command đã chạy xong hoặc bị treo, tiếp tục lấy log...)")
        except Exception as e:
            print(f"    -> Error executing command: {e}")

        # Chờ Sysmon kịp ghi log vào journal
        time.sleep(3)

        # === BƯỚC 3: LẤY LOG ===
        # Lấy toàn bộ log hiện có của sysmon (vì ta đã vacuum sạch cái cũ ở Bước 1 rồi)
        run_shell(f"journalctl -u sysmon --no-pager > {log_file}")
        print(f"    -> Saved log: ...{log_file[-20:]}")

    # === BƯỚC 4: FIX QUYỀN ===
    if os.environ.get('SUDO_UID'):
        try:
            uid = int(os.environ.get('SUDO_UID'))
            gid = int(os.environ.get('SUDO_GID'))
            for root, dirs, f_list in os.walk(rule_log_dir):
                for d in dirs: os.chown(os.path.join(root, d), uid, gid)
                for f in f_list: os.chown(os.path.join(root, f), uid, gid)
            os.chown(rule_log_dir, uid, gid)
            print("\n[OK] Đã fix quyền folder log.")
        except: pass

    print("\n[DONE] Hoàn thành.")

if __name__ == "__main__":
    main()