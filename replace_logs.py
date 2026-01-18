import os
import shutil

LOG_ROOT = "logs_output"
BACKUP_ROOT = "stuff"

def replace_and_backup():
    if not os.path.exists(LOG_ROOT):
        print(f"Directory not found: {LOG_ROOT}")
        return

    # Ensure backup root exists
    if not os.path.exists(BACKUP_ROOT):
        os.makedirs(BACKUP_ROOT)
        print(f"Created backup directory: {BACKUP_ROOT}")

    # Scan for directories containing 'filtered' subfolder
    dirs = [d for d in os.listdir(LOG_ROOT) if os.path.isdir(os.path.join(LOG_ROOT, d))]
    
    for d in dirs:
        rule_dir = os.path.join(LOG_ROOT, d)
        filtered_dir = os.path.join(rule_dir, "filtered")
        
        if os.path.exists(filtered_dir) and os.path.isdir(filtered_dir):
            print(f"Processing {d}...")
            
            # Setup backup directory for this rule
            backup_dir = os.path.join(BACKUP_ROOT, d)
            if not os.path.exists(backup_dir):
                os.makedirs(backup_dir)
            
            # 1. Backup original logs (Everything except 'filtered' and 'filtered_summary.txt')
            # Actually, we should probably backup everything that is currently there just in case, 
            # but user specifically asked to "store old logs (full logs before filtering)".
            # So taking all .log files from the rule_dir is safer.
            
            all_files = os.listdir(rule_dir)
            files_to_move = [f for f in all_files if f != "filtered" and f != "filtered_summary.txt"]
            
            if not files_to_move:
                print(f"  No original files found to backup in {d} (excluding filtered/).")
            else:
                for f in files_to_move:
                    src = os.path.join(rule_dir, f)
                    dst = os.path.join(backup_dir, f)
                    # If it's a file, move it. If it's a dir (unexpected), maybe skip or move.
                    # We expect logs and maybe metadata files.
                    if os.path.isfile(src):
                        shutil.move(src, dst)
                    elif os.path.isdir(src):
                        # Should not happen based on current structure, but good to handle
                        if f != "filtered":
                            if os.path.exists(dst):
                                shutil.rmtree(dst)
                            shutil.move(src, dst)
                print(f"  Backed up {len(files_to_move)} items to {backup_dir}")

            # 2. Move filtered logs to rule_dir
            filtered_files = os.listdir(filtered_dir)
            for f in filtered_files:
                src = os.path.join(filtered_dir, f)
                dst = os.path.join(rule_dir, f)
                shutil.move(src, dst)
            print(f"  Moved {len(filtered_files)} filtered logs to {rule_dir}")
            
            # 3. Remove empty filtered directory
            os.rmdir(filtered_dir)
            print("  Removed 'filtered' directory.")
            
        else:
            # print(f"Skipping {d} (no 'filtered' folder)")
            pass

    print("Log replacement and backup completed.")

if __name__ == "__main__":
    replace_and_backup()
