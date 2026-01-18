import os
import re
import shutil

LOG_DIR = "logs_output/Kaspersky_Endpoint_Security_Stopped_Via_CommandLine"
FILTERED_DIR = os.path.join(LOG_DIR, "filtered")

def filter_logs():
    if not os.path.exists(LOG_DIR):
        print(f"Log directory not found: {LOG_DIR}")
        return

    if not os.path.exists(FILTERED_DIR):
        os.makedirs(FILTERED_DIR)

    files = sorted([f for f in os.listdir(LOG_DIR) if f.endswith(".log")])
    if not files:
        print(f"No log files found in {LOG_DIR}")
        return

    print(f"Checking {len(files)} logs in {LOG_DIR}...")

    kept_count = 0
    for log_file in files:
        path = os.path.join(LOG_DIR, log_file)
        try:
            with open(path, 'r', errors='ignore') as f:
                content = f.read()

            if re.search(r'kesl', content, re.IGNORECASE) and \
               (re.search(r'stop', content, re.IGNORECASE) or re.search(r'disable', content, re.IGNORECASE)):
                
                shutil.copy(path, os.path.join(FILTERED_DIR, log_file))
                kept_count += 1
        except Exception as e:
            print(f"Error reading {log_file}: {e}")
    
    print(f"Filtered {kept_count}/{len(files)} logs to {FILTERED_DIR}")

if __name__ == "__main__":
    filter_logs()
