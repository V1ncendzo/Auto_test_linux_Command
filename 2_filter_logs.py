import os
import re
import shutil

LOG_ROOT = "logs_output"
FILTER_RULES = {
    "Kaspersky_Endpoint_Security_Stopped_Via_CommandLine": {
        "func": lambda c: re.search(r'kesl', c, re.IGNORECASE) and (re.search(r'stop', c, re.IGNORECASE) or re.search(r'disable', c, re.IGNORECASE))
    },
    "Crontab_Enumeration": {
        # Check for crontab context AND the -l flag (trigger or bypass attempt)
        # We search specifically for -l surrounded by non-word chars or start/end of string, 
        # or special chars like > (redirect), | (pipe), space.
        # But simple check: "crontab" present AND "-l" present (not --list).
        # We use a regex that looks for -l not followed by i,s,t etc.
        "func": lambda c: re.search(r'crontab', c, re.IGNORECASE) and re.search(r'[\s"\'|]-l[\s"\'|>]', c)
    }
}

def filter_logs():
    if not os.path.exists(LOG_ROOT):
        print(f"Log directory not found: {LOG_ROOT}")
        return

    for rule_name, rule_config in FILTER_RULES.items():
        log_dir = os.path.join(LOG_ROOT, rule_name)
        if not os.path.exists(log_dir):
            print(f"Skipping {rule_name}: Directory not found.")
            continue
            
        print(f"\nProcessing {rule_name}...")
        filtered_dir = os.path.join(log_dir, "filtered")
        if not os.path.exists(filtered_dir):
            os.makedirs(filtered_dir)
        else:
            # Clean directory? Or just add/overwrite. Let's overwrite.
            pass

        files = sorted([f for f in os.listdir(log_dir) if f.endswith(".log")])
        if not files:
            print(f"  No logs found.")
            continue

        kept_count = 0
        for log_file in files:
            path = os.path.join(log_dir, log_file)
            try:
                with open(path, 'r', errors='ignore') as f:
                    content = f.read()

                if rule_config["func"](content):
                    shutil.copy(path, os.path.join(filtered_dir, log_file))
                    kept_count += 1
            except Exception as e:
                print(f"  Error reading {log_file}: {e}")
        
        print(f"  Filtered {kept_count}/{len(files)} logs to {filtered_dir}")

if __name__ == "__main__":
    filter_logs()
