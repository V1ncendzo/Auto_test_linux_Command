import os
import re
import shutil

LOG_ROOT = "logs_output"
TARGET_DIR = "BPFtrace_Unsafe_Option_Usage"
FILTERED_SUBDIR = "filtered"

# Sigma Rule Triggers (Strict String Matching)
SIGMA_IMAGES = ['bpftrace']

def filter_logs():
    source_dir = os.path.join(LOG_ROOT, TARGET_DIR)
    if not os.path.exists(source_dir):
        print(f"Directory not found: {source_dir}")
        return

    filtered_dir = os.path.join(source_dir, FILTERED_SUBDIR)
    if os.path.exists(filtered_dir):
        shutil.rmtree(filtered_dir)
    os.makedirs(filtered_dir)

    files = sorted([f for f in os.listdir(source_dir) if f.endswith(".log")])
    if not files:
        print("No logs found.")
        return

    stats = {
        "total": len(files),
        "kept": 0,
        "trigger": 0,
        "bypass": 0,
        "wrong_meaning": 0
    }

    # Regex for "Right Meaning"
    # Basic meaning: bpftrace execution, usually with -e or a script file, and often attempting unsafe mode.
    # The attack commands highlight MANY ways to mask "--unsafe".
    # But fundamentally, they are all invoking bpftrace to do something.
    # We should look for "bpftrace" (or renamed variants in context) AND typical flags like -e, -c, or implicit script execution.
    # However, given the attack set, simply detecting "unsafe" variations or "-e" execution is key.
    
    # We'll recognize "Right Meaning" if:
    # 1. Contains "unsafe" (fuzzy match)
    # 2. Contains "-e " followed by a script block (indicated by 'BEGIN' or similar)
    # 3. Contains typical BPFtrace structure.
    
    # Fuzzy regex for "unsafe": --un...safe with interruptions
    # Matches: --un"safe", --un\safe, --un$afe, etc.
    unsafe_fuzzy_pattern = re.compile(r'--[\'\"]?u[\'\"]?n[\'\"]?s[\'\"]?a[\'\"]?f[\'\"]?e', re.IGNORECASE)
    
    # General execution pattern: -e '...' or -e "..."
    exec_pattern = re.compile(r' -e\s+[\'\"]', re.IGNORECASE)

    print(f"Processing {len(files)} logs in {source_dir}...")

    for log_file in files:
        path = os.path.join(source_dir, log_file)
        try:
            with open(path, 'r', errors='ignore') as f:
                content = f.read()
            
            # Extract ALL CommandLines and Images
            command_lines = re.findall(r'CommandLine">(.*?)</Data>', content)
            images = re.findall(r'Image">(.*?)</Data>', content)
            
            file_is_right_meaning = False
            file_is_trigger = False
            
            for cmd in command_lines:
                # Check "Right Meaning"
                is_rm = False
                
                # Check for unsafe variations (most common in this attack set)
                # We need a robust regex. The attack list has --un$afe etc.
                # Let's simplify: if it contains "safe" or "secure" context, or "-e" execution.
                # Actually, simple heuristic: Check for 'unsafe' loosely OR -e usage.
                
                # Loose check for unsafe: u..n..s..a..f..e with potential noise in between
                # Too broad? Maybe. 
                # Let's look for known specific patterns from the file:
                # --unsafe, --un"safe", --un\safe
                
                # If command executes a BPF script (contains "BEGIN" or "exit()"), it's definitely meaningful.
                if 'BEGIN' in cmd or 'exit()' in cmd or 'system(' in cmd:
                    is_rm = True
                
                # If it explicitly tries to specify unsafe/safe mode
                if 'safe' in cmd.lower() or 'secure' in cmd.lower():
                    is_rm = True
                    
                if exec_pattern.search(cmd):
                    is_rm = True
                    
                if is_rm:
                    file_is_right_meaning = True
                    
                    # Check Trigger conditions for this command
                    # Sigma Rule:
                    # 1. Image ends with bpftrace
                    # 2. CommandLine contains '--unsafe' matches
                    
                    is_trigger_cli = True
                    if '--unsafe' not in cmd: 
                        is_trigger_cli = False
                        
                    if is_trigger_cli:
                        # Check image
                        if any(img.endswith("bpftrace") for img in images):
                            file_is_trigger = True

            if file_is_right_meaning:
                shutil.copy(path, os.path.join(filtered_dir, log_file))
                stats["kept"] += 1
                if file_is_trigger:
                    stats["trigger"] += 1
                else:
                    stats["bypass"] += 1
            else:
                stats["wrong_meaning"] += 1

        except Exception as e:
            print(f"Error reading {log_file}: {e}")

    summary_path = os.path.join(source_dir, "filtered_summary.txt")
    with open(summary_path, "w") as f:
        f.write("Filter Summary for BPFtrace_Unsafe_Option_Usage\n")
        f.write("==============================================\n")
        f.write(f"Total Logs: {stats['total']}\n")
        f.write(f"Filtered (Kept): {stats['kept']}\n")
        f.write(f"  - Trigger (Sigma Match): {stats['trigger']}\n")
        f.write(f"  - Bypass (Right Meaning, No Match): {stats['bypass']}\n")
        f.write(f"Discarded (Wrong Meaning): {stats['wrong_meaning']}\n")
        f.write("\nDefinitions:\n")
        f.write("- Trigger: Image ends in bpftrace, CLI contains '--unsafe'.\n")
        f.write("- Bypass: Invokes bpftrace/execution but avoids exact '--unsafe' (e.g. --un\"safe\", --un$afe, renamed binary).\n")
        f.write("- Wrong Meaning: No script execution or unsafe flag usage found.\n")

    print(f"Filtering complete. Summary written to {summary_path}")
    print(stats)

if __name__ == "__main__":
    filter_logs()
