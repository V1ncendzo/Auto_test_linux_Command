import os
import re
import shutil

LOG_ROOT = "logs_output"
TARGET_DIR = "Suspicious_Invocation_of_Shell_via_AWK"
FILTERED_SUBDIR = "filtered"

# Sigma Rule Triggers (Strict String Matching)
SIGMA_IMAGES = ['/awk', '/gawk', '/mawk', '/nawk']
SIGMA_SHELLS = ['/bin/bash', '/bin/dash', '/bin/fish', '/bin/sh', '/bin/zsh']

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
    # Core concept: awk invoking system() or pipe to shell
    # Pattern must catch: system(...), | sh, | bash, etc.
    # The attack commands often split strings like "/bin/" "sh", or use hex.
    # We look for 'system' call or pipe to shell logic.
    
    # Meaningful: contains 'system(' OR pipes to a shell
    # Catch 'system' followed by some content
    # Also catch | sh, | bash
    right_meaning_pattern = re.compile(r'(system\s*\(|\|\s*(sh|bash|dash|zsh|csh)($|\s))', re.IGNORECASE)

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
                # Check "Right Meaning": Invokes system() or pipes to shell
                if right_meaning_pattern.search(cmd):
                    file_is_right_meaning = True
                    
                    # Check Trigger conditions for this command
                    # Sigma Rule:
                    # 1. Image ends with awk/gawk/mawk/nawk
                    # 2. CommandLine contains 'BEGIN {system'
                    # 3. CommandLine contains one of the shells
                    
                    # Since we verify Image loosely (is there an AWK image in the file?),
                    # we check CLI strictly first.
                    
                    is_trigger_cli = True
                    if 'BEGIN {system' not in cmd: 
                        is_trigger_cli = False
                        
                    has_sigma_shell = False
                    for shell in SIGMA_SHELLS:
                        if shell in cmd:
                            has_sigma_shell = True
                            break
                    if not has_sigma_shell:
                        is_trigger_cli = False
                        
                    if is_trigger_cli:
                        # Check if any image in the log matches Sigma images
                        if any(img.endswith(tuple(SIGMA_IMAGES)) for img in images):
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
        f.write("Filter Summary for Suspicious_Invocation_of_Shell_via_AWK\n")
        f.write("=========================================================\n")
        f.write(f"Total Logs: {stats['total']}\n")
        f.write(f"Filtered (Kept): {stats['kept']}\n")
        f.write(f"  - Trigger (Sigma Match): {stats['trigger']}\n")
        f.write(f"  - Bypass (Right Meaning, No Match): {stats['bypass']}\n")
        f.write(f"Discarded (Wrong Meaning): {stats['wrong_meaning']}\n")
        f.write("\nDefinitions:\n")
        f.write("- Trigger: Image is awk/sibling, CLI contains 'BEGIN {system' AND exact shell path.\n")
        f.write("- Bypass: Invokes 'system(' or pipes to shell but avoids exact string match (e.g. string concatenation, encoded chars, missing BEGIN).\n")
        f.write("- Wrong Meaning: No system() call or shell invocation attempt found.\n")

    print(f"Filtering complete. Summary written to {summary_path}")
    print(stats)

if __name__ == "__main__":
    filter_logs()
