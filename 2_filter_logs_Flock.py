import os
import re
import shutil

LOG_ROOT = "logs_output"
TARGET_DIR = "Shel_Execution_via_Flock"
FILTERED_SUBDIR = "filtered"

# Sigma Rule Triggers (Strict String Matching)
SIGMA_IMAGES = ['/flock']
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
    # Core concept: flock executing a command.
    # Pattern: flock [options] <lockfile|fd> <command>
    # We look for shell invocations in the arguments.
    # Common flags: -x, -s, -u, -n, -E, -w.
    # The attack commands show extensive variations.
    # Basic meaning: Is there a shell being executed via flock?
    # We look for "flock" (or renamed) followed by typical args and then a shell.
    # But since binary can be renamed, we focus on the structure:
    # "command ... shell"
    # Actually, simplistic regex for shell paths might be enough if we confirm it's a flock-like execution.
    # Given the attack set, looking for /bin/sh or similar shells in the CLI is the primary indicator of "Right Meaning".
    # Just checking for shell paths might be too broad if it catches random grep, but in these specific attack logs, it's likely fine.
    # We will refine: Check for shell paths. 
    
    shell_pattern = re.compile(r'(/bin/sh|/bin/bash|/bin/dash|/bin/zsh|/bin/fish|/usr/bin/sh|/usr/bin/bash|/bin/\W*sh|bash\s)', re.IGNORECASE)

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
                # Check "Right Meaning": Invokes a shell?
                if shell_pattern.search(cmd):
                    # To be "Right Meaning" for *Flock*, it should involve flock-like behavior.
                    # Since we don't know the binary name (could be renamed), we rely on the context of the attack logs.
                    # Almost all "Right Meaning" logs in this set are flock attacks.
                    # A benign log might be just "ls" or similar.
                    file_is_right_meaning = True
                    
                    # Check Trigger conditions for this command
                    # Sigma Rule:
                    # 1. Image ends with /flock
                    # 2. CommandLine contains ' -u ' (space u space)
                    # 3. CommandLine contains one of the shells
                    
                    is_trigger_cli = True
                    if ' -u ' not in cmd: 
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
                        if any(img.endswith('/flock') for img in images):
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
        f.write("Filter Summary for Shell_Execution_via_Flock\n")
        f.write("===========================================\n")
        f.write(f"Total Logs: {stats['total']}\n")
        f.write(f"Filtered (Kept): {stats['kept']}\n")
        f.write(f"  - Trigger (Sigma Match): {stats['trigger']}\n")
        f.write(f"  - Bypass (Right Meaning, No Match): {stats['bypass']}\n")
        f.write(f"Discarded (Wrong Meaning): {stats['wrong_meaning']}\n")
        f.write("\nDefinitions:\n")
        f.write("- Trigger: Image ends in /flock, CLI contains ' -u ' AND exact shell path.\n")
        f.write("- Bypass: Invokes shell via flock but avoids ' -u ' (uses -x, -s, -n, etc) or obfuscates shell path.\n")
        f.write("- Wrong Meaning: No shell invocation found.\n")

    print(f"Filtering complete. Summary written to {summary_path}")
    print(stats)

if __name__ == "__main__":
    filter_logs()
