import os
import re
import shutil

LOG_ROOT = "logs_output"
TARGET_DIR = "Shell_Execution_via_Find"
FILTERED_SUBDIR = "filtered"

# Sigma Rule Triggers (Strict String Matching)
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

    # Regex for Shell Execution Indicators
    # Matches -exec or -ok followed by suspect patterns
    # Suspect patterns: shell names, obfuscation quotes, variable expansion
    # We want to catch: /bin/sh, /bin/s"h", $(...), `...`, etc.
    
    # Broad catch for shell-like terms
    shell_pattern = re.compile(r'(-exec|-ok)\s+.*?(sh|bash|dash|zsh|fish|cmd|powershell|uid|whoami|\$\(|\`|/bin/)', re.IGNORECASE)

    print(f"Processing {len(files)} logs in {source_dir}...")

    for log_file in files:
        path = os.path.join(source_dir, log_file)
        try:
            with open(path, 'r', errors='ignore') as f:
                content = f.read()
            
            # Extract ALL CommandLines and Images to check usage
            # Note: There might be multiple events. We want to keep the file if *any* event matches "Right Meaning".
            
            command_lines = re.findall(r'CommandLine">(.*?)</Data>', content)
            images = re.findall(r'Image">(.*?)</Data>', content)
            
            # Map images to commands if possible? 
            # re.findall just gives lists. They might not perfectly align if some events lack fields, 
            # but usually CommandLine and Image go together in EventID 1. 
            # For filtering, just checking if *content* contains the pattern is easier,
            # but to distinguish Trigger vs Bypass accurately we need the specific pair.
            # However, sophisticated parsing is brittle with regex.
            # Let's check regex on the command lines we found.
            
            file_is_right_meaning = False
            file_is_trigger = False
            
            for i, cmd in enumerate(command_lines):
                # Check "Right Meaning"
                if re.search(r'(-exec|-ok)', cmd):
                    # Check for known shell binaries or suspect patterns
                    if shell_pattern.search(cmd):
                        file_is_right_meaning = True
                        
                        # Now check Trigger conditions for THIS matched command
                        # We need the corresponding Image. 
                        # Simple Heuristic: Does the file contain a Find Image? matches logic roughly.
                        # Strict Trigger: (Image ends /find) AND ( . ) AND (-exec) ...
                        
                        # Since we can't easily link Image to Cmd with regex lists without offsets,
                        # We will assume if the CMD looks like a Trigger, and "find" is somewhere in the file (or implicit in cmd), it's a trigger.
                        # Actually, Sigma says Image|endswith: /find.
                        # If a CLI matches " . -exec /bin/sh", it's almost certainly Find.
                        # But strictly, if we renamed find, CLI matches but Image doesn't.
                        
                        is_likely_trigger = True
                        if " . " not in cmd: 
                            is_likely_trigger = False
                        if "-exec" not in cmd: 
                            is_likely_trigger = False
                        
                        has_sigma_shell = False
                        for shell in SIGMA_SHELLS:
                            if shell in cmd:
                                has_sigma_shell = True
                                break
                        if not has_sigma_shell:
                            is_likely_trigger = False
                            
                        # Check image constraint if possible. 
                        # If we found a trigger-like command, we assume it's a trigger unless we want to be super strict.
                        if is_likely_trigger:
                            # Try to confirm "find" image exists in file
                            if any(img.endswith('/find') for img in images):
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
        f.write("Filter Summary for Shell_Execution_via_Find\n")
        f.write("===========================================\n")
        f.write(f"Total Logs: {stats['total']}\n")
        f.write(f"Filtered (Kept): {stats['kept']}\n")
        f.write(f"  - Trigger (Sigma Match): {stats['trigger']}\n")
        f.write(f"  - Bypass (Right Meaning, No Match): {stats['bypass']}\n")
        f.write(f"Discarded (Wrong Meaning): {stats['wrong_meaning']}\n")
        f.write("\nDefinitions:\n")
        f.write("- Trigger: Image ends in /find, contains ' . ', '-exec', and exact shell path.\n")
        f.write("- Bypass: Uses -exec/-ok to invoke shell but evades one of the above constraints (e.g., no space-dot-space, obfuscated shell name, copied binary).\n")
        f.write("- Wrong Meaning: No -exec/-ok or benign command execution (triggering no shell).\n")

    print(f"Filtering complete. Summary written to {summary_path}")
    print(stats)

if __name__ == "__main__":
    filter_logs()
