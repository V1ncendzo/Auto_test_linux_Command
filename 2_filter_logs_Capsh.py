import os
import re
import shutil

LOG_ROOT = "logs_output"
TARGET_DIR = "Capsh_Shell_Invocation"
FILTERED_SUBDIR = "filtered"

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

    # "Right Meaning": Command indicates intent to spawn shell via capsh.
    # Logic: Look for " --" (space dash dash) acting as separator, 
    # OR explicit shell flags like --forkexec, --dropped=... (unlikely)
    # Primary trigger for Sigma is " --" at end.
    
    # Updated regex to handle XML tags (e.g., <Data...>... --</Data>)
    # We look for " --" followed by Valid Terminator (End of String, Space, Quote, or '<')
    shell_indicator_pattern = re.compile(r'\s--(?:$|[\s"\'<])') 
    
    # Special case: "capsh" alone might spawn shell, but we focus on explicit flags from the attack list
    # The attack list heavily features "--" for shell invocation.
    
    kept_files = []

    print(f"Processing {len(files)} logs in {source_dir}...")

    for log_file in files:
        path = os.path.join(source_dir, log_file)
        try:
            with open(path, 'r', errors='ignore') as f:
                content = f.read()
            
            # Extract command line for better precision if possible, but searching content is standard for these scripts
            # We look for the command that looks like capsh usage.
            
            is_right_meaning = False
            
            # Simple check: does it contain capsh?
            if 'capsh' in content.lower():
                # Check for the magic separator " --"
                if shell_indicator_pattern.search(content):
                    is_right_meaning = True
                # Also check specifically for "--login" as valid shell invocation (bypass)
                # Ensure we match end of flag properly even if followed by XML tag <
                elif re.search(r'\s--login(?:$|[\s"\'<])', content):
                    is_right_meaning = True
            
            if is_right_meaning:
                shutil.copy(path, os.path.join(filtered_dir, log_file))
                kept_files.append(log_file)
                stats["kept"] += 1
                
                # Classification
                # Trigger: Matches Sigma "endswith: ' --'"
                # In our content search, we have to guess the command line termination.
                # But roughly: if " --" is followed by nothing or just non-word chars in the match snippet?
                # Actually, precise determining of Sigma trigger on raw log text is hard without parsing XML.
                # But we can approximate: if pattern `\s--$` or `\s--"?(<|$)` appears.
                # Let's use a simpler heuristic for the report.
                
                # We'll check if the pattern matches specifically at the end of a likely command string
                # For this report, we'll mark as "Trigger" if " --" appears.
                # And "Bypass" if it appears but followed by other args (like -c).
                
                # Refined Trigger logic for report:
                # Sigma: CommandLine endswith " --"
                # We search for " --" followed by non-whitespace/args.
                
                if re.search(r'\s--[\s"\']*$', content) or re.search(r'\s--\s*<', content): # heuristically end of cmd or end of xml val
                     # This is likely a trigger if it ends strictly.
                     # But actually, many " --" will have trailing xml tags in raw log.
                     stats["trigger"] += 1
                else:
                     # It has " --" but presumably something follows? 
                     # Or it matched "--login".
                     stats["bypass"] += 1
            else:
                stats["wrong_meaning"] += 1

        except Exception as e:
            print(f"Error reading {log_file}: {e}")

    # Correction: The definition of Trigger vs Bypass in the report is tricky with raw logs.
    # The User wants to know "how many are filtered, and why".
    # I will rely on the counts and write a summary.
    
    summary_path = os.path.join(source_dir, "filtered_summary.txt")
    with open(summary_path, "w") as f:
        f.write("Filter Summary for Capsh_Shell_Invocation\n")
        f.write("=========================================\n")
        f.write(f"Total Logs: {stats['total']}\n")
        f.write(f"Filtered (Kept): {stats['kept']}\n")
        f.write(f"Discarded (Wrong Meaning): {stats['wrong_meaning']}\n")
        f.write("\nRationale:\n")
        f.write("- Right Meaning: Commands containing ' --' (shell trigger) or '--login'.\n")
        f.write("- Wrong Meaning: Informational commands (e.g., --print, --help) or syntax errors.\n")
        f.write("\nNote on Trigger/Bypass:\n")
        f.write("Logs kept include both Sigma rule triggers (ending in ' --') and potential bypasses (valid shell flags followed by arguments).\n")

    print(f"Filtering complete. Summary written to {summary_path}")
    print(f"Kept: {stats['kept']}, Discarded: {stats['wrong_meaning']}")

if __name__ == "__main__":
    filter_logs()
