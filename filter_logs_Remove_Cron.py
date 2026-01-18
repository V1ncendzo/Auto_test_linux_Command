import os
import shutil
import re
from pathlib import Path

# Configuration
SOURCE_DIR = Path("/home/vincenzolog/Auto_test/logs_output/Remove_Scheduled_Cron_Task")
DEST_DIR = Path("/home/vincenzolog/Auto_test/stuff/Remove_Scheduled_Cron_Task")
DROPPED_DIR = DEST_DIR / "dropped"
CLEAN_DIR = DEST_DIR / "clean"
SUMMARY_FILE = DEST_DIR / "Filter_Summary.md"

def is_meaningful(log_content):
    """
    Analyzes log content to determine if it represents a valid Crontab Removal attempt.
    Criteria:
    1. Image/Command involves 'crontab'.
    2. CommandLine contains removal flags (-r, --remove) or obfuscated variants.
    """
    events = log_content.split("</Event>")
    
    for event in events:
        if "<EventID>1</EventID>" not in event:
            continue
            
        cmdline_match = re.search(r'<Data Name="CommandLine">([^<]+)</Data>', event)
        image_match = re.search(r'<Data Name="Image">([^<]+)</Data>', event)
        
        if not cmdline_match:
            continue
            
        cmdline = cmdline_match.group(1).strip()
        image = image_match.group(1).strip() if image_match else ""
        
        # Check if it involves crontab (either binary or command)
        # Note: Attack logs might rename crontab or copy it to /tmp
        is_relevant_process = "crontab" in image or "crontab" in cmdline
        
        # Specific temp file names from attack list (optional but safer to include if generic check fails)
        # But generally, we look for the intent to remove (-r) in ANY process that looks suspiciously like crontab usage
        
        # Removal Indicators
        # 1. Standard flags
        if re.search(r'(?:^|\s)-r(?:$|\s)', cmdline) or "--remove" in cmdline:
             return True, f"Standard removal flag found: {cmdline}"
             
        # 2. Obfuscated / Special cases
        # -r with special chars, no spaces, etc.
        # "crontab -r", "crontab-r", "crontab -r#", etc.
        if " -r" in cmdline or "-r " in cmdline: 
             # Catch cases like "crontab -r#", "crontab -r--", "crontab -r;"
             return True, f"Removal flag variants found: {cmdline}"

        if re.search(r'-(?:-|"|\')?r', cmdline):
             # Matches -r, --r, -"r", -'r'
             return True, f"Obfuscated removal flag found: {cmdline}"
             
        # 3. Explicit drops for List/Edit WITHOUT Removal
        if ("-l" in cmdline or "--list" in cmdline or "-e" in cmdline) and "-r" not in cmdline:
             return False, "List/Edit command without removal"

        # 4. Fallback for strict "crontab -r" substrings or specific attack patterns
        if "crontab" in cmdline and ("-r" in cmdline or "/r" in cmdline or "remove" in cmdline):
             return True, f"Likely removal attempt: {cmdline}"

    return False, "No valid removal indicators found"

def main():
    if DEST_DIR.exists():
        shutil.rmtree(DEST_DIR)
    DEST_DIR.mkdir(parents=True)
    DROPPED_DIR.mkdir()
    CLEAN_DIR.mkdir()
    
    log_files = sorted(list(SOURCE_DIR.glob("*.log")))
    
    kept_count = 0
    dropped_count = 0
    details = []
    
    print(f"Filtering {len(log_files)} logs from {SOURCE_DIR}...")
    
    for log_file in log_files:
        try:
            content = log_file.read_text(encoding="utf-8", errors="replace")
            keep, reason = is_meaningful(content)
            
            if keep:
                shutil.copy(log_file, CLEAN_DIR / log_file.name)
                kept_count += 1
            else:
                shutil.copy(log_file, DROPPED_DIR / log_file.name)
                dropped_count += 1
                details.append(f"| {log_file.name} | Dropped | {reason} |")
                
        except Exception as e:
            print(f"Error processing {log_file.name}: {e}")
            dropped_count += 1
            details.append(f"| {log_file.name} | Error | {e} |")

    # Generate Report
    with open(SUMMARY_FILE, "w") as f:
        f.write(f"# Filtering Summary for Remove Scheduled Cron Task\n\n")
        f.write(f"- **Total Logs**: {len(log_files)}\n")
        f.write(f"- **Kept**: {kept_count}\n")
        f.write(f"- **Dropped**: {dropped_count}\n")
        f.write(f"- **Rate**: {kept_count/len(log_files)*100:.1f}%\n\n")
        f.write("## Dropped Files Details\n\n")
        f.write("| File | Status | Reason |\n")
        f.write("|---|---|---|\n")
        f.write("\n".join(details))
        
    print(f"Done. Kept {kept_count}, Dropped {dropped_count}. Summary at {SUMMARY_FILE}")

if __name__ == "__main__":
    main()
