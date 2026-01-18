import os
import shutil
import re
from pathlib import Path

# Configuration
SOURCE_DIR = Path("/home/vincenzolog/Auto_test/logs_output/Crontab_Enumeration")
DEST_DIR = Path("/home/vincenzolog/Auto_test/stuff/Crontab_Enumeration")
SUMMARY_FILE = DEST_DIR / "Filter_Summary.md"

def is_meaningful(log_content):
    """
    Analyzes log content to determine if it represents a valid Crontab Enumeration attempt.
    Criteria:
    1. Image is 'crontab' (or specific renamed variants from attack list) AND CommandLine has '-l'.
    2. CommandLine contains 'crontab' AND '-l' (handling shell wrappers/redirection).
    3. Excludes invalid flags like '--list', '-d', etc. unless '-l' is also there.
    """
    events = log_content.split("</Event>")
    
    for event in events:
        if "<EventID>1</EventID>" not in event:
            continue
            
        image_match = re.search(r'<Data Name="Image">([^<]+)</Data>', event)
        cmdline_match = re.search(r'<Data Name="CommandLine">([^<]+)</Data>', event)
        
        if not image_match or not cmdline_match:
            continue
            
        image = image_match.group(1).strip()
        cmdline = cmdline_match.group(1).strip()
        
        image_name = os.path.basename(image)
        
        # Check 1: Standard Execution or Renamed Binary
        # If the binary is running, check arguments
        if "crontab" in image_name or any(p in image for p in ["/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/", "/home/"]):
             # We want to catch 'crontab -l', '/tmp/x -l'
             # But we must ensure the command line has '-l'
             
             # Robust check for -l flag
             # 1. Exact match "-l"
             # 2. "-l" surrounded by spaces
             # 3. End of string
             if re.search(r'(?:\s|^)-l(?:\s|$)', cmdline):
                 return True, f"Valid execution: {image_name} {cmdline}"
        
        # Check 2: Shell Wrappers / Redirection
        # e.g. /bin/sh -c "crontab -l > ..."
        if "crontab" in cmdline and re.search(r'(?:\s|^)-l(?:\s|$)', cmdline):
             return True, f"Shell wrapper with valid command: {cmdline}"
             
        # Handling special cases from the attack file
        # e.g. "crontab -l", "crontab-l" (typo? usually fails, but strict check for space)
        # The Sigma rule says: 
        # Image|endswith: '/crontab' AND CommandLine|contains: ' -l'
        # Or just CommandLine contains 'crontab' for bypasses?
        # Let's stick to "meaningful intent to list".
        
        # If we see "crontab -l" anywhere in commandline, it's likely a valid attempt
        if "crontab" in cmdline and "-l" in cmdline:
             # Sanity check: is it "-l" or "--list" or "-list"?
             # Sigma rule looks for " -l" (space -l).
             
             if " -l" in cmdline:
                 return True, f"Command line contains key pattern: {cmdline}"

    return False, "No valid crontab enumeration process found"

def main():
    if DEST_DIR.exists():
        shutil.rmtree(DEST_DIR)
    DEST_DIR.mkdir(parents=True)
    
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
                shutil.copy(log_file, DEST_DIR / log_file.name)
                kept_count += 1
            else:
                dropped_count += 1
                details.append(f"| {log_file.name} | Dropped | {reason} |")
                
        except Exception as e:
            print(f"Error processing {log_file.name}: {e}")
            dropped_count += 1
            details.append(f"| {log_file.name} | Error | {e} |")

    # Generate Report
    with open(SUMMARY_FILE, "w") as f:
        f.write(f"# Filtering Summary for Crontab Enumeration\n\n")
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
