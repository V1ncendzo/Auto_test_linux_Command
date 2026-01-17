import os
import shutil
import re
from pathlib import Path

# Configuration
SOURCE_DIR = Path("/home/vincenzolog/Auto_test/logs_output/Linux_Crypto_Mining_Indicators")
DEST_DIR = Path("/home/vincenzolog/Auto_test/stuff/Linux_Crypto_Mining_Indicators")
DROPPED_DIR = DEST_DIR / "dropped"
CLEAN_DIR = DEST_DIR / "clean"
SUMMARY_FILE = DEST_DIR / "Filter_Summary.md"

def is_meaningful(log_content):
    """
    Analyzes log content to determine if it represents a valid Crypto Mining attempt.
    Criteria:
    1. CommandLine contains mining-specific flags/params.
    2. CommandLine contains MSR modification commands (common miner prep).
    """
    events = log_content.split("</Event>")
    
    for event in events:
        if "<EventID>1</EventID>" not in event:
            continue
            
        cmdline_match = re.search(r'<Data Name="CommandLine">([^<]+)</Data>', event)
        
        if not cmdline_match:
            continue
            
        cmdline = cmdline_match.group(1).strip()
        
        # 1. Mining Parameters
        mining_indicators = [
            "--cpu-priority",
            "--donate-level",
            "-o pool",
            "--nicehash",
            "--algo=",
            "stratum+tcp://",
            "stratum+udp://",
            "stratum+ssl://"
        ]
        
        for indicator in mining_indicators:
            if indicator in cmdline:
                return True, f"Mining parameter found: {indicator} in {cmdline}"

        # 2. MSR Modification (RandomX prep)
        # Matches 'allow_writes=on', 'allow_writes=1', etc.
        if "allow_writes" in cmdline:
            return True, f"MSR modification attempt: {cmdline}"
        
        # Alternative strict check for modprobe msr if allow_writes is obfuscated/missing
        if "modprobe" in cmdline and "msr" in cmdline:
             return True, f"MSR kernel module interaction: {cmdline}"

        # 3. Base64 strings from Sigma rule (optional backup)
        base64_indicators = [
            "LS1kb25hdGUtbGV2ZWw9", "0tZG9uYXRlLWxldmVsP", "tLWRvbmF0ZS1sZXZlbD", # --donate-level=
            "c3RyYXR1bSt0Y3A6Ly", "N0cmF0dW0rdGNwOi8v", "zdHJhdHVtK3RjcDovL", # stratum+tcp://
            "c3RyYXR1bSt1ZHA6Ly", "N0cmF0dW0rdWRwOi8v", "zdHJhdHVtK3VkcDovL"  # stratum+udp://
        ]
        for b64 in base64_indicators:
            if b64 in cmdline:
                return True, f"Base64 encoded miner config found: {cmdline}"

    return False, "No valid crypto mining indicators found"

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
        f.write(f"# Filtering Summary for Linux Crypto Mining Indicators\n\n")
        f.write(f"- **Total Logs**: {len(log_files)}\n")
        f.write(f"- **Kept**: {kept_count}\n")
        f.write(f"- **Dropped**: {dropped_count}\n")
        f.write(f"- **Rate**: {kept_count/len(log_files)*100:.1f}%\n\n")
        f.write("## Dropped Files Details\n\n")
        f.write("| File | Status | Reason |\n")
        f.write("|---|---|---|\n")
        f.write("\n".join(details))
        
    print(f"Done. Kept {kept_count}, Dropped {dropped_count}. Summary at {SUMMARY_FILE}")
    print(f"Clean logs in: {CLEAN_DIR}")
    print(f"Dropped logs in: {DROPPED_DIR}")

if __name__ == "__main__":
    main()
