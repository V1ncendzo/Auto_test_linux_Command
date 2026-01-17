import os
import shutil
import re
from pathlib import Path

# Configuration
SOURCE_DIR = Path("/home/vincenzolog/Auto_test/logs_output/Clear_Linux_Logs")
DEST_DIR = Path("/home/vincenzolog/Auto_test/stuff/Clear_Linux_Logs")
SUMMARY_FILE = DEST_DIR / "Filter_Summary.md"

# Tools that are distinct binaries for clearing/manipulating logs
TOOLS = {
    "shred", "rm", "unlink", "mv", "truncate", "cp", "ln", "dd", 
    "head", "tail", "cat", "sed", "awk", "cut", "tee"
}

# Interpreters (Shells and script engines)
INTERPRETERS = {"python", "perl", "node", "ruby", "php", "bash", "sh", "dash", "zsh"}

def is_meaningful(log_content):
    """
    Analyzes log content to determine if it represents a valid log clearing attempt.
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
        # Handle "python3.12" -> "python"
        image_base = re.split(r'[0-9.]+$', image_name)[0]

        # 1. Direct Tool Execution (The tool itself is running)
        # Check against blacklist of tools if needed, but here we just check membership
        if image_name in TOOLS or image_base in TOOLS:
            if "/var/log" in cmdline or "/var/spool" in cmdline:
                return True, f"Direct tool execution: {image} {cmdline}"

        # 2. Interpreter Execution (Shells/Python/etc)
        if image_name in INTERPRETERS or image_base in INTERPRETERS or any(image_name.startswith(x) for x in INTERPRETERS):
            
            # Check for shell redirection (>)
            if ">" in cmdline:
                 if "/var/log" in cmdline or "/var/spool" in cmdline:
                    return True, f"Shell redirection: {cmdline}"

            # Check for direct manipulation/open without calling external tools
            if "/var/log" in cmdline or "/var/spool" in cmdline:
                # Discard if it looks like it's just trying to call a TOOL (which would have its own event if successful)
                # e.g. "/bin/sh -c shred ..." -> Discard, wait for "shred" event
                # e.g. "python -c os.system('rm ...')" -> Discard, wait for "rm" event
                
                has_tool_call = False
                for t in TOOLS:
                    # Simple check: tool name surrounded by spaces or at start/end
                    # Regex: \btool\b
                    if re.search(fr"\b{t}\b", cmdline):
                        has_tool_call = True
                        break
                
                if not has_tool_call:
                     return True, f"Interpreter direct access: {cmdline}"

    return False, "No valid log clearing process found"

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
        f.write(f"# Filtering Summary for Clear Linux Logs\n\n")
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
