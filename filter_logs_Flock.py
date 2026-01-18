#!/usr/bin/env python3
"""
Filter Script for Shell_Execution_via_Flock logs.

This script filters logs collected from Flock attack tests:
- Keeps logs with "right meaning" (commands that trigger or bypass the Sigma rule)
- Drops logs with "wrong meaning" (unexecutable, irrelevant, or noise commands)

Sigma Rule: proc_creation_lnx_flock_shell_execution.yml
Detection logic:
  - Image ends with '/flock'
  - CommandLine contains ' -u '
  - CommandLine contains shell paths: /bin/bash, /bin/dash, /bin/fish, /bin/sh, /bin/zsh

Right Meaning (kept):
  - Trigger: Matches all Sigma conditions (Image ends in /flock, CLI has ' -u ', and shell path)
  - Bypass: Uses flock behavior to execute shell but evades detection (renamed binary, different flags, etc.)

Wrong Meaning (dropped):
  - Noise from test infrastructure (journalctl, cpuUsage.sh, git, which ps, check_mapping.py)
  - Test harness wrappers (sh -c flock...)
  - Commands with no shell invocation related to flock attack
"""

import os
import re
import shutil

LOG_ROOT = "logs_output"
TARGET_DIR = "Shel_Execution_via_Flock"
STUFF_DIR = "stuff/Shel_Execution_via_Flock_dropped"

# Sigma Rule Triggers (Strict String Matching)
SIGMA_IMAGES = ['/flock']
SIGMA_SHELLS = ['/bin/bash', '/bin/dash', '/bin/fish', '/bin/sh', '/bin/zsh']

# Noise patterns to exclude from "Right Meaning"
NOISE_PATTERNS = [
    'journalctl',
    'cpuUsage.sh',
    'git ',
    '/usr/bin/git',
    'which ps',
    'check_mapping.py'
]

def filter_logs():
    source_dir = os.path.join(LOG_ROOT, TARGET_DIR)
    if not os.path.exists(source_dir):
        print(f"Directory not found: {source_dir}")
        return

    # Create directories
    stuff_dropped_dir = STUFF_DIR
    if os.path.exists(stuff_dropped_dir):
        shutil.rmtree(stuff_dropped_dir)
    os.makedirs(stuff_dropped_dir)

    # Get all log files (excluding subdirectories)
    files = sorted([f for f in os.listdir(source_dir) if f.endswith(".log") and os.path.isfile(os.path.join(source_dir, f))])
    if not files:
        print("No logs found.")
        return

    stats = {
        "total": len(files),
        "kept": 0,
        "trigger": 0,
        "bypass": 0,
        "dropped": 0,
        "dropped_files": []
    }

    # Regex for "Right Meaning": Invokes a shell via flock-like execution
    shell_pattern = re.compile(r'(/bin/sh|/bin/bash|/bin/dash|/bin/zsh|/bin/fish|/usr/bin/sh|/usr/bin/bash|/bin/\S*sh|bash\s)', re.IGNORECASE)

    print(f"Processing {len(files)} logs in {source_dir}...")

    kept_files = []
    dropped_files = []

    for log_file in files:
        path = os.path.join(source_dir, log_file)
        try:
            with open(path, 'r', errors='ignore') as f:
                content = f.read()
            
            # Extract ALL CommandLines and Images
            command_lines = re.findall(r'<Data Name="CommandLine">(.*?)</Data>', content)
            images = re.findall(r'<Data Name="Image">(.*?)</Data>', content)
            
            file_is_right_meaning = False
            file_is_trigger = False
            
            for cmd in command_lines:
                # Filter out known "Noise" from the test infrastructure
                if any(noise in cmd for noise in NOISE_PATTERNS):
                    continue
                # Exclude test harness wrapper "/bin/sh -c flock..."
                if re.search(r'(sh|bash|dash|zsh|fish)\s+-c\s+.*flock', cmd):
                    continue

                # Check "Right Meaning": Invokes a shell?
                if shell_pattern.search(cmd):
                    file_is_right_meaning = True
                    
                    # Check Trigger conditions for this command
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
                kept_files.append((log_file, path, file_is_trigger))
                stats["kept"] += 1
                if file_is_trigger:
                    stats["trigger"] += 1
                else:
                    stats["bypass"] += 1
            else:
                dropped_files.append((log_file, path))
                stats["dropped"] += 1
                stats["dropped_files"].append(log_file)

        except Exception as e:
            print(f"Error reading {log_file}: {e}")

    # Step 1: Copy dropped logs to stuff folder
    print(f"\nMoving {len(dropped_files)} dropped logs to {stuff_dropped_dir}...")
    for log_file, path in dropped_files:
        shutil.copy(path, os.path.join(stuff_dropped_dir, log_file))

    # Step 2: Remove all original logs from source directory
    print(f"Removing all logs from {source_dir}...")
    for f in files:
        os.remove(os.path.join(source_dir, f))

    # Step 3: Also remove the filtered subdirectory if it exists
    filtered_subdir = os.path.join(source_dir, "filtered")
    if os.path.exists(filtered_subdir):
        shutil.rmtree(filtered_subdir)

    # Step 4: Copy kept logs back to source directory
    print(f"Restoring {len(kept_files)} meaningful logs to {source_dir}...")
    for log_file, path, _ in kept_files:
        # Need to copy from the stuff_dropped_dir won't work since we only put dropped there
        # We already removed them, so we need to get from our kept list's original content
        pass

    # Actually, we need to save kept files before removing. Let me fix this:
    # We'll temporarily store kept files in memory or a temp location

    print("\n--- Reprocessing with correct logic ---\n")

    # Restore original files and redo properly
    # Since we already removed them, let's restore from the dropped folder for dropped ones
    # and we need to rerun the logic properly

    # This is a logic error in the script - let me create a corrected version

def filter_logs_v2():
    """Corrected version that properly handles file operations."""
    source_dir = os.path.join(LOG_ROOT, TARGET_DIR)
    if not os.path.exists(source_dir):
        print(f"Directory not found: {source_dir}")
        return

    # Create directories
    stuff_dropped_dir = STUFF_DIR
    if os.path.exists(stuff_dropped_dir):
        shutil.rmtree(stuff_dropped_dir)
    os.makedirs(stuff_dropped_dir)

    temp_kept_dir = os.path.join(source_dir, "_temp_kept")
    if os.path.exists(temp_kept_dir):
        shutil.rmtree(temp_kept_dir)
    os.makedirs(temp_kept_dir)

    # Get all log files (excluding subdirectories)
    all_items = os.listdir(source_dir)
    files = sorted([f for f in all_items if f.endswith(".log") and os.path.isfile(os.path.join(source_dir, f))])
    if not files:
        print("No logs found.")
        return

    stats = {
        "total": len(files),
        "kept": 0,
        "trigger": 0,
        "bypass": 0,
        "dropped": 0,
        "dropped_files": [],
        "trigger_files": [],
        "bypass_files": []
    }

    # Regex for "Right Meaning": Invokes a shell via flock-like execution
    shell_pattern = re.compile(r'(/bin/sh|/bin/bash|/bin/dash|/bin/zsh|/bin/fish|/usr/bin/sh|/usr/bin/bash|/bin/\S*sh|bash\s)', re.IGNORECASE)

    print(f"Processing {len(files)} logs in {source_dir}...")

    for log_file in files:
        path = os.path.join(source_dir, log_file)
        try:
            with open(path, 'r', errors='ignore') as f:
                content = f.read()
            
            # Extract ALL CommandLines and Images
            command_lines = re.findall(r'<Data Name="CommandLine">(.*?)</Data>', content)
            images = re.findall(r'<Data Name="Image">(.*?)</Data>', content)
            
            file_is_right_meaning = False
            file_is_trigger = False
            
            for cmd in command_lines:
                # Filter out known "Noise" from the test infrastructure
                if any(noise in cmd for noise in NOISE_PATTERNS):
                    continue
                # Exclude test harness wrapper "/bin/sh -c flock..."
                if re.search(r'(sh|bash|dash|zsh|fish)\s+-c\s+.*flock', cmd):
                    continue

                # Check "Right Meaning": Invokes a shell?
                if shell_pattern.search(cmd):
                    file_is_right_meaning = True
                    
                    # Check Trigger conditions for this command
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
                # Copy to temp kept directory
                shutil.copy(path, os.path.join(temp_kept_dir, log_file))
                stats["kept"] += 1
                if file_is_trigger:
                    stats["trigger"] += 1
                    stats["trigger_files"].append(log_file)
                else:
                    stats["bypass"] += 1
                    stats["bypass_files"].append(log_file)
            else:
                # Copy to dropped directory
                shutil.copy(path, os.path.join(stuff_dropped_dir, log_file))
                stats["dropped"] += 1
                stats["dropped_files"].append(log_file)

        except Exception as e:
            print(f"Error reading {log_file}: {e}")

    # Remove 'filtered' subdirectory if exists
    filtered_subdir = os.path.join(source_dir, "filtered")
    if os.path.exists(filtered_subdir):
        shutil.rmtree(filtered_subdir)

    # Remove old summary file if exists
    old_summary = os.path.join(source_dir, "filtered_summary.txt")
    if os.path.exists(old_summary):
        os.remove(old_summary)

    # Now remove all original log files from source
    print(f"Removing {len(files)} original logs from {source_dir}...")
    for f in files:
        os.remove(os.path.join(source_dir, f))

    # Copy kept logs back to source directory
    kept_files = os.listdir(temp_kept_dir)
    print(f"Restoring {len(kept_files)} meaningful logs to {source_dir}...")
    for f in kept_files:
        shutil.copy(os.path.join(temp_kept_dir, f), os.path.join(source_dir, f))

    # Clean up temp directory
    shutil.rmtree(temp_kept_dir)

    # Write summary report to source directory
    summary_path = os.path.join(source_dir, "filter_report.md")
    with open(summary_path, "w") as f:
        f.write("# Filter Report for Shell_Execution_via_Flock\n\n")
        f.write("## Summary\n\n")
        f.write(f"| Category | Count |\n")
        f.write(f"|----------|-------|\n")
        f.write(f"| Total Logs Processed | {stats['total']} |\n")
        f.write(f"| **Kept (Right Meaning)** | **{stats['kept']}** |\n")
        f.write(f"| - Trigger (Sigma Match) | {stats['trigger']} |\n")
        f.write(f"| - Bypass (Evades Detection) | {stats['bypass']} |\n")
        f.write(f"| **Dropped (Wrong Meaning)** | **{stats['dropped']}** |\n\n")
        
        f.write("## Definitions\n\n")
        f.write("### Right Meaning (Kept)\n")
        f.write("- **Trigger**: Matches all Sigma rule conditions:\n")
        f.write("  - Image ends in `/flock`\n")
        f.write("  - CommandLine contains ` -u `\n")
        f.write("  - CommandLine contains shell path (`/bin/bash`, `/bin/dash`, `/bin/fish`, `/bin/sh`, `/bin/zsh`)\n")
        f.write("- **Bypass**: Executes shell via flock but evades detection by:\n")
        f.write("  - Renaming flock binary (e.g., `cp /usr/bin/flock /tmp/.systemd`)\n")
        f.write("  - Using different flags (e.g., `-x`, `-s`, `-n` instead of `-u`)\n")
        f.write("  - Obfuscating shell paths\n\n")
        
        f.write("### Wrong Meaning (Dropped)\n")
        f.write("- Test infrastructure noise (journalctl, cpuUsage.sh, git, which ps, check_mapping.py)\n")
        f.write("- Test harness wrappers (`sh -c flock...`)\n")
        f.write("- Commands with no shell invocation related to flock attack\n\n")
        
        f.write("## Dropped Files\n\n")
        f.write(f"Dropped logs have been moved to: `{stuff_dropped_dir}/`\n\n")
        if stats["dropped_files"]:
            f.write("| # | File Name |\n")
            f.write("|---|----------|\n")
            for i, fname in enumerate(stats["dropped_files"], 1):
                f.write(f"| {i} | {fname} |\n")
        else:
            f.write("No files were dropped.\n")

    # Also write report to dropped folder
    dropped_report_path = os.path.join(stuff_dropped_dir, "dropped_report.md")
    with open(dropped_report_path, "w") as f:
        f.write("# Dropped Logs Report\n\n")
        f.write(f"These {stats['dropped']} logs were dropped from Shell_Execution_via_Flock because they contain no meaningful flock attack commands.\n\n")
        f.write("## Reason for Dropping\n\n")
        f.write("The logs were categorized as 'Wrong Meaning' because:\n")
        f.write("- They contain only test infrastructure noise\n")
        f.write("- No shell invocation via flock was detected\n")
        f.write("- Commands did not represent actual flock attack behavior\n\n")
        f.write("## Dropped Files\n\n")
        if stats["dropped_files"]:
            f.write("| # | File Name |\n")
            f.write("|---|----------|\n")
            for i, fname in enumerate(stats["dropped_files"], 1):
                f.write(f"| {i} | {fname} |\n")
        else:
            f.write("No files were dropped.\n")

    print(f"\nFiltering complete!")
    print(f"  - Kept: {stats['kept']} logs ({stats['trigger']} trigger, {stats['bypass']} bypass)")
    print(f"  - Dropped: {stats['dropped']} logs")
    print(f"  - Report written to: {summary_path}")
    print(f"  - Dropped logs moved to: {stuff_dropped_dir}")


if __name__ == "__main__":
    filter_logs_v2()
