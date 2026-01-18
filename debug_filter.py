
import re
import os

log_file = "logs_output/Shel_Execution_via_Flock/Shel_Execution_via_Flock_attack200.log"
shell_pattern = re.compile(r'(/bin/sh|/bin/bash|/bin/dash|/bin/zsh|/bin/fish|/usr/bin/sh|/usr/bin/bash|/bin/\W*sh|bash\s)', re.IGNORECASE)

with open(log_file, 'r') as f:
    content = f.read()

# Extract CommandLines (simplified regex extraction for demo)
# In real script it parses XML-like manually
command_lines = re.findall(r'CommandLine">([^<]+)<', content)

print(f"Checking {log_file}...")
for cmd in command_lines:
    # Apply noise filter
    if any(noise in cmd for noise in ['journalctl', 'cpuUsage.sh', 'git ', '/usr/bin/git', 'which ps', 'check_mapping.py']):
        print(f"Skipping Noise: {cmd}")
        continue
    if re.search(r'(sh|bash|dash|zsh|fish)\s+-c\s+.*flock', cmd):
        print(f"Skipping Harness: {cmd}")
        continue

    match = shell_pattern.search(cmd)
    if match:
        print(f"MATCH: '{cmd}' matches '{match.group(0)}'")
    else:
        print(f"No match: {cmd}")
