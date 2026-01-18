# Filter Report for Shell_Execution_via_Flock

## Summary

| Category | Count |
|----------|-------|
| Total Logs Processed | 390 |
| **Kept (Right Meaning)** | **385** |
| - Trigger (Sigma Match) | 81 |
| - Bypass (Evades Detection) | 304 |
| **Dropped (Wrong Meaning)** | **5** |

## Definitions

### Right Meaning (Kept)
- **Trigger**: Matches all Sigma rule conditions:
  - Image ends in `/flock`
  - CommandLine contains ` -u `
  - CommandLine contains shell path (`/bin/bash`, `/bin/dash`, `/bin/fish`, `/bin/sh`, `/bin/zsh`)
- **Bypass**: Executes shell via flock but evades detection by:
  - Renaming flock binary (e.g., `cp /usr/bin/flock /tmp/.systemd`)
  - Using different flags (e.g., `-x`, `-s`, `-n` instead of `-u`)
  - Obfuscating shell paths

### Wrong Meaning (Dropped)
- Test infrastructure noise (journalctl, cpuUsage.sh, git, which ps, check_mapping.py)
- Test harness wrappers (`sh -c flock...`)
- Commands with no shell invocation related to flock attack

## Dropped Files

Dropped logs have been moved to: `stuff/Shel_Execution_via_Flock_dropped/`

| # | File Name |
|---|----------|
| 1 | Shel_Execution_via_Flock_attack15.log |
| 2 | Shel_Execution_via_Flock_attack26.log |
| 3 | Shel_Execution_via_Flock_attack261.log |
| 4 | Shel_Execution_via_Flock_attack36.log |
| 5 | Shel_Execution_via_Flock_attack47.log |
