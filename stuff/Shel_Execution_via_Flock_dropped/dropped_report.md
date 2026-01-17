# Dropped Logs Report

These 5 logs were dropped from Shell_Execution_via_Flock because they contain no meaningful flock attack commands.

## Reason for Dropping

The logs were categorized as 'Wrong Meaning' because:
- They contain only test infrastructure noise
- No shell invocation via flock was detected
- Commands did not represent actual flock attack behavior

## Dropped Files

| # | File Name |
|---|----------|
| 1 | Shel_Execution_via_Flock_attack15.log |
| 2 | Shel_Execution_via_Flock_attack26.log |
| 3 | Shel_Execution_via_Flock_attack261.log |
| 4 | Shel_Execution_via_Flock_attack36.log |
| 5 | Shel_Execution_via_Flock_attack47.log |
