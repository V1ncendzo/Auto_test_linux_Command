# Filtering Report: Linux Crypto Mining Indicators

**Date**: 2026-01-17
**Filtered By**: Antigravity

## Summary
- **Total Logs**: 186
- **Kept**: 186 (100.0%)
- **Dropped**: 0 (0.0%)

## Filtering Logic
Logs were retained if they contained Sysmon Process Creation events with either:
1.  **Mining Parameters**: Flags like `--cpu-priority`, `stratum+tcp://`, `--donate-level`, etc.
2.  **MSR Modification**: Commands enabling Model Specific Registers (MSR) via `modprobe` or `allow_writes`, which is a prerequisite for RandomX (Monero) mining.

## Conclusion
All 186 logs in the dataset were found to contain valid indicators of crypto mining activity or preparation. No logs were discarded.
