# AMIDES Linux Data Generation & Rule Improvement Project

## Project Overview

This project is tailored to support the **AMIDES** ecosystem by automating the generation of high-quality Linux security datasets and improving SIEM detection rules. The pipeline automates attack simulation, log collection, noise filtering, detection analysis, and data normalization into AMIDES format.

## Prerequisites

- **OS**: Linux (Ubuntu 20.04+ recommended) or Windows (for remote analysis).
- **Python**: 3.8+
- **Sysmon for Linux**: Must be installed and running.
- **Root/Sudo Privileges**: Required for log collection.

## Directory Structure

| Directory / File | Description |
| :--- | :--- |
| `attack_commands/` | **Input**: Attack logic (`.txt` files). |
| `logs_output/` | **Output**: Raw Sysmon logs (`.log`). |
| `process_creation_sigmahq/` | **Rules**: Sigma rules (`.yml`) under test. |
| `linux_data/` | **Final Data**: AMIDES-compatible JSON events. |
| `1_collect_logs.py` | **Step 1**: Run attacks & collect logs. |
| `2_filter_logs.py` | **Step 2**: specific log filtering (e.g., reduce noise or keep only relevant events). |
| `3_generate_report.py` | **Step 3**: Compare logs vs. detection to find Bypasses. |
| `4_build_all_events.py` | **Step 4**: Batch convert logs to AMIDES format. |
| `generate_process_creation_report.py` | **Reporting**: Generate Markdown/JSON stats for the final dataset. |

## Workflow Guide

### 1. Attack Simulation & Log Collection
Run attack commands to generate raw Sysmon logs.
```bash
sudo python3 1_collect_logs.py
```
*   Select the target attack file.
*   Logs are saved to `logs_output/<Rule_Name>/`.

### 2. Log Filtering (Optional but Recommended)
Filter raw logs to remove noise or isolate specific attack patterns.
```bash
python3 2_filter_logs.py
```
*   Applies rules defined in the script (e.g., removing `crontab -l` noise).
*   Filtered logs are stored in `logs_output/<Rule_Name>/filtered/`.

### 3. Detection & Reporting
Analyze which attacks were detected (Triggered) vs. missed (Bypass).
```bash
python3 3_generate_report.py
```
*   Generates a `Report_<Rule_Name>.csv` showing results for each command.
*   Use this to identify weak rules that need improvement in `process_creation_sigmahq/`.

### 4. AMIDES Data Generation (Batch)
Convert valid logs (Match/Evasion) into the final AMIDES JSON format.
```bash
python3 4_build_all_events.py
```
*   Automatically scans `process_creation_sigmahq/` for rules.
*   Matches them with `logs_output/` and `Report_*.csv`.
*   Outputs standardized JSON events to `linux_data/sigma/events/linux/process_creation/`.
*   Generates `properties.yml` for the dataset.

### 5. Final Dataset Reporting
Generate a comprehensive statistical report of the generated AMIDES data.
```bash
python3 generate_process_creation_report.py
```
*   Produces `process_creation_report.md` (readable summary) and `process_creation_summary.json`.
*   Use this to verify the quality and coverage of your dataset.

## Advanced Tools

-   **`sysmon_behavior_matcher.py`**: Behavioral analysis to match logs against a baseline.
-   **`filter_output.py`**: Verify if attack commands actually executed successfully (checking stdout/stderr).
-   **`fix_amides_event_filenames.py`**: Helper to standardize output filenames (called automatically by Step 4).
