# AMIDES Linux Data Generation & Rule Improvement Project

## Project Overview

This project is tailored to support the **AMIDES** ecosystem by automating the generation of high-quality Linux security datasets and improving SIEM detection rules. The primary objectives are:

1.  **Attack Simulation**: Automate the execution of attack commands on Linux systems to generate real-world logs.
2.  **Detection Evaluation**: specific analysis of SIEM rule performance to identify "Bypass" scenarios (where attacks are executed but not detected) or "False Negatives".
3.  **Rule Improvement**: Facilitate the refinement of Sigma rules to close detection gaps.
4.  **AMIDES Data Generation**: Convert raw Sysmon for Linux logs into standardized AMIDES event JSON format for dataset publication or training.

## Prerequisites

- **OS**: Linux (Ubuntu 20.04+ recommended for testing) or Windows (if analyzing logs remotely).
- **Python**: 3.8+
- **Sysmon for Linux**: Must be installed and running on the test machine to capture `ProcessCreate` (Event ID 1) and other relevant events.
- **Root/Sudo Privileges**: Required to run `1_collect_logs.py` and restart Sysmon services.

## Directory Structure

| Directory / File | Description |
| :--- | :--- |
| `attack_commands/` | **Input**: Contains `.txt` files with list of attack commands to run (e.g., `Linux_Base64_Encoded_Shebang_In_CLI.txt`). |
| `logs_output/` | **Output**: Raw Sysmon logs generated after running attacks. Each rule gets its own folder. |
| `detection_results/` | **Intermediate**: Contains JSON results from your detection engine (e.g., after running the logs through a SIEM or sigma-cli). Used by the report generator. |
| `process_creation_sigmahq/` | **Rules**: Repository of Sigma rules (`.yml`) that are being tested and improved. |
| `amides_origin_data/` | **Reference**: Original AMIDES data/schema for validation (if applicable). |
| `linux_data/` | **Final Output**: Generated AMIDES-compatible JSON events stored here (e.g., `sigma/events/linux/...`). |
| `1_collect_logs.py` | **Script**: Automates attack execution and collects Sysmon logs. |
| `3_generate_report.py` | **Script**: compares executed commands vs. detection results to calculate Catch/Bypass rates. |
| `build_amides_events_from_report.py`| **Script**: Core converter that transforms Sysmon logs into AMIDES JSON events (Match/Evasion). |
| `sysmon_behavior_matcher.py` | **Script**: Advanced tool to match behavioral patterns in logs against a baseline (useful for filtering noise). |
| `filter_output.py` | **Script**: Utility to map success commands to output logs and verify correctness. |

## Workflow Guide

### 1. Attack Simulation & Log Collection

Use `1_collect_logs.py` to run attack commands and capture fresh logs.

**Steps:**
1.  Place your attack command lists in `attack_commands/*.txt`.
2.  Run the script with sudo:
    ```bash
    sudo python3 1_collect_logs.py
    ```
3.  Select the attack file from the menu.
4.  The script will:
    *   Ensure Sysmon is running.
    *   Execute each command in the file.
    *   Capture specific logs for that command into `logs_output/<Rule_Name>/`.

### 2. Detection & Reporting

After collecting logs, you (or your automated pipeline) must run them through your detection engine. The results should be saved as JSON files in `detection_results/<Rule_Name>/`.

Once detection results are ready, generate a summary report:

**Steps:**
1.  Run the reporting tool:
    ```bash
    python3 3_generate_report.py
    ```
2.  Select the project/rule you want to analyze.
3.  The script generates a CSV report (e.g., `Report_<Rule_Name>.csv`) containing:
    *   Command executed.
    *   Detection result: **Trigger** (Detected) or **Bypass** (Missed).
    *   Bypass Rate statistics.

### 3. Rule Improvement

Review the `Report_*.csv` file.
*   **If High Bypass Rate**: precise commands that failed detection are identified.
*   **Action**: Open the corresponding rule in `process_creation_sigmahq/` and modify the detection logic (e.g., add new keywords, fix regex, adjust selection criteria).
*   **Re-test**: Rerun Step 1 and 2 to verify the fix.

### 4. AMIDES Data Generation

Once you are satisfied with the logs and detection (or want to document the evasion), use `build_amides_events_from_report.py` to convert the raw logs into the AMIDES dataset format.

**Command:**
```bash
python3 build_amides_events_from_report.py \
  --report "Report_Linux_Base64_Encoded_Shebang_In_CLI.csv" \
  --logs-dir "logs_output/Linux_Base64_Encoded_Shebang_In_CLI" \
  --rule-dir-name "proc_creation_lnx_base64_shebang_cli" \
  --rule-title "Base64 Encoded Shebang In CLI" \
  --queried-event-type "Microsoft-Windows-Sysmon_1"
```

**What it does:**
*   Parses the CSV report.
*   Extracts the specific Sysmon Event ID 1 XML from the logs corresponding to each command.
*   Normalizes the data into flat JSON with AMIDES schema (including `process.command_line`, `process.executable`, etc.).
*   Classifies events as `_Match_` (Detected) or `_Evasion_` (Bypass) based on the report.
*   Outputs files to `sigma/events/linux/process_creation/<rule_dir_name>/`.

## Advanced Tools

-   **`sysmon_behavior_matcher.py`**: Use this if you need to compare your new logs against a "baseline" of normal behavior to filter out background noise, especially for high-volume log sources.
-   **`filter_output.py`**: Helps in validating if the attack commands actually executed successfully by checking their standard output/error, ensuring that a "Bypass" is a true detection failure and not just a failed command execution.
