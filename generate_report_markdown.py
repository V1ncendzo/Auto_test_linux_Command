import csv
import glob
import os

def generate_markdown_table():
    files = glob.glob("Report_*.csv")
    files.sort()
    
    if not files:
        print("No Report_*.csv files found.")
        return

    # Table Header
    output = []
    output.append("## 6. Detailed Rule Breakdown")
    output.append("")
    output.append("| Rule Name | Total Logs | Triggers | Bypasses | Bypass Rate |")
    output.append("| :--- | :--- | :--- | :--- | :--- |")

    total_logs = 0
    total_triggers = 0
    total_bypasses = 0

    for file_path in files:
        if "Summary_Report.csv" in file_path:
            continue

        rule_name = os.path.basename(file_path).replace("Report_", "").replace(".csv", "")
        
        triggers = 0
        bypasses = 0
        meaningful_logs = 0
        has_summary = False
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.readlines()
            
            # 1. Try to parsing SUMMARY REPORT section first
            for i, line in enumerate(lines):
                if "=== SUMMARY REPORT ===" in line:
                    has_summary = True
                    # Look ahead for stats
                    # Expected format:
                    # Total Meaningful Logs (Denominator),360,,,
                    # Triggered Target (Detections),110,,,
                    # Bypass Logs (Numerator),250,,,
                    
                    found_stats = 0
                    for j in range(i+1, min(i+10, len(lines))):
                        parts = lines[j].split(',')
                        if len(parts) < 2: continue
                        
                        key = parts[0].strip()
                        val_str = parts[1].strip()
                        
                        if "Total Meaningful Logs" in key:
                            val_str = val_str.split('/')[0].strip().split(' ')[0] # Handle "250 / 360" if present, though typically just number
                            try: meaningful_logs = int(val_str)
                            except: pass
                        elif "Triggered Target" in key:
                            try: triggers = int(val_str)
                            except: pass
                        elif "Bypass Logs" in key:
                            try: bypasses = int(val_str)
                            except: pass
                            
                    break
            
            # 2. Fallback to row counting if no summary
            if not has_summary:
                csv_lines = []
                for line in lines:
                    if "=== SUMMARY REPORT ===" in line: break
                    if line.strip(): csv_lines.append(line)
                
                reader = csv.reader(csv_lines)
                header = next(reader, None)
                
                cnt = 0
                trig = 0
                byp = 0
                for row in reader:
                    if not row or len(row) < 4: continue
                    res = row[3]
                    cnt += 1
                    if res.startswith("Trigger:"): trig += 1
                    elif "Bypass Target Rule" in res: byp += 1
                
                triggers = trig
                bypasses = byp
                meaningful_logs = cnt # In fallback, all rows are meaningful

            # Calculate Rate
            # If meaningful logs provided, use that. Else triggers+bypasses.
            # Ideally Trigger + Bypass + Missing = Meaningful.
            # Bypass Rate = Bypasses / Meaningful * 100
            
            # If meaningful_logs is 0 (parsing error), use sum
            if meaningful_logs == 0:
                meaningful_logs = triggers + bypasses

            rate = (bypasses / meaningful_logs * 100) if meaningful_logs > 0 else 0.0
            
            # Append row
            output.append(f"| `{rule_name}` | {meaningful_logs} | {triggers} | {bypasses} | **{rate:.1f}%** |")
            
            total_logs += meaningful_logs
            total_triggers += triggers
            total_bypasses += bypasses
            
        except Exception as e:
            output.append(f"| `{rule_name}` | Error | - | - | - |")
            print(f"Error parsing {file_path}: {e}")

    # Total Row
    overall_rate = (total_bypasses / (total_triggers + total_bypasses) * 100) if (total_triggers + total_bypasses) > 0 else 0.0
    output.append(f"| **TOTAL** | **{total_logs}** | **{total_triggers}** | **{total_bypasses}** | **{overall_rate:.1f}%** |")
    
    print("\n".join(output))

if __name__ == "__main__":
    generate_markdown_table()
