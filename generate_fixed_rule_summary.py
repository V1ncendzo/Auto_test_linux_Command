import csv
import glob
import os

def generate_summary_report():
    input_dir = "report_fixed_rule"
    output_file = os.path.join(input_dir, "Summary_Fixed_Rule_Report.csv")
    
    file_pattern = os.path.join(input_dir, "Report_Fixed_*.csv")
    files = glob.glob(file_pattern)
    files.sort()
    
    if not files:
        print(f"No report files found in {input_dir}")
        return

    print(f"Processing {len(files)} files...")
    
    summary_data = []
    
    # Track totals
    total_cmds_all = 0
    match_events_all = 0
    evasion_events_all = 0
    total_training_all = 0

    for file_path in files:
        try:
            basename = os.path.basename(file_path)
            # Check if this is the summary file itself to avoid circular read if running multiple times
            if basename == "Summary_Fixed_Rule_Report.csv":
                continue
                
            rule_name = basename.replace("Report_Fixed_", "").replace(".csv", "")
            
            # Manual CSV reading
            rows = []
            with open(file_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                if 'Result' not in reader.fieldnames:
                    print(f"[WARN] Skipping {basename}: No 'Result' column.")
                    continue
                for row in reader:
                    rows.append(row)
            
            match_events = 0
            evasion_events = 0
            error_events = 0
            
            for row in rows:
                res = row.get('Result', '')
                if not res: continue
                
                if res.startswith('Trigger'):
                    match_events += 1
                elif 'Bypass' in res:
                    evasion_events += 1
                elif 'Error' in res:
                    error_events += 1
            
            total_training = match_events + evasion_events
            total_commands = match_events + evasion_events + error_events
            
            bypass_rate = (evasion_events / total_training * 100) if total_training > 0 else 0.0
            
            summary_data.append({
                'Rule Name': rule_name,
                'Command Count (Summarize)': total_commands,
                'Match Events (Trigger)': match_events,
                'Evasion Events (Bypass)': evasion_events,
                'Total Training Events (Match + Evasion)': total_training,
                'Bypass Rate (%)': f"{bypass_rate:.2f}"
            })
            
            # Add to totals
            total_cmds_all += total_commands
            match_events_all += match_events
            evasion_events_all += evasion_events
            total_training_all += total_training

        except Exception as e:
            print(f"[ERROR] Processing {file_path}: {e}")

    # Add Total Row
    bypass_rate_total = (evasion_events_all / total_training_all * 100) if total_training_all > 0 else 0.0
    summary_data.append({
        'Rule Name': 'TOTAL',
        'Command Count (Summarize)': total_cmds_all,
        'Match Events (Trigger)': match_events_all,
        'Evasion Events (Bypass)': evasion_events_all,
        'Total Training Events (Match + Evasion)': total_training_all,
        'Bypass Rate (%)': f"{bypass_rate_total:.2f}"
    })

    # Write Output
    if summary_data:
        headers = [
            'Rule Name', 
            'Command Count (Summarize)', 
            'Match Events (Trigger)', 
            'Evasion Events (Bypass)', 
            'Total Training Events (Match + Evasion)', 
            'Bypass Rate (%)'
        ]
        
        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                writer.writeheader()
                writer.writerows(summary_data)
                
            print(f"\n[SUCCESS] Summary report generated: {output_file}")
            
            # Print table
            # Simple print
            header_fmt = "{:<50} {:<15} {:<15} {:<15} {:<20} {:<15}"
            row_fmt = "{:<50} {:<15} {:<15} {:<15} {:<20} {:<15}"
            print("-" * 130)
            print(header_fmt.format(*headers))
            print("-" * 130)
            for item in summary_data:
                print(row_fmt.format(
                    item['Rule Name'][:45],
                    item['Command Count (Summarize)'],
                    item['Match Events (Trigger)'],
                    item['Evasion Events (Bypass)'],
                    item['Total Training Events (Match + Evasion)'],
                    item['Bypass Rate (%)']
                ))
            print("-" * 130)
            
        except Exception as e:
            print(f"[ERROR] Writing summary: {e}")
    else:
        print("No valid data to report.")

if __name__ == "__main__":
    generate_summary_report()
