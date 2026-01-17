#!/usr/bin/env python3
import csv
import glob
import os

def generate_summary():
    report_dir = "report"
    files = sorted(glob.glob(os.path.join(report_dir, "Report_*.csv")))
    
    if not files:
        print(f"No Report_*.csv files found in {report_dir}")
        return

    print(f"Processing {len(files)} files found in {report_dir}...")

    summary_rows = []
    
    # Header for the summary
    headers = ["Rule Name", "Total Commands", "Triggered", "Bypassed", "Errors", "Bypass Rate (%)"]

    for file_path in files:
        try:
            filename = os.path.basename(file_path)
            # Extrapolate rule name
            # Report_Rule_Name.csv -> Rule_Name
            rule_name = filename[7:-4] 
            
            total = 0
            triggered = 0
            bypassed = 0
            errors = 0
            
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Skip if not a valid data row (sometimes summary tables are appended at bottom)
                    result = row.get("Result", "")
                    
                    # Stop if we hit the "=== SUMMARY REPORT ===" line if present
                    if "=== SUMMARY REPORT ===" in str(row):
                        break
                        
                    # Basic classification
                    res_lower = result.lower()
                    if "trigger" in res_lower:
                        triggered += 1
                    elif "bypass" in res_lower:
                        bypassed += 1
                    elif "error" in res_lower:
                        errors += 1
                        
            total = triggered + bypassed + errors
            
            valid_samples = triggered + bypassed
            rate = (bypassed / valid_samples * 100.0) if valid_samples > 0 else 0.0
            
            summary_rows.append({
                "Rule Name": rule_name,
                "Total Commands": total,
                "Triggered": triggered,
                "Bypassed": bypassed,
                "Errors": errors,
                "Bypass Rate (%)": f"{rate:.2f}"
            })
            
        except Exception as e:
            print(f"Error processing {file_path}: {e}")

    # Calculate Totals
    grand_total = sum(r["Total Commands"] for r in summary_rows)
    grand_triggered = sum(r["Triggered"] for r in summary_rows)
    grand_bypassed = sum(r["Bypassed"] for r in summary_rows)
    grand_errors = sum(r["Errors"] for r in summary_rows)
    
    valid_grand = grand_triggered + grand_bypassed
    grand_rate = (grand_bypassed / valid_grand * 100.0) if valid_grand > 0 else 0.0
    
    # Output to CSV
    out_csv = os.path.join(report_dir, "Combined_Report_Summary.csv")
    with open(out_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(summary_rows)
        # Add Total Row
        writer.writerow({
            "Rule Name": "TOTAL",
            "Total Commands": grand_total,
            "Triggered": grand_triggered,
            "Bypassed": grand_bypassed,
            "Errors": grand_errors,
            "Bypass Rate (%)": f"{grand_rate:.2f}"
        })
        
    print(f"Created CSV summary: {out_csv}")

    # Output to Markdown
    out_md = os.path.join(report_dir, "Combined_Report_Summary.md")
    with open(out_md, 'w', encoding='utf-8') as f:
        f.write("# Combined Detection Report Summary\n\n")
        f.write(f"**Total Rules:** {len(files)}\n\n")
        
        # Table Header
        f.write("| Rule Name | Total | Triggered | Bypassed | Errors | Bypass Rate (%) |\n")
        f.write("|---|---|---|---|---|---|\n")
        
        for r in summary_rows:
            f.write(f"| {r['Rule Name']} | {r['Total Commands']} | {r['Triggered']} | {r['Bypassed']} | {r['Errors']} | {r['Bypass Rate (%)']} |\n")
            
        # Total Row in Bold
        f.write(f"| **TOTAL** | **{grand_total}** | **{grand_triggered}** | **{grand_bypassed}** | **{grand_errors}** | **{grand_rate:.2f}** |\n")

    print(f"Created Markdown summary: {out_md}")
    
    # Print table to console
    print("\n" + "="*80)
    print(f"{'Rule Name':<50} {'Total':<8} {'Trig':<8} {'Bypass':<8} {'Rate':<8}")
    print("-" * 80)
    for r in summary_rows:
        print(f"{r['Rule Name']:<50} {r['Total Commands']:<8} {r['Triggered']:<8} {r['Bypassed']:<8} {r['Bypass Rate (%)']:<8}")
    print("-" * 80)
    print(f"{'TOTAL':<50} {grand_total:<8} {grand_triggered:<8} {grand_bypassed:<8} {grand_rate:.2f}")
    print("="*80 + "\n")

if __name__ == "__main__":
    generate_summary()
