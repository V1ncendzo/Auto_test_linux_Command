import os
import json
import csv
import glob

def generate_counts_summary(base_dir, output_file):
    """
    Summarizes process creation events counts (Match vs Evasion) from separate subdirectories.
    """
    
    headers = [
        "Rule Name",
        "Match Events",
        "Evasion Events",
        "Total Events"
    ]

    data_rows = []

    print(f"Scanning directory: {base_dir}")

    # Walk through all subdirectories
    # We assume each subdirectory corresponds to a rule
    for root, dirs, files in os.walk(base_dir):
        # Skip the base dir itself if it has subdirs, we only care about the leaves or immediate children
        # But os.walk visits everything. Let's look at directories that contain JSON files.
        
        json_files = [f for f in files if f.endswith(".json")]
        if not json_files:
            continue

        match_count = 0
        evasion_count = 0
        rule_name = "Unknown"
        
        # Try to determine rule name from properties.yml or the first JSON file
        properties_path = os.path.join(root, "properties.yml")
        if os.path.exists(properties_path):
             # Simple parsing for properties.yml if needed, but JSON is more reliable for the full title usually
             pass
        
        # Read the first JSON to get the Rule Name
        first_json = os.path.join(root, json_files[0])
        try:
            with open(first_json, 'r', encoding='utf-8') as f:
                data = json.load(f)
                rule_name = data.get("labels", {}).get("sigma_rule_title", "Unknown")
        except:
            pass
            
        # If still unknown, use directory name as fallback
        if rule_name == "Unknown":
            rule_name = os.path.basename(root)

        for file in json_files:
            if "_Match_" in file:
                match_count += 1
            elif "_Evasion_" in file:
                evasion_count += 1
            else:
                # Fallback or other type? Let's count them based on content if needed, 
                # but file naming convention is strong here.
                # Inspecting file content to be sure?
                # For now, let's stick to filename as per plan, but maybe treat others as uncertain?
                # Actually, in the file listing we saw _Match_ and _Evasion_ predominantly.
                pass
        
        total_events = match_count + evasion_count
        
        data_rows.append([rule_name, match_count, evasion_count, total_events])

    # Sort by Rule Name for better readability
    data_rows.sort(key=lambda x: x[0])

    print(f"Found {len(data_rows)} rules.")
    
    # Write to CSV
    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(data_rows)
        print(f"Successfully generated summary report: {output_file}")
    except Exception as e:
        print(f"Failed to write CSV file: {e}")

if __name__ == "__main__":
    BASE_DIR = "/home/vincenzolog/Auto_test/linux_data/sigma/events/linux/process_creation"
    OUTPUT_FILE = "process_creation_counts.csv"
    generate_counts_summary(BASE_DIR, OUTPUT_FILE)
