import os
import shutil

def map_and_copy_reports(src_dir, dest_base_dir):
    """
    Maps report filenames (Report_<Rule_Name>.csv) to destination folders and copies them.
    """
    if not os.path.exists(dest_base_dir):
        print(f"Error: Destination base directory {dest_base_dir} does not exist.")
        return

    # Get list of existing folders in dest_base_dir
    dest_folders = [d for d in os.listdir(dest_base_dir) if os.path.isdir(os.path.join(dest_base_dir, d))]
    print(f"Target folders: {dest_folders}")

    # Standardize names for comparison (consistent with rule copy script)
    def standardize(name):
        return name.replace(" ", "_").replace("-", "_").lower()

    standardized_dest = {standardize(d): d for d in dest_folders}

    # Iterate through CSV files in src_dir
    csv_files = [f for f in os.listdir(src_dir) if f.startswith("Report_") and f.endswith(".csv")]
    
    copied_count = 0
    for file_name in csv_files:
        src_path = os.path.join(src_dir, file_name)
        
        # Remove "Report_" and ".csv"
        rule_name_part = file_name[len("Report_"):-len(".csv")]
        std_name = standardize(rule_name_part)
        
        # In case the report name has extra parts like "Discovery_-_Linux" vs folder "Discovery"
        # We try to match the standardized part.
        
        if std_name in standardized_dest:
            folder_name = standardized_dest[std_name]
            dest_path = os.path.join(dest_base_dir, folder_name, file_name)
            shutil.copy2(src_path, dest_path)
            print(f"Copied '{file_name}' to {folder_name}/")
            copied_count += 1
        else:
            # Try partial matching if needed, but let's see if exact standardized match works first.
            # Some reports have "Discovery_-_Linux" but folder is "Discovery"? 
            # No, let's check the listing again.
            pass

    print(f"Successfully copied {copied_count} reports.")

if __name__ == "__main__":
    SRC_DIR = "/home/vincenzolog/Auto_test/report"
    DEST_BASE_DIR = "/home/vincenzolog/Auto_test/fixed_rule_process_creation"
    map_and_copy_reports(SRC_DIR, DEST_BASE_DIR)
