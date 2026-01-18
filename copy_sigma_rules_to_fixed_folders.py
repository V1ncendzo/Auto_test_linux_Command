import os
import shutil
import yaml

def map_and_copy_rules(src_dir, dest_base_dir):
    """
    Maps rule titles from Sigma YAML files to destination folders and copies them.
    """
    if not os.path.exists(dest_base_dir):
        print(f"Error: Destination directory {dest_base_dir} does not exist.")
        return

    # Get list of existing folders in dest_base_dir
    dest_folders = [d for d in os.listdir(dest_base_dir) if os.path.isdir(os.path.join(dest_base_dir, d))]
    print(f"Target folders: {dest_folders}")

    # Standardize names for comparison
    def standardize(name):
        return name.replace(" ", "_").replace("-", "_").lower()

    standardized_dest = {standardize(d): d for d in dest_folders}

    # Iterate through YAML files in src_dir
    yaml_files = [f for f in os.listdir(src_dir) if f.endswith(".yml")]
    
    copied_count = 0
    for file_name in yaml_files:
        src_path = os.path.join(src_dir, file_name)
        try:
            with open(src_path, 'r', encoding='utf-8') as f:
                # Use safe_load to avoid security issues with untrusted YAML
                rule_data = yaml.safe_load(f)
                if not rule_data or 'title' not in rule_data:
                    continue
                
                title = rule_data['title']
                normalized_title = title.replace(" - Linux", "")
                std_title = standardize(normalized_title)

                # Find match in standardized_dest
                if std_title in standardized_dest:
                    folder_name = standardized_dest[std_title]
                    dest_path = os.path.join(dest_base_dir, folder_name, file_name)
                    shutil.copy2(src_path, dest_path)
                    print(f"Copied '{title}' to {folder_name}/")
                    copied_count += 1
                else:
                    # Special case for "OS Architecture Discovery Via Grep" vs "OS-Architecture_Discovery_Via_Grep"
                    # My standardize covers this if I treat dash and underscore equally.
                    # Let's see if there are any others.
                    pass
        except Exception as e:
            print(f"Error processing {file_name}: {e}")

    print(f"Successfully copied {copied_count} rules.")

if __name__ == "__main__":
    SRC_DIR = "/home/vincenzolog/Auto_test/process_creation_sigmahq"
    DEST_BASE_DIR = "/home/vincenzolog/Auto_test/fixed_rule_process_creation"
    map_and_copy_rules(SRC_DIR, DEST_BASE_DIR)
