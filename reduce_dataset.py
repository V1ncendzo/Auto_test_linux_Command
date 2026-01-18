import os
import random
import shutil

# Paths
base_dir = "linux_data/socbed/process_creation"
train_path = os.path.join(base_dir, "train")
val_path = os.path.join(base_dir, "validation")
all_path = os.path.join(base_dir, "all")

# Target counts
TRAIN_COUNT = 6000
VAL_COUNT = 4000

def backup_file(path):
    if os.path.exists(path):
        backup_path = path + ".bak"
        shutil.copy2(path, backup_path)
        print(f"Backed up {path} to {backup_path}")
    else:
        print(f"Warning: {path} does not exist!")

def sample_file(path, target_count):
    if not os.path.exists(path):
        print(f"Error: {path} not found.")
        return []

    with open(path, 'r') as f:
        lines = f.readlines()

    current_count = len(lines)
    print(f"Reading {path}: {current_count} lines found.")

    if current_count <= target_count:
        print(f"Warning: {path} has fewer or equal lines than target ({current_count} <= {target_count}). Keeping all lines.")
        return lines

    sampled_lines = random.sample(lines, target_count)
    print(f"Sampled {len(sampled_lines)} lines from {path}.")
    return sampled_lines

def write_lines(path, lines):
    with open(path, 'w') as f:
        f.writelines(lines)
    print(f"Wrote {len(lines)} lines to {path}")

def main():
    # 1. Backup
    backup_file(train_path)
    backup_file(val_path)
    backup_file(all_path)

    # 2. Sample Train
    train_lines = sample_file(train_path, TRAIN_COUNT)

    # 3. Sample Validation
    val_lines = sample_file(val_path, VAL_COUNT)

    # 4. Write back sampled data
    write_lines(train_path, train_lines)
    write_lines(val_path, val_lines)

    # 5. Regenerate 'all'
    all_lines = train_lines + val_lines
    write_lines(all_path, all_lines)

    # 6. Verification
    print("\nVerification:")
    print(f"Train lines: {len(train_lines)}")
    print(f"Validation lines: {len(val_lines)}")
    print(f"All lines: {len(all_lines)}")

if __name__ == "__main__":
    main()
