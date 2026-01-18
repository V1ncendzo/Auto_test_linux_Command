import os

# Paths
base_dir = "linux_data/socbed/process_creation"
train_path = os.path.join(base_dir, "train")
val_path = os.path.join(base_dir, "validation")
all_path = os.path.join(base_dir, "all")

def load_lines_set(path):
    if not os.path.exists(path):
        print(f"Error: {path} not found.")
        return set()
    with open(path, 'r') as f:
        return set(line.strip() for line in f)

def main():
    print("Loading files...")
    train_set = load_lines_set(train_path)
    val_set = load_lines_set(val_path)
    all_set = load_lines_set(all_path)
    
    print(f"Train unique count: {len(train_set)}")
    print(f"Validation unique count: {len(val_set)}")
    print(f"All unique count: {len(all_set)}")

    # Check subsets
    train_subset = train_set.issubset(all_set)
    val_subset = val_set.issubset(all_set)
    
    print(f"\nIs Train a subset of All? {train_subset}")
    if not train_subset:
        missing = len(train_set - all_set)
        print(f"  FAILED: {missing} lines from Train are missing in All")

    print(f"Is Validation a subset of All? {val_subset}")
    if not val_subset:
        missing = len(val_set - all_set)
        print(f"  FAILED: {missing} lines from Validation are missing in All")

    # Check if All is exactly Train + Validation union
    union_set = train_set.union(val_set)
    all_equals_union = all_set == union_set
    print(f"Is All exactly Union(Train, Validation)? {all_equals_union}")
    
    if not all_equals_union:
        extra = len(all_set - union_set)
        missing = len(union_set - all_set)
        if extra > 0:
            print(f"  All has {extra} lines not in Train or Validation")
        if missing > 0:
            print(f"  Union has {missing} lines not in All")

if __name__ == "__main__":
    main()
