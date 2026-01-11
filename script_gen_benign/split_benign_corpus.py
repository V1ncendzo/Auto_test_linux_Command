#!/usr/bin/env python3
import argparse
import random
from pathlib import Path

def read_lines(p: Path):
    lines = []
    with p.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if s:
                lines.append(s)
    return lines

def write_lines(p: Path, lines):
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8", newline="\n") as f:
        for s in lines:
            f.write(s + "\n")

def main():
    ap = argparse.ArgumentParser(description="Split benign_all.txt into train/validate")
    ap.add_argument(
        "--in-file",
        default=r".\socbed\process_creation\all\benign_all.txt",
        help="Input file (default matches your folder structure)",
    )
    ap.add_argument(
        "--out-train",
        default=r".\socbed\process_creation\train\benign_train.txt",
        help="Train output file",
    )
    ap.add_argument(
        "--out-validate",
        default=r".\socbed\process_creation\validate\benign_validate.txt",
        help="Validate output file (note: your folder is named 'validate')",
    )
    ap.add_argument("--train-ratio", type=float, default=0.8, help="e.g. 0.8")
    ap.add_argument("--seed", type=int, default=20260111, help="shuffle seed")
    ap.add_argument("--dedup", action="store_true", help="deduplicate before split")
    args = ap.parse_args()

    in_path = Path(args.in_file)

    if not in_path.exists():
        raise SystemExit(f"Input file not found: {in_path.resolve()}")

    lines = read_lines(in_path)

    if args.dedup:
        # dedup but keep initial order (deterministic)
        lines = list(dict.fromkeys(lines))

    rng = random.Random(args.seed)
    rng.shuffle(lines)

    n_total = len(lines)
    n_train = int(n_total * args.train_ratio)

    train_lines = lines[:n_train]
    val_lines = lines[n_train:]

    write_lines(Path(args.out_train), train_lines)
    write_lines(Path(args.out_validate), val_lines)

    print(f"Input : {in_path}")
    print(f"Total : {n_total}")
    print(f"Train : {len(train_lines)} -> {Path(args.out_train)}")
    print(f"Valid : {len(val_lines)} -> {Path(args.out_validate)}")

if __name__ == "__main__":
    main()
