#!/usr/bin/env python3
# sigmahq_to_amides_flat.py
#
# Convert SigmaHQ YAML -> AMIDES normalized YAML
# Output layout: flat files (AMIDES-style): <out_dir>/<amides_name>.yml
#
# Fixes in this version:
# - Support Sigma operators like CommandLine|contains|all
# - For condition "all of selection_*": combine anchors in stable order:
#   binary/executable first, then other tokens (avoid dd ordering bug)
# - If prefer-commandline=yes: ALWAYS output filter on process.command_line

import argparse
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

SIGMA_TO_AMIDES_FIELD = {
    "CommandLine": "process.command_line",
    "Image": "process.executable",
    "ParentImage": "process.parent.executable",
    "OriginalFileName": "process.pe.original_file_name",
}

SUPPORTED_OPS = {"contains", "startswith", "endswith", "equals"}

# common short/generic tokens to avoid becoming a lone anchor
GENERIC_TOKENS = {
    "bash", "sh", "zsh", "dash",
    "| bash", "|sh", "| sh", "|bash",
    "-d", "-c", "-h", "-v", "-q", "-x",
}


def normalize_tag(tag: str) -> str:
    return tag.replace("-", "_").strip()


def severity_from_level(level: Optional[str]) -> str:
    lvl = (level or "").strip().lower()
    return lvl if lvl in {"low", "medium", "high", "critical"} else "medium"


def slugify_lower(s: str) -> str:
    s = s.strip().lower()
    s = re.sub(r"[^\w\s-]", "", s, flags=re.UNICODE)
    s = s.replace("-", " ")
    s = re.sub(r"\s+", "_", s)
    s = re.sub(r"_+", "_", s)
    return s or "unnamed_rule"


def make_wildcard(value: str, op: str) -> str:
    if op == "endswith":
        return f"*{value}"
    if op == "startswith":
        return f"{value}*"
    if op == "contains":
        return f"*{value}*"
    return value


def safe_token(s: str) -> str:
    return s.replace('"', '\\"')


def basename_like(path_str: str) -> str:
    s = path_str.replace("\\", "/")
    if "/" in s:
        return s.split("/")[-1]
    return s


def is_short_flag(tok: str) -> bool:
    return bool(re.fullmatch(r"-[a-zA-Z0-9]$", tok.strip()))


def looks_base64_prefix(tok: str) -> bool:
    if len(tok) < 8:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9+/=]+", tok))


def longest_common_prefix(strings: List[str]) -> str:
    if not strings:
        return ""
    s1 = min(strings)
    s2 = max(strings)
    i = 0
    while i < min(len(s1), len(s2)) and s1[i] == s2[i]:
        i += 1
    return s1[:i]


def detect_condition_kind(condition: str) -> str:
    c = (condition or "").strip().lower()
    if re.search(r"\ball of selection", c):
        return "all"
    if re.search(r"\b1 of selection", c) or re.search(r"\bone of selection", c):
        return "one"
    if re.search(r"\bany of selection", c):
        return "any"
    return "complex"


def parse_sigma_key(key: str) -> Tuple[str, str, Optional[str]]:
    """
    Parse Sigma field/operator/modifier:
      CommandLine|contains
      CommandLine|contains|all
      CommandLine|contains|any
    Return: (field, op, modifier)
    """
    parts = [p.strip() for p in key.split("|") if p.strip()]
    field = parts[0] if parts else key.strip()
    op = parts[1].lower() if len(parts) > 1 else "equals"
    modifier = parts[2].lower() if len(parts) > 2 else None
    return field, op, modifier


# We'll keep richer candidate info to fix ordering later
# (sigma_field, op, modifier, value)
Candidate = Tuple[str, str, Optional[str], str]


def iter_candidates_by_selection(detection: Dict[str, Any]) -> Dict[str, List[Candidate]]:
    """
    Return mapping: selection_name -> list of candidates (sigma_field, op, modifier, value)
    Supports:
      - Field|contains
      - Field|contains|all  (treated as combined token chain)
      - Field|startswith / endswith / equals
    """
    out: Dict[str, List[Candidate]] = {}

    for sel_name, sel_body in detection.items():
        if sel_name == "condition":
            continue

        out.setdefault(sel_name, [])
        blocks = sel_body if isinstance(sel_body, list) else [sel_body]
        for b in blocks:
            if not isinstance(b, dict):
                continue

            for k, v in b.items():
                sigma_field, op, modifier = parse_sigma_key(k)

                # Normalize op for safety
                if op not in SUPPORTED_OPS:
                    continue

                values = v if isinstance(v, list) else [v]
                str_values = [x.strip() for x in values if isinstance(x, str) and x.strip()]

                if not str_values:
                    continue

                # If many similar values (like base64 prefixes), compress by LCP
                if len(str_values) >= 3:
                    lcp = longest_common_prefix(str_values)
                    if len(lcp) >= 6 and all(s.startswith(lcp) for s in str_values) and looks_base64_prefix(lcp):
                        str_values = [lcp]

                # Handle contains|all: combine into one chain token (order as given)
                # Example: ["ufw", "disable"] -> "ufw*disable"
                if op == "contains" and modifier == "all" and len(str_values) >= 2:
                    combined = "*".join(str_values)
                    out[sel_name].append((sigma_field, op, modifier, combined))
                else:
                    for one in str_values:
                        out[sel_name].append((sigma_field, op, modifier, one))

    return out


def score_token(field: str, op: str, value: str, title_hint: str) -> int:
    """
    Higher is better. Penalize generic tokens so we don't pick "-d" or "bash" alone.
    """
    v = value.strip()
    s = 0

    if field == "CommandLine":
        s += 120
    elif field in {"Image", "ParentImage"}:
        s += 60
    else:
        s += 20

    s += {"endswith": 30, "startswith": 20, "contains": 10, "equals": 5}.get(op, 0)
    s += min(len(v), 50)

    # Penalize generic tokens and short flags
    if v.lower() in GENERIC_TOKENS:
        s -= 120
    if is_short_flag(v):
        s -= 140

    # Boost if token relates to title keywords
    if title_hint:
        for w in set(re.findall(r"[a-z0-9]{4,}", title_hint.lower())):
            if w in v.lower():
                s += 15

    # Extra boosts for common "meaning" tokens
    if "base64" in v.lower():
        s += 30
    if "apt::update::pre-invoke" in v.lower():
        s += 40
    if "stratum+tcp" in v.lower() or "xmrig" in v.lower() or "xmr" in v.lower():
        s += 25
    if "ufw" in v.lower():
        s += 20

    return s


def to_commandline_pattern(sigma_field: str, op: str, value: str) -> str:
    """
    Force everything into a process.command_line wildcard pattern.
    - For Image/ParentImage: use basename token (dd, ufw, at, atd...)
    - For CommandLine: keep value
    """
    v = value.strip()
    if sigma_field in {"Image", "ParentImage"}:
        v = basename_like(v)

    # For non-CommandLine indicators, we treat as "contains" in command line
    effective_op = op if sigma_field == "CommandLine" else "contains"
    pat = make_wildcard(safe_token(v), effective_op)

    if not pat.startswith("*"):
        pat = "*" + pat
    if not pat.endswith("*"):
        pat = pat + "*"
    return pat


def combine_patterns_in_order(parts: List[str], max_parts: int = 3) -> str:
    """
    Combine patterns into single wildcard chain, keeping given order,
    stripping outer '*' to avoid '**'.
    """
    cleaned: List[str] = []
    for p in parts:
        p2 = p.strip().lstrip("*").rstrip("*")
        if p2 and p2 not in cleaned:
            cleaned.append(p2)
    cleaned = cleaned[:max_parts]
    if not cleaned:
        return "*"
    return "*" + "*".join(cleaned) + "*"


def pick_anchor(sigma_rule: Dict[str, Any], prefer_commandline: bool = True) -> Tuple[str, str]:
    detection = sigma_rule.get("detection") or {}
    condition = detection.get("condition", "") or ""
    kind = detect_condition_kind(condition)

    by_sel = iter_candidates_by_selection(detection)
    title_hint = (sigma_rule.get("title") or "")

    # Best candidate per selection (keep sigma_field for ordering)
    # entries: (score, sigma_field, op, value, pattern)
    best_per_sel: List[Tuple[int, str, str, str, str]] = []

    for sel_name, items in by_sel.items():
        if not items:
            continue
        best_item = max(
            items,
            key=lambda t: score_token(t[0], t[1], t[3], title_hint),
        )
        sigma_field, op, modifier, value = best_item
        pat = to_commandline_pattern(sigma_field, op, value) if prefer_commandline else make_wildcard(value, op)
        sc = score_token(sigma_field, op, value, title_hint)
        best_per_sel.append((sc, sigma_field, op, value, pat))

    if not best_per_sel:
        return ("process.command_line", "*")

    # Sort by score desc for general selection
    best_per_sel.sort(key=lambda x: x[0], reverse=True)

    # If condition requires ALL selections, we combine multiple anchors.
    if kind == "all":
        # Re-order to avoid dd bug: binary/exe first, then other tokens
        def priority(item: Tuple[int, str, str, str, str]) -> Tuple[int, int]:
            _, sigma_field, op, value, _pat = item
            # executable-like fields first
            exe_first = 0 if sigma_field in {"Image", "ParentImage", "OriginalFileName"} else 1
            # within CommandLine, prefer "base keyword" tokens over flags
            flag_penalty = 1 if is_short_flag(value.strip()) else 0
            return (exe_first, flag_penalty)

        # take top-k by score first, then reorder by priority (stable)
        top = best_per_sel[:4]
        top.sort(key=priority)

        chosen_patterns = [it[4] for it in top]
        pattern = combine_patterns_in_order(chosen_patterns, max_parts=3)
        return ("process.command_line", pattern)

    # Otherwise: pick single best (if too generic, combine with next best)
    best_score, _sf, _op, _val, best_pat = best_per_sel[0]
    if best_score < 60 and len(best_per_sel) >= 2:
        pattern = combine_patterns_in_order([best_pat, best_per_sel[1][4]], max_parts=2)
        return ("process.command_line", pattern)

    return ("process.command_line", best_pat)


def amides_filename_from_sigma_path(src: Path) -> str:
    stem = src.stem.lower()

    prefixes = [
        "proc_creation_",
        "proc_access_",
        "process_creation_",
        "lnx_proc_creation_",
        "win_proc_creation_",
    ]
    for p in prefixes:
        if stem.startswith(p):
            stem = stem[len(p):]
            break

    for p in ["lnx_", "linux_", "win_", "windows_", "macos_"]:
        if stem.startswith(p):
            stem = stem[len(p):]
            break

    stem = slugify_lower(stem)
    return f"{stem}.yml"


def unique_path(out_dir: Path, filename: str) -> Path:
    p = out_dir / filename
    if not p.exists():
        return p
    base = p.stem
    ext = p.suffix
    i = 2
    while True:
        cand = out_dir / f"{base}_{i}{ext}"
        if not cand.exists():
            return cand
        i += 1


def convert_one(sigma_rule: Dict[str, Any], prefer_commandline: bool = True) -> Dict[str, Any]:
    amides_field, pattern = pick_anchor(sigma_rule, prefer_commandline=prefer_commandline)
    tags = sigma_rule.get("tags") or []
    mitre = [normalize_tag(t) for t in tags if isinstance(t, str)]

    return {
        "filter": f'{amides_field}: "{pattern}"',
        "pre_detector": {
            "case_condition": "directly",
            "id": sigma_rule.get("id"),
            "mitre": mitre,
            "severity": severity_from_level(sigma_rule.get("level")),
            "title": sigma_rule.get("title"),
        },
        "sigma_fields": True,
        "description": sigma_rule.get("description", "") or "",
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in-dir", required=True, help="SigmaHQ rules dir (vd: ./process_creation)")
    ap.add_argument("--out-dir", required=True, help="AMIDES rules dir (vd: ./sigma/rules/process_creation)")
    ap.add_argument("--recursive", action="store_true")
    ap.add_argument("--prefer-commandline", choices=["yes", "no"], default="yes")
    ap.add_argument("--write-original", action="store_true")
    args = ap.parse_args()

    in_dir = Path(args.in_dir).resolve()
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    prefer_cmd = args.prefer_commandline == "yes"
    pattern = "**/*.y*ml" if args.recursive else "*.y*ml"
    files = sorted(in_dir.glob(pattern))
    if not files:
        raise SystemExit(f"No YAML files found: {in_dir} (recursive={args.recursive})")

    ok = 0
    fail: List[Tuple[Path, str]] = []

    for f in files:
        try:
            sigma_rule = yaml.safe_load(f.read_text(encoding="utf-8", errors="ignore"))
            if not isinstance(sigma_rule, dict):
                raise ValueError("YAML root is not a dict")

            amides_rule = convert_one(sigma_rule, prefer_commandline=prefer_cmd)

            out_name = amides_filename_from_sigma_path(f)
            out_path = unique_path(out_dir, out_name)

            out_path.write_text(
                yaml.safe_dump(amides_rule, sort_keys=False, allow_unicode=True),
                encoding="utf-8",
            )

            if args.write_original:
                orig_path = out_path.with_name(out_path.stem + "_sigma_original.yml")
                orig_path.write_text(
                    yaml.safe_dump(sigma_rule, sort_keys=False, allow_unicode=True),
                    encoding="utf-8",
                )

            ok += 1
            print(f"[OK] {f.name} -> {out_path}")

        except Exception as e:
            fail.append((f, str(e)))
            print(f"[FAIL] {f} : {e}")

    print(f"\nDone. Converted: {ok}/{len(files)}")
    if fail:
        print("Failed files:")
        for f, err in fail:
            print(f"  - {f}: {err}")


if __name__ == "__main__":
    main()
