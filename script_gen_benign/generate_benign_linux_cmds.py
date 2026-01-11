#!/usr/bin/env python3
import argparse
import random
import re
from pathlib import Path

SAFE_BLACKLIST_PATTERNS = [
    r"\brm\s+-rf\b",                          # destructive
    r"\bmkfs\.",                              # destructive
    r"\bdd\s+if=/dev/(zero|random)\s+of=/dev/",  # destructive
    r"\b:>\s*/",                              # destructive truncate
    r"\bshutdown\b|\breboot\b",               # disruptive
    r"\bchown\s+root\b",                      # privilege-y
    r"\bchmod\s+\+x\b",                       # staging-ish
    r"\bbase64\s+-d\b",                       # avoid overlap with suspicious rules
    r"\b\|\s*bash\b|\b\|\s*sh\b",             # pipe-to-shell
]

CATEGORIES = {}

def register(cat: str):
    def deco(fn):
        CATEGORIES.setdefault(cat, []).append(fn)
        return fn
    return deco

def pick(lst, rng):
    return rng.choice(lst)

def maybe(s, rng, p=0.3):
    return s if rng.random() < p else ""

def ws_join(parts):
    return " ".join([p for p in parts if p and str(p).strip()])

# ---------- benign building blocks ----------
USERS = ["alice", "bob", "dev", "ops", "ubuntu", "student"]
PKGS = ["vim", "curl", "git", "htop", "python3-pip", "net-tools", "jq", "tmux", "tree"]
SERVICES = ["ssh", "cron", "rsyslog", "nginx", "docker", "cups"]

# Common paths first; rare paths last (opt/tools should be rare)
COMMON_PATHS = [
    "/home/{u}/projects",
    "/home/{u}/docs",
    "/home/{u}/Downloads",
    "/var/log",
    "/etc",
    "/tmp",
    "/var/tmp",
]
RARE_PATHS = [
    "/opt/tools",  # keep but rare
]

FILES = [
    "notes.txt", "todo.md", "readme.md", "config.yml", "app.log", "syslog", "auth.log",
    "report.csv", "data.json", "requirements.txt"
]

def fmt_dir(rng):
    u = pick(USERS, rng)
    # 95% common, 5% rare
    if rng.random() < 0.95:
        base = pick(COMMON_PATHS, rng)
    else:
        base = pick(RARE_PATHS, rng)
    return base.format(u=u)

def fmt_path(rng):
    d = fmt_dir(rng)
    f = pick(FILES, rng)
    return f"{d}/{f}"

# ---------- category generators ----------
@register("filesystem")
def gen_ls(rng):
    flags = pick(["-la", "-l", "-lh", "-1", ""], rng)
    target = pick([fmt_dir(rng), fmt_path(rng), "."], rng)
    return ws_join(["ls", flags, target])

@register("filesystem")
def gen_find(rng):
    base = pick([fmt_dir(rng), "/var/log", "/etc", "/home/" + pick(USERS, rng)], rng)
    name = pick(["*.log", "*.conf", "*.yml", "*.json", "*.md", "*.txt"], rng)
    depth = pick(["-maxdepth 1", "-maxdepth 2", "-maxdepth 3", ""], rng)
    return ws_join(["find", base, depth, "-name", f"'{name}'"])

@register("filesystem")
def gen_cp_mv(rng):
    op = pick(["cp", "mv"], rng)
    src = fmt_path(rng)
    dst_dir = fmt_dir(rng)
    return ws_join([op, src, dst_dir + "/"])

@register("filesystem")
def gen_tar(rng):
    d = fmt_dir(rng)
    out = f"{d}/backup{pick(['', '_old', '_daily'], rng)}.tar.gz"
    target = pick([d, fmt_dir(rng), "/var/log"], rng)
    return ws_join(["tar", "-czf", out, target])

@register("text")
def gen_grep(rng):
    pat = pick(["error", "warn", "failed", "timeout", "denied"], rng)
    file_ = pick(["/var/log/syslog", "/var/log/auth.log", fmt_path(rng)], rng)
    flags = pick(["-n", "-i", "-n -i", ""], rng)
    return ws_join(["grep", flags, f"'{pat}'", file_])

@register("text")
def gen_sed(rng):
    file_ = fmt_path(rng)
    a = pick(["foo", "bar", "DEBUG", "INFO", "prod"], rng)
    b = pick(["baz", "qux", "WARN", "ERROR", "dev"], rng)
    return ws_join(["sed", f"\"s/{a}/{b}/g\"", file_])

@register("text")
def gen_awk(rng):
    file_ = pick([fmt_path(rng), "/var/log/syslog", "/var/log/auth.log"], rng)
    return ws_join(["awk", "'{print $1,$2,$3}'", file_])

@register("system")
def gen_systemctl(rng):
    act = pick(["status", "is-active", "is-enabled", "show"], rng)
    svc = pick(SERVICES, rng)
    return ws_join(["systemctl", act, svc])

@register("system")
def gen_journalctl(rng):
    unit = pick(SERVICES, rng)
    tail = pick(["-n 50", "-n 100", "-n 200"], rng)
    return ws_join(["journalctl", "-u", unit, tail, "--no-pager"])

@register("system")
def gen_ps(rng):
    flags = pick(["aux", "ax", "eo pid,comm,%cpu,%mem --sort=-%cpu"], rng)
    return ws_join(["ps", flags])

@register("system")
def gen_df_free_uptime(rng):
    return pick(["df -h", "free -m", "uptime", "uname -a"], rng)

@register("user")
def gen_id_whoami(rng):
    return pick(["whoami", "id", "groups", "date"], rng)

@register("user")
def gen_head_tail_cat(rng):
    file_ = pick(["/var/log/syslog", "/var/log/auth.log", fmt_path(rng)], rng)
    return pick(
        [f"head -n 50 {file_}", f"tail -n 50 {file_}", f"cat {file_}"],
        rng
    )

@register("network")
def gen_ping(rng):
    host = pick(["1.1.1.1", "8.8.8.8", "localhost"], rng)
    c = pick(["-c 1", "-c 2", "-c 3"], rng)
    return ws_join(["ping", c, host])

@register("network")
def gen_ip(rng):
    return pick(["ip a", "ip r", "ip link show"], rng)

@register("network")
def gen_ss(rng):
    return pick(["ss -tulpen", "ss -antp", "ss -s"], rng)

@register("package")
def gen_apt(rng):
    return pick([
        "apt-cache policy " + pick(PKGS, rng),
        "apt-cache show " + pick(PKGS, rng),
        "dpkg -l | head",
        "apt list --installed | head",
    ], rng)

@register("devops")
def gen_git(rng):
    d = fmt_dir(rng)
    return pick([
        f"git -C {d} status",
        f"git -C {d} branch",
        f"git -C {d} log -n 5 --oneline",
        f"git -C {d} diff --stat",
    ], rng)

@register("devops")
def gen_python(rng):
    # tránh python -c, chỉ benign help/list
    return pick([
        "python3 --version",
        "pip3 --version",
        "python3 -m pip list | head",
        "python3 -m venv .venv && echo created",
    ], rng)

@register("devops")
def gen_docker_query(rng):
    # query-only
    return pick([
        "docker ps",
        "docker ps -a",
        "docker images",
        "docker info | head",
    ], rng)

def is_head_candidate(cmd: str) -> bool:
    """
    Only add '| head' to commands that typically produce long output,
    and only if they do NOT already have a pipe / head / tail.
    """
    if "|" in cmd:
        return False
    if re.search(r"\b(head|tail)\b", cmd):
        return False

    starters = (
        "ls ",
        "find ",
        "grep ",
        "awk ",
        "sed ",
        "ps ",
        "journalctl ",
        "apt list ",
        "dpkg -l",
        "python3 -m pip list",
        "docker info",
        "docker images",
    )
    return cmd.startswith(starters)

def build_command(rng):
    # Add "user" category to balance realism
    weights = [
        ("filesystem", 0.26),
        ("text",       0.18),
        ("system",     0.18),
        ("user",       0.12),
        ("network",    0.14),
        ("package",    0.08),
        ("devops",     0.04),
    ]

    r = rng.random()
    acc = 0.0
    cat = "filesystem"
    for k, w in weights:
        acc += w
        if r <= acc:
            cat = k
            break

    fn = rng.choice(CATEGORIES[cat])
    cmd = fn(rng).strip()

    # benign noise: keep LOW and realistic
    # add redirect only if no redirect exists
    if ">/dev/null" not in cmd and "2>/dev/null" not in cmd:
        cmd = ws_join([cmd, maybe("2>/dev/null", rng, 0.07)])

    # add '| head' only for long-output commands
    if is_head_candidate(cmd):
        cmd = ws_join([cmd, maybe("| head", rng, 0.12)])

    # Never allow accidental '| head | head' (just in case)
    cmd = re.sub(r"(\|\s*head)(\s*\|\s*head)+", r"\1", cmd)

    return cmd

def is_safe(cmd: str) -> bool:
    for pat in SAFE_BLACKLIST_PATTERNS:
        if re.search(pat, cmd):
            return False
    if re.search(r"\|\s*(bash|sh)\b", cmd):
        return False
    return True

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, help="output file (one cmd per line)")
    ap.add_argument("--n", type=int, default=200000, help="number of commands")
    ap.add_argument("--seed", type=int, default=1337, help="rng seed")
    ap.add_argument("--dedup", action="store_true", help="deduplicate lines")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    seen = set()
    written = 0
    attempts = 0
    max_attempts = args.n * 7

    with out_path.open("w", encoding="utf-8") as f:
        while written < args.n and attempts < max_attempts:
            attempts += 1
            cmd = build_command(rng)
            if not is_safe(cmd):
                continue
            if args.dedup:
                if cmd in seen:
                    continue
                seen.add(cmd)
            f.write(cmd + "\n")
            written += 1

    if written < args.n:
        raise SystemExit(
            f"Generated only {written}/{args.n} safe commands. "
            f"Try reducing --n or removing --dedup."
        )

    print(f"OK: wrote {written} commands to {out_path}")

if __name__ == "__main__":
    main()
