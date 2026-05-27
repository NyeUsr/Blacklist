import argparse
import calendar
import os
import re
import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date

from PyFunceble.checker.availability.domain import DomainAvailabilityChecker

DEFAULT_FILES = ["Main", "Mixed Content", "Porn"]
#DEFAULT_DIRS = ["Anti-Corp"] - Don't use with Anti-Corp, many of the domains show as dead when they are not.
RULE_RE = re.compile(r"^\|\|([^\^/\$\s]+)\^")
DEAD_RE = re.compile(r"^!\s*dead\s+(\d{4}-\d{2}-\d{2})\s+(.+)$")
DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
AUTO_WORKERS = min(64, max(8, (os.cpu_count() or 4) * 5))


def get_default_files(repo):
    files = list(DEFAULT_FILES)
    for dirname in DEFAULT_DIRS:
        files.extend(
            path.relative_to(repo).as_posix()
            for path in sorted((repo / dirname).iterdir())
            if path.is_file()
        )
    return files


def is_literal_domain(domain):
    if not domain or "*" in domain:
        return False
    return all(DOMAIN_LABEL_RE.match(label) for label in domain.split("."))


def get_domain(line):
    line = line.strip()
    if not line:
        return None
    if line.startswith("!") or line.startswith("@@") or line.startswith("["):
        return None
    m = RULE_RE.match(line)
    if not m:
        return None
    domain = m.group(1).lower()
    if not is_literal_domain(domain):
        return None
    return domain


def get_dead_line(line):
    m = DEAD_RE.match(line.strip())
    if not m:
        return None

    try:
        checked = date.fromisoformat(m.group(1))
    except ValueError:
        return None

    rule = m.group(2)
    domain = get_domain(rule)
    if not domain:
        return None

    return checked, rule, domain


def months_ago(n):
    today = date.today()
    month = today.month - n
    year = today.year

    while month <= 0:
        month += 12
        year -= 1

    day = min(today.day, calendar.monthrange(year, month)[1])
    return date(year, month, day)


def check_one(domain):
    try:
        checker = DomainAvailabilityChecker(subject=domain)
        checker.dns_query_tool.set_nameservers(["9.9.9.10", "149.112.112.10"])
        status = checker.get_status().status
        return domain, status
    except Exception:
        return domain, "ERROR"


def process_file(path, workers=AUTO_WORKERS, dry_run=False):
    print(f"\n# {path.name}")

    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)

    found = []
    domain_to_items = {}

    for i, line in enumerate(lines):
        dead_line = get_dead_line(line)
        if dead_line:
            checked, rule, domain = dead_line
            item = {
                "line": i,
                "domain": domain,
                "rule": rule,
                "checked": checked,
                "commented": True,
            }
        else:
            domain = get_domain(line)
            if not domain:
                continue
            item = {
                "line": i,
                "domain": domain,
                "rule": line.rstrip("\n"),
                "checked": None,
                "commented": False,
            }

        found.append(item)
        domain_to_items.setdefault(item["domain"], []).append(item)

    domains = sorted(domain_to_items.keys())
    if not domains:
        print("no domains found")
        return 0, 0, 0, 0

    print(f"checking {len(domains)} domains...")

    statuses = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(check_one, d) for d in domains]
        done = 0
        total = len(futures)

        for f in as_completed(futures):
            d, s = f.result()
            statuses[d] = s
            done += 1
            if done % 100 == 0 or done == total:
                print(f"  {done}/{total}")

    bad = {d for d, s in statuses.items() if s == "ERROR"}

    if bad:
        print(f"{len(bad)} had check errors (left untouched)")

    new_lines = lines[:]
    today = date.today().isoformat()
    cutoff = months_ago(6)

    commented = 0
    restored = 0
    removed = 0

    for item in found:
        domain = item["domain"]
        status = statuses.get(domain)
        if status == "ERROR":
            continue

        i = item["line"]
        old = lines[i]
        end = "\n" if old.endswith("\n") else ""
        old = old.rstrip("\n")

        if item["commented"]:
            if status not in ("INACTIVE", "INVALID"):
                new_lines[i] = item["rule"] + end
                restored += 1
            elif item["checked"] <= cutoff:
                new_lines[i] = None
                removed += 1
        elif status in ("INACTIVE", "INVALID"):
            new_lines[i] = f"! dead {today} {old}{end}"
            commented += 1

    print(f"newly commented: {commented}")
    print(f"restored: {restored}")
    print(f"removed after 6 months: {removed}")

    if not (commented or restored or removed):
        print("nothing to change")
        return len(domains), 0, 0, 0

    if dry_run:
        print("dry run: no file changes")
        return len(domains), commented, restored, removed

    new_lines = [line for line in new_lines if line is not None]
    path.write_text("".join(new_lines), encoding="utf-8")
    print(f"saved ({len(lines)} -> {len(new_lines)})")

    return len(domains), commented, restored, removed


def main():
    p = argparse.ArgumentParser(description="mark dead domains in blacklist files")
    p.add_argument("--files", nargs="+")
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()

    repo = Path(__file__).resolve().parent.parent
    files = args.files if args.files is not None else get_default_files(repo)

    total_checked = 0
    total_commented = 0
    total_restored = 0
    total_removed = 0

    print(f"workers: {AUTO_WORKERS}")

    for name in files:
        path = repo / name
        if not path.exists():
            print(f"missing file: {path}", file=sys.stderr)
            continue

        checked, commented, restored, removed = process_file(
            path,
            workers=AUTO_WORKERS,
            dry_run=args.dry_run,
        )
        total_checked += checked
        total_commented += commented
        total_restored += restored
        total_removed += removed

    print("\n---")
    print(f"checked: {total_checked}")
    print(f"commented: {total_commented}")
    print(f"restored: {total_restored}")
    print(f"removed: {total_removed}")


if __name__ == "__main__":
    main()
