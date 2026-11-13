"""
Log Analyser - a lightweight, SIEM-style SSH log auditor.

Reads an SSH authentication log, extracts every login attempt with a
regular expression, then reports security-relevant patterns:
  - brute-force attempts (many failures from one IP)
  - likely successful break-ins (many failures, then a success)
  - credential stuffing (one IP trying many usernames)
  - out-of-hours activity (logins at unusual times)

Usage:
    python log_analyser.py auth.log
"""

import re
import sys
from collections import defaultdict

# --- Configuration -------------------------------------------------
BRUTE_FORCE_THRESHOLD = 10     # this many failures from one IP = suspicious
STUFFING_THRESHOLD = 5         # distinct usernames from one IP = stuffing
OFF_HOURS = range(0, 6)        # 00:00-05:59 counts as out-of-hours

# A single regular expression pulls the fields out of each log line.
# Named groups (?P<name>...) make the extracted parts easy to read.
LOG_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2}).*?"
    r"(?P<status>Failed|Accepted) password for (?:invalid user )?"
    r"(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)


def parse_log(path):
    """Read the log and group every attempt by its source IP address."""
    # each IP maps to a running tally of its activity
    activity = defaultdict(lambda: {
        "failed": 0, "success": 0, "failed_before_success": 0,
        "users": set(), "events": []
    })
    total_lines = 0
    matched = 0

    with open(path, "r", errors="replace") as log:
        for line in log:
            total_lines += 1
            match = LOG_PATTERN.search(line)
            if not match:
                continue  # not a login line - ignore it

            matched += 1
            ip = match.group("ip")
            status = match.group("status")
            user = match.group("user")

            record = activity[ip]
            record["users"].add(user)
            record["events"].append((match.group("time"), status, user))
            if status == "Failed":
                record["failed"] += 1
            else:
                # remember how many failures came BEFORE the first success,
                # so a normal login followed by typos is not called a breach
                if record["success"] == 0:
                    record["failed_before_success"] = record["failed"]
                record["success"] += 1

    return activity, total_lines, matched


def report(activity, total_lines, matched, path):
    """Print a SOC-style security report from the parsed activity."""
    total_failed = sum(r["failed"] for r in activity.values())
    total_success = sum(r["success"] for r in activity.values())

    print("=" * 60)
    print("  Log Analyser - Security Report")
    print(f"  Source: {path}   "
          f"(parsed {total_lines} lines, {matched} auth events)")
    print("=" * 60)

    print("\n[SUMMARY]")
    print(f"  Failed logins:      {total_failed}")
    print(f"  Successful logins:  {total_success}")
    print(f"  Unique source IPs:  {len(activity)}")

    # CRITICAL: failures over the threshold, THEN a success on the same IP
    breaches = [(ip, r) for ip, r in activity.items()
                if r["failed_before_success"] >= BRUTE_FORCE_THRESHOLD]
    if breaches:
        print("\n[!! CRITICAL] Possible SUCCESSFUL brute-force")
        for ip, r in breaches:
            print(f"  {ip}  ->  {r['failed_before_success']} failed, then "
                  f"SUCCESS  (tried {len(r['users'])} users)")

    # WARNING: failures over the threshold, no success
    attacks = [(ip, r) for ip, r in activity.items()
               if r["failed"] >= BRUTE_FORCE_THRESHOLD and r["success"] == 0]
    if attacks:
        print(f"\n[!]  WARNING - Brute-force attempts "
              f"({BRUTE_FORCE_THRESHOLD} or more failures)")
        for ip, r in sorted(attacks, key=lambda x: x[1]["failed"],
                            reverse=True):
            note = (f", {len(r['users'])} usernames (credential stuffing)"
                    if len(r["users"]) >= STUFFING_THRESHOLD else "")
            print(f"  {ip}  ->  {r['failed']} failed attempts{note}")

    # WARNING: successful logins during out-of-hours
    off_hours = []
    for ip, r in activity.items():
        for time, status, user in r["events"]:
            if status == "Accepted" and int(time.split(":")[0]) in OFF_HOURS:
                off_hours.append((time, user, ip))
    if off_hours:
        print(f"\n[!]  WARNING - Out-of-hours logins "
              f"({OFF_HOURS.start:02d}:00-{OFF_HOURS.stop - 1:02d}:59)")
        for time, user, ip in sorted(off_hours):
            print(f"  {time}  Accepted login for '{user}' from {ip}")

    # Ranking of the noisiest sources
    print("\n[TOP SOURCES BY FAILED ATTEMPTS]")
    ranked = sorted(activity.items(), key=lambda x: x[1]["failed"],
                    reverse=True)
    for ip, r in ranked[:5]:
        if r["failed"] == 0:
            continue
        print(f"  {ip:<18} {r['failed']} failed, {r['success']} success")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python log_analyser.py auth.log")
        sys.exit(1)

    logfile = sys.argv[1]
    try:
        data, lines, hits = parse_log(logfile)
    except FileNotFoundError:
        print(f"[-] Log file not found: {logfile}")
        sys.exit(1)

    if hits == 0:
        print("[i] No SSH login lines recognised in this file.")
    else:
        report(data, lines, hits, logfile)
