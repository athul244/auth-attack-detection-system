#!/usr/bin/env python3
"""
Authentication Attack Detector - v1
Parses failed SSH login attempts from auth.log and flags brute force attacks.

Brute force rule: same source IP has >= FAIL_THRESHOLD failed attempts
within WINDOW_MINUTES.
"""

import re
import sys
from datetime import datetime, timedelta
from collections import defaultdict

LOG_FILE = "/var/log/auth.log"
FAIL_THRESHOLD = 5       # number of failed attempts to flag
WINDOW_MINUTES = 5       # time window to count attempts within

# Matches both:
#   ...Failed password for invalid user fake from 192.168.29.104 port 37964 ssh2
#   ...Failed password for root from 192.168.29.104 port 37964 ssh2
LOG_PATTERN = re.compile(
    r'^(?P<timestamp>\S+)\s+\S+\s+sshd-session\[\d+\]:\s+'
    r'Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+) ssh2'
)


def parse_line(line):
    """Extract (timestamp, user, ip) from one log line, or None if no match."""
    match = LOG_PATTERN.search(line)
    if not match:
        return None
    ts_str = match.group("timestamp")
    try:
        # timestamp format: 2026-10-17T02:48:34.187597-04:00
        ts = datetime.fromisoformat(ts_str)
    except ValueError:
        return None
    return {
        "timestamp": ts,
        "user": match.group("user"),
        "ip": match.group("ip"),
    }


def load_events(log_file):
    """Read the log file and return a list of parsed failed-login events."""
    events = []
    with open(log_file, "r") as f:
        for line in f:
            event = parse_line(line)
            if event:
                events.append(event)
    return events


def detect_brute_force(events, threshold=FAIL_THRESHOLD, window_minutes=WINDOW_MINUTES):
    """
    Group events by source IP. For each IP, slide a time window across its
    failed attempts; if any window contains >= threshold attempts, flag it.
    Returns a dict: ip -> list of flagged attempts (for the report).
    """
    by_ip = defaultdict(list)
    for e in events:
        by_ip[e["ip"]].append(e)

    flagged = {}
    window = timedelta(minutes=window_minutes)

    for ip, attempts in by_ip.items():
        attempts.sort(key=lambda e: e["timestamp"])
        # sliding window check
        for i in range(len(attempts)):
            window_start = attempts[i]["timestamp"]
            window_end = window_start + window
            count = sum(1 for a in attempts if window_start <= a["timestamp"] <= window_end)
            if count >= threshold:
                flagged[ip] = attempts
                break

    return flagged


def print_report(flagged):
    if not flagged:
        print("No brute force activity detected.")
        return

    print(f"=== Brute Force Detection Report ===\n")
    for ip, attempts in flagged.items():
        usernames = sorted(set(a["user"] for a in attempts))
        first_seen = min(a["timestamp"] for a in attempts)
        last_seen = max(a["timestamp"] for a in attempts)

        print(f"[ALERT] Source IP: {ip}")
        print(f"  Total failed attempts : {len(attempts)}")
        print(f"  Usernames targeted    : {', '.join(usernames)}")
        print(f"  First seen            : {first_seen}")
        print(f"  Last seen             : {last_seen}")
        print()


def main():
    log_file = sys.argv[1] if len(sys.argv) > 1 else LOG_FILE
    events = load_events(log_file)
    print(f"Parsed {len(events)} failed login events from {log_file}\n")

    flagged = detect_brute_force(events)
    print_report(flagged)


if __name__ == "__main__":
    main()
