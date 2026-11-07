import csv
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict

# Locate the evidence file relative to this script
BASE_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = BASE_DIR / "evidence" / "sample-windows-events.csv"

# Detection configuration
FAILED_LOGIN_EVENT = "4625"
THRESHOLD = 3
TIME_WINDOW = timedelta(seconds=60)


def load_events():
    """Load security events from the CSV evidence file."""
    with open(LOG_FILE, newline="", encoding="utf-8") as file:
        return list(csv.DictReader(file))


def detect_failed_logins(events):
    """Detect repeated failed logins from the same account and IP."""

    failed_attempts = defaultdict(list)

    for event in events:
        if event["event_id"] != FAILED_LOGIN_EVENT:
            continue

        key = (event["username"], event["source_ip"])
        timestamp = datetime.strptime(
            event["timestamp"], "%Y-%m-%d %H:%M:%S"
        )

        failed_attempts[key].append(timestamp)

    alerts = []

    for (username, source_ip), timestamps in failed_attempts.items():
        timestamps.sort()

        for index in range(len(timestamps)):
            window_start = timestamps[index]
            window_end = window_start + TIME_WINDOW

            matching_attempts = [
                time for time in timestamps
                if window_start <= time <= window_end
            ]

            if len(matching_attempts) >= THRESHOLD:
                alerts.append({
                    "username": username,
                    "source_ip": source_ip,
                    "attempts": len(matching_attempts),
                    "first_seen": window_start,
                    "last_seen": matching_attempts[-1]
                })
                break

    return alerts


def main():
    print("\n=== SOC FAILED LOGIN DETECTION ===\n")

    if not LOG_FILE.exists():
        print(f"Evidence file not found: {LOG_FILE}")
        return

    events = load_events()
    alerts = detect_failed_logins(events)

    if not alerts:
        print("No matching failed-login patterns detected.")
        return

    for alert in alerts:
        print("[ALERT] Repeated failed login attempts detected")
        print(f"Account: {alert['username']}")
        print(f"Source IP: {alert['source_ip']}")
        print(f"Attempts: {alert['attempts']}")
        print(f"First seen: {alert['first_seen']}")
        print(f"Last seen: {alert['last_seen']}")
        print("Assessment: Requires further investigation.\n")


if __name__ == "__main__":
    main()
