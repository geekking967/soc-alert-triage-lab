import csv
import json
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict

BASE_DIR = Path(__file__).resolve().parent.parent

LOG_FILE = BASE_DIR / "evidence" / "sample-windows-events.csv"
OUTPUT_FILE = BASE_DIR / "output" / "correlated-alerts.json"

CORRELATION_WINDOW = timedelta(minutes=5)

FAILED_LOGON = "4625"
SUCCESSFUL_LOGON = "4624"
NETWORK_SHARE = "5140"


def load_events():
    with open(LOG_FILE, newline="", encoding="utf-8") as file:
        events = list(csv.DictReader(file))

    for event in events:
        event["parsed_time"] = datetime.strptime(
            event["timestamp"], "%Y-%m-%d %H:%M:%S"
        )

    return sorted(events, key=lambda event: event["parsed_time"])


def correlate_events(events):
    failed_events = defaultdict(list)
    successful_events = defaultdict(list)
    share_events = defaultdict(list)

    for event in events:
        key = (event["username"], event["source_ip"])

        if event["event_id"] == FAILED_LOGON:
            failed_events[key].append(event)

        elif event["event_id"] == SUCCESSFUL_LOGON:
            successful_events[key].append(event)

        elif event["event_id"] == NETWORK_SHARE:
            share_events[key].append(event)

    alerts = []

    for key, failures in failed_events.items():
        username, source_ip = key

        for success in successful_events.get(key, []):
            success_time = success["parsed_time"]

            previous_failures = [
                failure for failure in failures
                if timedelta(0) <= success_time - failure["parsed_time"]
                <= CORRELATION_WINDOW
            ]

            if len(previous_failures) < 3:
                continue

            related_shares = [
                share for share in share_events.get(key, [])
                if timedelta(0) <= share["parsed_time"] - success_time
                <= CORRELATION_WINDOW
            ]

            alerts.append({
                "alert_id": f"SOC-AUTH-{len(alerts) + 1:03d}",
                "alert_name": "Repeated Failed Logins Followed by Success",
                "rule_id": "AUTH-001",
                "severity": "Medium",
                "status": "Requires Investigation",
                "username": username,
                "source_ip": source_ip,
                "failed_attempts": len(previous_failures),
                "successful_login": success_time.isoformat(),
                "network_share_events": len(related_shares),
                "assessment": (
                    "Suspicious authentication sequence detected. "
                    "Account compromise is not confirmed."
                )
            })

    return alerts


def save_alerts(alerts):
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=4)

    print(f"Alerts saved to: {OUTPUT_FILE}")


def main():
    print("\n=== SOC AUTHENTICATION CORRELATION ENGINE ===\n")

    if not LOG_FILE.exists():
        print("Evidence file not found.")
        return

    events = load_events()
    alerts = correlate_events(events)

    if not alerts:
        print("No correlated authentication activity detected.")
        save_alerts(alerts)
        return

    for alert in alerts:
        print("[CORRELATED ALERT]")
        print(f"Alert ID: {alert['alert_id']}")
        print(f"Account: {alert['username']}")
        print(f"Source IP: {alert['source_ip']}")
        print(f"Failed attempts: {alert['failed_attempts']}")
        print(f"Severity: {alert['severity']}")
        print(f"Assessment: {alert['assessment']}\n")

    save_alerts(alerts)


if __name__ == "__main__":
    main()
