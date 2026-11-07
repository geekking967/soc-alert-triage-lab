
import sys
import unittest
from pathlib import Path
from datetime import datetime

# Make the scripts folder available for imports
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from correlate_authentication_events import correlate_events


def make_event(event_id, timestamp):
    return {
        "event_id": event_id,
        "username": "j.smith",
        "source_ip": "203.0.113.45",
        "parsed_time": datetime.fromisoformat(timestamp)
    }


class TestAuthenticationCorrelation(unittest.TestCase):

    def test_detects_three_failures_followed_by_success(self):
        events = [
            make_event("4625", "2026-11-06T09:01:12"),
            make_event("4625", "2026-11-06T09:01:20"),
            make_event("4625", "2026-11-06T09:01:29"),
            make_event("4624", "2026-11-06T09:02:03"),
        ]

        alerts = correlate_events(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["failed_attempts"], 3)

    def test_ignores_only_two_failed_logins(self):
        events = [
            make_event("4625", "2026-11-06T09:01:12"),
            make_event("4625", "2026-11-06T09:01:20"),
            make_event("4624", "2026-11-06T09:02:03"),
        ]

        alerts = correlate_events(events)

        self.assertEqual(len(alerts), 0)

    def test_ignores_success_outside_five_minute_window(self):
        events = [
            make_event("4625", "2026-11-06T09:00:00"),
            make_event("4625", "2026-11-06T09:00:30"),
            make_event("4625", "2026-11-06T09:01:00"),
            make_event("4624", "2026-11-06T09:07:00"),
        ]

        alerts = correlate_events(events)

        self.assertEqual(len(alerts), 0)


if __name__ == "__main__":
    unittest.main()
