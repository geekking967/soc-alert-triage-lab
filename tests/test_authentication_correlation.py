
import sys
import unittest
from pathlib import Path
from datetime import datetime

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from correlate_authentication_events import (
    correlate_events,
    assess_severity
)


def make_event(event_id, timestamp):
    return {
        "event_id": event_id,
        "username": "j.smith",
        "source_ip": "203.0.113.45",
        "parsed_time": datetime.fromisoformat(timestamp)
    }


def build_events(failed_count, include_share=False):
    events = []

    for number in range(failed_count):
        seconds = number * 5

        events.append(
            make_event(
                "4625",
                f"2026-11-06T09:00:{seconds:02d}"
            )
        )

    events.append(
        make_event("4624", "2026-11-06T09:02:00")
    )

    if include_share:
        events.append(
            make_event("5140", "2026-11-06T09:03:00")
        )

    return events


class TestAuthenticationCorrelation(unittest.TestCase):

    def test_detects_three_failures_within_60_seconds(self):
        alerts = correlate_events(build_events(3))
        self.assertEqual(len(alerts), 1)

    def test_ignores_only_two_failed_logins(self):
        alerts = correlate_events(build_events(2))
        self.assertEqual(len(alerts), 0)

    def test_ignores_success_outside_five_minute_window(self):
        events = [
            make_event("4625", "2026-11-06T09:00:00"),
            make_event("4625", "2026-11-06T09:00:30"),
            make_event("4625", "2026-11-06T09:01:00"),
            make_event("4624", "2026-11-06T09:07:00"),
        ]

        self.assertEqual(len(correlate_events(events)), 0)

    def test_ignores_failures_spread_over_60_seconds(self):
        events = [
            make_event("4625", "2026-11-06T09:00:00"),
            make_event("4625", "2026-11-06T09:00:30"),
            make_event("4625", "2026-11-06T09:01:01"),
            make_event("4624", "2026-11-06T09:02:00"),
        ]

        self.assertEqual(len(correlate_events(events)), 0)

    def test_low_severity_assessment(self):
        severity, _ = assess_severity(3, 0)
        self.assertEqual(severity, "Low")

    def test_medium_severity_assessment(self):
        severity, _ = assess_severity(5, 0)
        self.assertEqual(severity, "Medium")

    def test_high_severity_assessment(self):
        severity, _ = assess_severity(10, 1)
        self.assertEqual(severity, "High")

    def test_network_share_activity_increases_severity(self):
        severity, _ = assess_severity(3, 1)
        self.assertEqual(severity, "Medium")

    def test_alert_contains_investigation_recommendations(self):
        alerts = correlate_events(build_events(3, include_share=True))

        self.assertEqual(len(alerts), 1)
        self.assertIn("recommended_actions", alerts[0])
        self.assertGreater(len(alerts[0]["recommended_actions"]), 0)

    def test_alert_contains_investigation_priority(self):
        alerts = correlate_events(build_events(3))

        self.assertEqual(len(alerts), 1)
        self.assertIn("investigation_priority", alerts[0])


if __name__ == "__main__":
    unittest.main()
