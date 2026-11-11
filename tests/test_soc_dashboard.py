
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from generate_soc_dashboard import build_dashboard


def sample_alert(
    alert_id="SOC-AUTH-001",
    severity="Medium",
    username="j.smith"
):
    return {
        "alert_id": alert_id,
        "alert_name": "Repeated Failed Logins Followed by Success",
        "rule_id": "AUTH-001",
        "severity": severity,
        "investigation_priority": "Prompt investigation recommended",
        "status": "Requires Investigation",
        "username": username,
        "source_ip": "203.0.113.45",
        "failed_attempts": 3,
        "successful_login": "2026-11-06T09:02:03",
        "network_share_events": 1,
        "assessment": "Suspicious authentication sequence detected.",
        "recommended_actions": [
            "Verify whether the successful login was legitimate.",
            "Review authentication history."
        ]
    }


class TestSOCDashboard(unittest.TestCase):

    def test_dashboard_displays_total_alert_count(self):
        dashboard = build_dashboard([
            sample_alert(),
            sample_alert("SOC-AUTH-002")
        ])

        self.assertIn("Total Alerts", dashboard)
        self.assertIn("<h2>2</h2>", dashboard)

    def test_dashboard_counts_severity_levels(self):
        alerts = [
            sample_alert(severity="High"),
            sample_alert("SOC-AUTH-002", "Medium"),
            sample_alert("SOC-AUTH-003", "Low")
        ]

        dashboard = build_dashboard(alerts)

        self.assertIn("High Severity", dashboard)
        self.assertIn("Medium Severity", dashboard)
        self.assertIn("Low Severity", dashboard)

    def test_dashboard_displays_recommended_actions(self):
        dashboard = build_dashboard([sample_alert()])

        self.assertIn(
            "Verify whether the successful login was legitimate.",
            dashboard
        )

    def test_dashboard_handles_empty_alert_list(self):
        dashboard = build_dashboard([])

        self.assertIn("No correlated alerts found", dashboard)
        self.assertIn("Total Alerts", dashboard)

    def test_dashboard_escapes_html_in_alert_data(self):
        dashboard = build_dashboard([
            sample_alert(username="<script>alert('test')</script>")
        ])

        self.assertNotIn(
            "<script>alert('test')</script>",
            dashboard
        )

        self.assertIn("&lt;script&gt;", dashboard)


if __name__ == "__main__":
    unittest.main()
