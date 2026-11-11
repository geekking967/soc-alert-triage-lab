
import json
from pathlib import Path
from datetime import datetime


BASE_DIR = Path(__file__).resolve().parent.parent

ALERT_FILE = BASE_DIR / "output" / "correlated-alerts.json"
REPORT_FILE = BASE_DIR / "analysis" / "incident-report.md"


def load_alerts():
    if not ALERT_FILE.exists():
        raise FileNotFoundError(
            f"Alert file not found: {ALERT_FILE}"
        )

    with open(ALERT_FILE, "r", encoding="utf-8") as file:
        alerts = json.load(file)

    if not isinstance(alerts, list):
        raise ValueError("The alert file must contain a JSON list.")

    return alerts


def build_report(alerts):
    report_time = datetime.now().astimezone().strftime(
        "%Y-%m-%d %H:%M:%S %Z"
    )

    lines = [
        "# SOC Incident Investigation Report",
        "",
        f"**Report generated:** {report_time}",
        "**Project:** SOC Alert Triage Lab",
        "**Environment:** Simulated security investigation",
        "**Evidence type:** Synthetic Windows security events",
        "",
        "---",
        "",
        "## 1. Executive Summary",
        "",
        f"The detection engine generated **{len(alerts)} alert(s)** "
        "for investigation.",
        "",
        "These alerts identify suspicious authentication patterns. "
        "They do not independently confirm account compromise.",
        "",
    ]

    if not alerts:
        lines.extend([
            "No correlated authentication alerts were generated.",
            "",
            "No incident conclusion can be drawn from the absence "
            "of an alert alone.",
            "",
        ])

    for number, alert in enumerate(alerts, start=1):
        lines.extend([
            "---",
            "",
            f"## 2.{number} Alert Investigation",
            "",
            f"**Alert ID:** {alert.get('alert_id', 'Not provided')}",
            f"**Alert name:** {alert.get('alert_name', 'Not provided')}",
            f"**Detection rule:** {alert.get('rule_id', 'Not provided')}",
            f"**Severity:** {alert.get('severity', 'Not assessed')}",
            f"**Investigation priority:** "
            f"{alert.get('investigation_priority', 'Not provided')}",
            f"**Status:** {alert.get('status', 'Not provided')}",
            "",
            "### Observed Evidence",
            "",
            f"- **Account:** {alert.get('username', 'Unknown')}",
            f"- **Source IP:** {alert.get('source_ip', 'Unknown')}",
            f"- **Failed login attempts:** "
            f"{alert.get('failed_attempts', 0)}",
            f"- **Successful login time:** "
            f"{alert.get('successful_login', 'Unknown')}",
            f"- **Network share events:** "
            f"{alert.get('network_share_events', 0)}",
            "",
            "### Analyst Assessment",
            "",
            alert.get(
                "assessment",
                "No assessment was provided by the detection engine."
            ),
            "",
            "### Recommended Investigation Actions",
            "",
        ])

        actions = alert.get("recommended_actions", [])

        if actions:
            for action in actions:
                lines.append(f"- {action}")
        else:
            lines.append("- No investigation actions were supplied.")

        lines.extend([
            "",
            "### Evidence Limitations",
            "",
            "- The events used in this project are synthetic.",
            "- A successful login following failed attempts does not "
            "prove account compromise.",
            "- Network share access does not prove that files were "
            "read, copied, or exfiltrated.",
            "- Additional endpoint, identity, and network evidence "
            "would be required for a real investigation.",
            "",
        ])

    lines.extend([
        "---",
        "",
        "## 3. Investigation Conclusion",
        "",
        "This report documents alerts produced by the project's "
        "authentication correlation engine.",
        "",
        "The alerts should be treated as investigation leads, not "
        "confirmed security incidents.",
        "",
        "## 4. Project Disclaimer",
        "",
        "This report was generated using synthetic evidence for "
        "educational and portfolio demonstration purposes. "
        "It does not represent a real organization's security "
        "environment or an actual security incident.",
        "",
    ])

    return "\n".join(lines)


def save_report(report):
    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(REPORT_FILE, "w", encoding="utf-8") as file:
        file.write(report)

    print(f"Investigation report generated: {REPORT_FILE}")


def main():
    print("\n=== SOC INCIDENT REPORT GENERATOR ===\n")

    try:
        alerts = load_alerts()
        report = build_report(alerts)
        save_report(report)

        print(f"Alerts documented: {len(alerts)}")
        print("Report generation completed successfully.")

    except (FileNotFoundError, ValueError, json.JSONDecodeError) as error:
        print(f"Report generation failed: {error}")


if __name__ == "__main__":
    main()
