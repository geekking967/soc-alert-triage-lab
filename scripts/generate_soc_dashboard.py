
import json
import html
from pathlib import Path
from collections import Counter
from datetime import datetime


BASE_DIR = Path(__file__).resolve().parent.parent

ALERT_FILE = BASE_DIR / "output" / "correlated-alerts.json"
DASHBOARD_FILE = BASE_DIR / "output" / "soc-dashboard.html"


def load_alerts():
    if not ALERT_FILE.exists():
        raise FileNotFoundError(
            f"Alert file not found: {ALERT_FILE}"
        )

    with open(ALERT_FILE, "r", encoding="utf-8") as file:
        alerts = json.load(file)

    if not isinstance(alerts, list):
        raise ValueError("Alert data must be a JSON list.")

    return alerts


def safe(value):
    return html.escape(str(value))


def build_dashboard(alerts):
    severity_counts = Counter(
        alert.get("severity", "Unclassified")
        for alert in alerts
    )

    high = severity_counts.get("High", 0)
    medium = severity_counts.get("Medium", 0)
    low = severity_counts.get("Low", 0)

    total = len(alerts)

    alert_cards = []

    for alert in alerts:
        severity = alert.get("severity", "Unclassified")
        severity_class = severity.lower()

        if severity_class not in ["high", "medium", "low"]:
            severity_class = "unknown"

        actions = alert.get("recommended_actions", [])

        action_html = "".join(
            f"<li>{safe(action)}</li>"
            for action in actions
        )

        if not action_html:
            action_html = "<li>No recommendations provided.</li>"

        alert_cards.append(f"""
        <article class="alert-card">
            <div class="alert-header">
                <h3>{safe(alert.get('alert_name', 'Unnamed alert'))}</h3>
                <span class="severity {severity_class}">
                    {safe(severity)}
                </span>
            </div>

            <p class="alert-id">
                {safe(alert.get('alert_id', 'Unknown ID'))}
                | Rule: {safe(alert.get('rule_id', 'Unknown'))}
            </p>

            <div class="details">
                <div>
                    <span>Account</span>
                    <strong>{safe(alert.get('username', 'Unknown'))}</strong>
                </div>
                <div>
                    <span>Source IP</span>
                    <strong>{safe(alert.get('source_ip', 'Unknown'))}</strong>
                </div>
                <div>
                    <span>Failed logins</span>
                    <strong>{safe(alert.get('failed_attempts', 0))}</strong>
                </div>
                <div>
                    <span>Share events</span>
                    <strong>{safe(alert.get('network_share_events', 0))}</strong>
                </div>
                <div>
                    <span>Successful login</span>
                    <strong>{safe(alert.get('successful_login', 'Unknown'))}</strong>
                </div>
                <div>
                    <span>Status</span>
                    <strong>{safe(alert.get('status', 'Unknown'))}</strong>
                </div>
            </div>

            <p class="assessment">
                {safe(alert.get('assessment', 'No assessment available.'))}
            </p>

            <h4>Recommended analyst actions</h4>
            <ul>{action_html}</ul>
        </article>
        """)

    if not alert_cards:
        alert_content = """
        <div class="empty-state">
            <h3>No correlated alerts found</h3>
            <p>The current alert dataset contains no investigation records.</p>
        </div>
        """
    else:
        alert_content = "\n".join(alert_cards)

    generated_at = datetime.now().astimezone().strftime(
        "%Y-%m-%d %H:%M:%S %Z"
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<title>SOC Security Dashboard</title>

<style>
* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;
    background: #f3f5f8;
    color: #1d2939;
    font-family: Arial, sans-serif;
}}

header {{
    background: #14243a;
    color: white;
    padding: 28px 6%;
}}

header h1 {{
    margin: 0 0 8px;
    font-size: 27px;
}}

header p {{
    margin: 0;
    color: #cbd5e1;
}}

main {{
    max-width: 1150px;
    margin: 30px auto;
    padding: 0 20px;
}}

.section-title {{
    margin: 30px 0 15px;
}}

.metrics {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
    gap: 15px;
}}

.metric {{
    background: white;
    padding: 22px;
    border-radius: 10px;
    border: 1px solid #e2e8f0;
}}

.metric span {{
    color: #64748b;
    font-size: 13px;
}}

.metric h2 {{
    margin: 10px 0 0;
    font-size: 30px;
}}

.alert-card {{
    background: white;
    border: 1px solid #e2e8f0;
    border-radius: 10px;
    padding: 22px;
    margin-bottom: 18px;
}}

.alert-header {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    flex-wrap: wrap;
}}

.alert-header h3 {{
    margin: 0;
    font-size: 18px;
}}

.severity {{
    padding: 6px 12px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: bold;
}}

.high {{
    background: #fee2e2;
    color: #991b1b;
}}

.medium {{
    background: #fef3c7;
    color: #92400e;
}}

.low {{
    background: #dcfce7;
    color: #166534;
}}

.unknown {{
    background: #e2e8f0;
    color: #334155;
}}

.alert-id {{
    color: #64748b;
    font-size: 12px;
    margin-top: 10px;
}}

.details {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 16px;
    margin: 22px 0;
}}

.details span {{
    display: block;
    color: #64748b;
    font-size: 12px;
    margin-bottom: 5px;
}}

.details strong {{
    font-size: 14px;
    overflow-wrap: anywhere;
}}

.assessment {{
    background: #f1f5f9;
    padding: 14px;
    border-radius: 7px;
    line-height: 1.5;
}}

.alert-card h4 {{
    margin-bottom: 8px;
}}

.alert-card li {{
    margin: 8px 0;
    line-height: 1.4;
}}

.empty-state {{
    background: white;
    border: 1px solid #e2e8f0;
    padding: 30px;
    border-radius: 10px;
    text-align: center;
}}

footer {{
    color: #64748b;
    text-align: center;
    padding: 30px 15px;
    font-size: 12px;
}}

@media (max-width: 600px) {{
    header h1 {{
        font-size: 22px;
    }}

    .alert-card {{
        padding: 16px;
    }}
}}
</style>
</head>

<body>

<header>
    <h1>SOC Security Dashboard</h1>
    <p>Authentication monitoring and alert investigation</p>
</header>

<main>

    <h2 class="section-title">Security Overview</h2>

    <section class="metrics">
        <div class="metric">
            <span>Total Alerts</span>
            <h2>{total}</h2>
        </div>

        <div class="metric">
            <span>High Severity</span>
            <h2>{high}</h2>
        </div>

        <div class="metric">
            <span>Medium Severity</span>
            <h2>{medium}</h2>
        </div>

        <div class="metric">
            <span>Low Severity</span>
            <h2>{low}</h2>
        </div>
    </section>

    <h2 class="section-title">Authentication Alerts</h2>

    {alert_content}

</main>

<footer>
    Generated: {safe(generated_at)}<br>
    SOC Alert Triage Lab | Educational simulation using synthetic evidence
</footer>

</body>
</html>"""


def save_dashboard(content):
    DASHBOARD_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(DASHBOARD_FILE, "w", encoding="utf-8") as file:
        file.write(content)

    print(f"Dashboard generated: {DASHBOARD_FILE}")


def main():
    print("\n=== SOC DASHBOARD GENERATOR ===\n")

    try:
        alerts = load_alerts()
        dashboard = build_dashboard(alerts)
        save_dashboard(dashboard)

        print(f"Alerts displayed: {len(alerts)}")
        print("Dashboard generation completed successfully.")

    except (FileNotFoundError, ValueError, json.JSONDecodeError) as error:
        print(f"Dashboard generation failed: {error}")


if __name__ == "__main__":
    main()
