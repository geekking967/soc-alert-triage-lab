
# SOC Alert Triage Lab

A Python-based Security Operations Centre (SOC) alert triage and investigation laboratory built to demonstrate authentication-event detection, event correlation, severity assessment, incident reporting, and security dashboard visualisation.

## Project Overview

The SOC Alert Triage Lab simulates a basic SOC investigation workflow using synthetic Windows security event data.

The project identifies suspicious authentication activity, correlates failed and successful login events, evaluates alert severity, generates structured JSON alerts, produces incident investigation reports, and displays results through a local SOC dashboard.

It demonstrates practical cybersecurity skills relevant to SOC Analyst, Security Analyst, and Incident Response roles.

**Project type:** Cybersecurity / SOC Operations  
**Programming language:** Python  
**Platform:** Windows  
**Evidence source:** Synthetic Windows security event data  
**Project status:** Completed

## Project Objectives

The main objectives are to:

- Detect repeated failed authentication attempts.
- Identify successful logins following suspicious authentication activity.
- Correlate related Windows security events.
- Assess alert severity and investigation priority.
- Generate structured security alerts in JSON format.
- Produce professional incident investigation reports.
- Visualise security alerts through an HTML dashboard.
- Validate detection and dashboard functionality through automated tests.

## Project Architecture

The project follows a simple security monitoring and investigation workflow:

1. Synthetic Windows security events are loaded from a CSV evidence file.
2. Python detection scripts analyse authentication activity.
3. Related events are correlated to identify suspicious patterns.
4. Alerts are assigned severity levels and investigation recommendations.
5. Correlated alerts are exported as JSON.
6. An incident report is generated in Markdown.
7. A local HTML dashboard presents the investigation results.
8. Automated tests validate the detection and dashboard functionality.

## Detection Rule: AUTH-001

**Rule name:** Repeated Failed Logins Followed by Success

**Purpose:** Identify potentially suspicious authentication sequences.

The detection logic identifies:

- Three or more failed login attempts within 60 seconds.
- A subsequent successful login within five minutes.
- Matching username and source IP address across the correlated events.

### Windows Event IDs

| Event ID | Description |
|---|---|
| 4625 | Failed logon |
| 4624 | Successful logon |
| 5140 | Network share accessed |

The system uses these events to build an authentication activity timeline and provide additional investigation context.

## Alert Severity Assessment

The lab uses a basic rule-based severity assessment:

| Severity | Condition |
|---|---|
| High | 10 or more failed attempts and at least one network share event |
| Medium | 5 or more failed attempts, or at least one network share event |
| Low | Other qualifying authentication sequences |

These thresholds are provisional rules created for this laboratory. They are not an official industry severity standard.

## Alert Investigation

Generated alerts include information such as:

- Alert ID and detection rule.
- Alert name and severity.
- Investigation priority.
- Username and source IP address.
- Number of failed authentication attempts.
- Successful login timestamp.
- Number of network share events.
- Initial security assessment.
- Recommended analyst investigation actions.

The system generates structured JSON output to support further analysis.

## Incident Reporting

The incident report generator creates a Markdown investigation report containing:

- Executive summary.
- Alert details.
- Severity and investigation priority.
- Available supporting evidence.
- Initial assessment.
- Recommended investigation actions.
- Technical limitations.
- Conclusion.

Generated report:

`analysis/incident-report.md`

## SOC Dashboard

The project includes a locally generated HTML dashboard.

The dashboard provides visibility into:

- Total alerts.
- High, medium, and low severity alerts.
- User accounts associated with alerts.
- Source IP addresses.
- Failed authentication attempts.
- Successful login timestamps.
- Network share event counts.
- Alert investigation status.
- Recommended analyst actions.

### SOC Dashboard — Overview

![SOC Dashboard Screenshot - LAB1](screenshots/Screenshot%20LAB1.jpg)

### SOC Dashboard — Alert Details

![SOC Dashboard Screenshot - LAB2](screenshots/Screenshot%20LAB2.jpg)

Generated dashboard:

`output/soc-dashboard.html`

The dashboard is a static local visualisation. It is not a live monitoring platform.

## Project Structure

```text
soc-alert-triage-lab/
│
├── analysis/
│   ├── initial-triage.md
│   ├── detection-results.md
│   └── incident-report.md
│
├── evidence/
│   └── sample-windows-events.csv
│
├── output/
│   ├── .gitkeep
│   └── correlated-alerts.json
│
├── scripts/
│   ├── detect_failed_logins.py
│   ├── correlate_authentication_events.py
│   ├── generate_incident_report.py
│   └── generate_soc_dashboard.py
│
├── tests/
│   ├── test_authentication_correlation.py
│   └── test_soc_dashboard.py
│
└── README.md
```

## Technologies and Tools

- **Python 3:** Detection logic, event correlation, reporting and dashboard generation.
- **CSV:** Synthetic Windows security event evidence.
- **JSON:** Structured alert output.
- **HTML and CSS:** SOC dashboard presentation.
- **Markdown:** Incident investigation documentation.
- **Unittest:** Automated testing.
- **Windows PowerShell:** Project execution and testing.
- **GitHub:** Source code management and portfolio presentation.

## How to Run the Project

### 1. Clone the repository

```powershell
git clone https://github.com/geekking967/soc-alert-triage-lab.git
```

### 2. Open the project directory

```powershell
cd soc-alert-triage-lab
```

### 3. Run the authentication detection script

```powershell
py scripts/detect_failed_logins.py
```

### 4. Run the authentication correlation script

```powershell
py scripts/correlate_authentication_events.py
```

### 5. Generate the incident report

```powershell
py scripts/generate_incident_report.py
```

### 6. Generate the SOC dashboard

```powershell
py scripts/generate_soc_dashboard.py
```

### 7. Open the dashboard

Open the generated file in your browser:

```text
output/soc-dashboard.html
```

### 8. Run automated tests

```powershell
py -m unittest discover -s tests -v
```

The completed project test suite contains **15 automated tests** covering authentication correlation, severity assessment, investigation recommendations, dashboard metrics, empty alert handling, and HTML escaping.

## Security Testing and Validation

The project includes automated tests designed to validate:

- Detection of repeated failed logins.
- Handling of insufficient failed login attempts.
- Authentication correlation time windows.
- Severity assessment.
- Investigation recommendations.
- Dashboard alert counts.
- Severity-level presentation.
- Recommended action presentation.
- Empty alert handling.
- HTML escaping of alert data.

**Test result:** 15 tests passed.

## Important Technical Limitations

This project is an educational SOC laboratory and has the following limitations:

1. It uses synthetic Windows event data rather than live endpoint logs.
2. It does not collect events directly from Windows systems.
3. It does not provide continuous or real-time monitoring.
4. Its detection thresholds are simplified laboratory rules.
5. Authentication correlation uses simplified username and source IP matching.
6. Event ID 5140 indicates network share access; it does not independently prove file access, downloading, or data exfiltration.
7. A successful login following failed attempts does not independently establish that an account was compromised.
8. The dashboard is a static visualisation and must be regenerated to reflect updated data.

The system is not a production SIEM or a replacement for enterprise security monitoring solutions.

## Skills Demonstrated

Through this project, I developed and demonstrated practical experience in:

- Security event analysis.
- Authentication monitoring.
- Detection engineering fundamentals.
- Event correlation.
- SOC alert triage.
- Severity assessment.
- Incident investigation workflows.
- Python scripting for cybersecurity.
- JSON-based security data handling.
- Incident report generation.
- Security dashboard development.
- Automated testing and validation.
- Technical documentation.

## Author

**Nkissu Lumayi**

Cybersecurity Graduate | Aspiring SOC Analyst | Cybersecurity Enthusiast



---

*This project was independently developed as a practical cybersecurity learning and portfolio initiative using synthetic security event data.*
