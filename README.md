# SOC Alert Triage Lab

A practical cybersecurity portfolio project demonstrating
Security Operations Centre (SOC) alert triage, Windows event
log analysis, incident investigation and response recommendations.

## Project Overview

This project simulates a SOC investigation involving suspicious
authentication activity on a fictional Windows environment.

The scenario involves multiple failed login attempts followed
by a successful login and subsequent network share access.

The objective is to investigate the activity, establish a timeline,
assess potential risks and recommend appropriate incident response
actions.

**Project Type:** Simulated SOC Investigation  
**Focus Area:** Security Operations and Incident Response  
**Status:** In Progress  
**Author:** Nkissu Lumayi

## Investigation Scenario

A fictional user account, `j.smith`, experiences several failed
authentication attempts originating from an unfamiliar IP address.

A successful login follows these attempts. Shortly afterwards,
the account accesses a network share.

As a SOC analyst, the task is to determine whether this activity
represents normal user behaviour or a potential account compromise.

All events and identities used in this project are fictional.

## Investigation Objectives

- Identify suspicious authentication patterns.
- Analyse failed and successful Windows logon events.
- Build a chronological incident timeline.
- Examine potential indicators of account compromise.
- Assess the severity and potential impact of the activity.
- Recommend containment and remediation measures.
- Document investigation findings professionally.

## Tools and Technologies

- Windows Security Event Logs
- Windows Event Viewer
- Microsoft Windows Event IDs
- GitHub
- Python (planned for log analysis)

## Windows Event IDs Under Investigation

| Event ID | Description |
|----------|-------------|
| 4625 | Failed logon attempt |
| 4624 | Successful logon |
| 5140 | Network share accessed |

## Investigation Methodology

1. Collect and review relevant security events.
2. Identify unusual authentication activity.
3. Correlate events by account, source address and timestamp.
4. Establish an incident timeline.
5. Assess the likelihood and impact of account compromise.
6. Develop appropriate response recommendations.
7. Document findings and lessons learned.

## Expected Deliverables

- Sample security event logs.
- Incident timeline.
- Alert triage and analysis.
- Investigation findings.
- Risk assessment.
- Incident response recommendations.
- Final investigation report.

## Disclaimer

This repository is an educational cybersecurity laboratory.

All scenarios, accounts, IP addresses and event records are
fictional or synthetic. No unauthorised access, real-world attacks
or testing against third-party systems are performed.

