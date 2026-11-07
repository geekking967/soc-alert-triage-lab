# Detection Results — SOC Case 001

## 1. Detection Overview

- Case ID: SOC-001
- Detection Name: Repeated Failed Login Detection
- Tool: Python
- Input: Synthetic Windows Security Event Logs
- Event ID monitored: 4625
- Detection threshold: 3 failed attempts
- Time window: 60 seconds
- Result: Alert successfully generated

## 2. Detection Logic

The Python script examines security events and identifies
repeated failed login attempts.

It groups failed authentication events by:

- Username
- Source IP address

An alert is generated when at least three failed attempts
occur within a 60-second window for the same account and
source IP address.

## 3. Detection Results

The script identified the following activity:

| Field | Result |
|---|---|
| Account | j.smith |
| Source IP | 203.0.113.45 |
| Failed attempts | 3 |
| First attempt | 09:01:12 |
| Last attempt | 09:01:29 |
| Detection window | 17 seconds |
| Alert status | Detected |

## 4. Analyst Assessment

The detection identified three failed authentication attempts
within approximately 17 seconds.

This pattern may be consistent with password guessing or
other suspicious authentication activity.

However, the alert alone does not establish malicious intent
or prove that an account was compromised.

## 5. Recommended Actions

1. Verify whether the login attempts were expected.
2. Investigate the source device and account.
3. Review subsequent successful authentication events.
4. Check for additional suspicious activity.
5. Escalate if further evidence indicates account compromise.

## 6. Detection Limitations

The current version:

- Processes CSV files rather than collecting live Windows events.
- Uses a fixed detection threshold and time window.
- Groups events using username and source IP.
- Does not yet correlate failed attempts with successful logins.
- Does not independently determine whether activity is malicious.

## 7. Conclusion

The Python detection tool successfully identified the
simulated repeated failed-login pattern.

This demonstrates a basic security event detection capability
using Python and structured log data.

Further development will focus on improving detection accuracy,
event correlation and investigation reporting.

## 8. Data Disclaimer

All accounts, IP addresses and event records used in this
exercise are fictional or synthetic.

This is an educational cybersecurity project.
