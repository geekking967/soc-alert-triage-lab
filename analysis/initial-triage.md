# Initial SOC Alert Triage — Case 001

## 1. Case Information

- Case ID: SOC-001
- Analyst: Nkissu Lumayi
- Investigation Type: Authentication Anomaly
- Environment: Fictional Windows environment
- Status: Initial triage
- Data Classification: Synthetic training data

## 2. Alert Summary

A fictional user account, j.smith, recorded three consecutive
failed login attempts followed by a successful login.

The events originated from the same simulated IP address:
203.0.113.45.

A network share access event was subsequently recorded.

This activity requires further investigation to determine
whether the login attempts were legitimate or malicious.

## 3. Evidence Observed

| Time | Event ID | Activity |
|------|----------|----------|
| 09:01:12 | 4625 | Failed login |
| 09:01:20 | 4625 | Failed login |
| 09:01:29 | 4625 | Failed login |
| 09:02:03 | 4624 | Successful login |
| 09:04:11 | 5140 | Network share accessed |

## 4. Initial Findings

1. Three failed authentication attempts occurred within
   approximately 17 seconds.

2. A successful authentication event followed the failures.

3. The simulated source IP address was consistent across
   the authentication events.

4. A network share access event followed the successful login.

5. The sequence may indicate password guessing or suspicious
   account activity, but does not establish account compromise.

## 5. Potential Security Risks

- Possible unauthorised account access.
- Potential exposure of information on a network share.
- Possible password guessing activity.

## 6. Recommended Investigation

- Confirm whether the user initiated the login.
- Identify the source device and its ownership.
- Examine the Windows logon type and authentication details.
- Review surrounding security events.
- Check for unusual privilege changes or further network activity.
- Verify whether the network share access was expected.

## 7. Preliminary Assessment

Priority: Medium — provisional.

Reason:
Repeated failed logins followed by a successful login
warrant investigation.

The available synthetic evidence is insufficient to confirm
a security incident or account compromise.

## 8. Conclusion

The activity has been identified as potentially suspicious
and requires further investigation.

No definitive conclusion about compromise can be made
from the available evidence.

## 9. Evidence Limitations

This investigation uses simplified synthetic event records.

The records do not contain all the fields available in actual
Windows Security Event Logs.

The IP address, account and events are fictional.

This is a self educational exercise, not a real incident investigation.
