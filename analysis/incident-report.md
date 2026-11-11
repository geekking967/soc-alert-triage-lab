# SOC Incident Investigation Report

**Report generated:** 2026-11-11 16:15:03 South Africa Standard Time
**Project:** SOC Alert Triage Lab
**Environment:** Simulated security investigation
**Evidence type:** Synthetic Windows security events

---

## 1. Executive Summary

The detection engine generated **1 alert(s)** for investigation.

These alerts identify suspicious authentication patterns. They do not independently confirm account compromise.

---

## 2.1 Alert Investigation

**Alert ID:** SOC-AUTH-001
**Alert name:** Repeated Failed Logins Followed by Success
**Detection rule:** AUTH-001
**Severity:** Medium
**Investigation priority:** Prompt investigation recommended
**Status:** Requires Investigation

### Observed Evidence

- **Account:** j.smith
- **Source IP:** 203.0.113.45
- **Failed login attempts:** 3
- **Successful login time:** 2026-11-06T09:02:03
- **Network share events:** 1

### Analyst Assessment

Suspicious authentication sequence detected. Account compromise is not confirmed.

### Recommended Investigation Actions

- Verify whether the successful login was legitimate.
- Review the account's recent authentication history.
- Investigate the source IP and device context.
- Review network share activity and access permissions.

### Evidence Limitations

- The events used in this project are synthetic.
- A successful login following failed attempts does not prove account compromise.
- Network share access does not prove that files were read, copied, or exfiltrated.
- Additional endpoint, identity, and network evidence would be required for a real investigation.

---

## 3. Investigation Conclusion

This report documents alerts produced by the project's authentication correlation engine.

The alerts should be treated as investigation leads, not confirmed security incidents.

## 4. Project Disclaimer

This report was generated using synthetic evidence for educational and portfolio demonstration purposes. It does not represent a real organization's security environment or an actual security incident.
