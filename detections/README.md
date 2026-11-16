# Detection Catalogue

Each folder contains:
- `detection.spl` — the exact search saved in Splunk
- `detection.yml` — metadata: MITRE mapping, data source, schedule, severity, known false positives
- `README.md` — how it was validated, with evidence

| Detection | MITRE | Data source | Schedule / window | Status |
|---|---|---|---|---|
| [NTFS Alternate Data Stream](T1564.004-ntfs-ads/) | T1564.004 | Sysmon EID 15 | every 15 min / `-15m@m`→`@m` | ✅ Validated |
| [Scheduled Task Creation](T1053.005-scheduled-task/) | T1053.005 | Security 4698 | every 5 min / `-5m@m`→`@m` | ✅ Validated (workstation) |
| [New Account Created](T1136-account-created/) | T1136.001/.002 | Security 4720 (both formats) | every 5 min / `-5m@m`→`@m` | ✅ Validated (DC + workstation) |
| [Privileged Group Membership Added](T1098-privileged-group-added/) | T1098 | Security 4728/4732/4756 (both formats) | every 5 min / `-5m@m`→`@m` | ✅ Validated (DC + workstation) |
| Password Spraying | T1110.003 | Security 4625/4771 | every 5 min / 15 min | 🔄 Pending |
| Multiple Failed Kerberos Auth | T1110.001 | Security 4771 | every 5 min / 15 min | 🔄 Pending |
| Suspicious Account Lockout | T1110 | Security 4740 | every 5 min / 15 min | 🔄 Pending |
| Failed Logons → Successful Logon | T1110 | Security 4625→4624 | every 5 min / 10 min | 🔄 Pending |
| PowerShell Process Execution | T1059.001 | Security 4688 | every 5 min / 15 min | ⚠️ Noisy — tuning planned |

**Design conventions**
- Single-event detections use a window equal to the schedule (`-5m@m`→`@m`) so each event alerts exactly once — see [finding 2](../findings/02-duplicate-alerts-window-overlap.md).
- Threshold detections (spraying, brute force) keep a longer window than their schedule on purpose, so slow attacks still cross the threshold.
- Searches that cover the DC must parse **both** `XmlWinEventLog` and `WinEventLog` — see [finding 3](../findings/03-split-log-formats-blind-alerts.md).
