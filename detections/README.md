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
| [Multiple Failed Kerberos Auth](T1110.001-kerberos-brute-force/) | T1110.001 | Security 4771 (`0x18`), DC01 | every 5 min / 15 min | ✅ Validated |
| [Password Spraying](T1110.003-password-spraying/) | T1110.003 | Security 4771 (`0x18`), DC01 | every 5 min / 15 min | ✅ Validated |
| [Suspicious Account Lockout](T1110-account-lockout/) | T1110 | Security 4740, DC01 | every 5 min / 15 min | ✅ Validated |
| [Multiple Failed Logon (endpoint)](T1110-failed-logon-endpoint/) | T1110 | Security 4625, workstation | every 5 min / 10 min | ✅ Validated |
| [Failed Logons → Successful Logon](T1110-failed-then-successful-logon/) | T1110 | Security 4625 → 4624, workstation | every 5 min / 10 min | ✅ Validated |
| PowerShell Process Execution | T1059.001 | Security 4688 | every 5 min / 15 min | ⚠️ Noisy — tuning planned |

**Design conventions**
- Single-event detections use a window equal to the schedule (`-5m@m`→`@m`) so each event alerts exactly once — see [finding 2](../findings/02-duplicate-alerts-window-overlap.md).
- Threshold detections (spraying, brute force) keep a longer window than their schedule on purpose, so slow attacks still cross the threshold — and must pair that window with **throttling** (`alert.suppress`) to avoid duplicate fires. The SOC logon alerts always did; the three AD alerts now do too (applied 2026-11-17) — see [finding 5](../findings/05-ad-alerts-no-throttling.md).
- Endpoint logon detections (4625 on the workstation) and DC Kerberos detections (4771 on the DC) see **different** auth paths; pick the validation method to match the event source — see [finding 4](../findings/04-endpoint-alerts-not-art-drivable.md).
- Searches that cover the DC must parse **both** `XmlWinEventLog` and `WinEventLog` — see [finding 3](../findings/03-split-log-formats-blind-alerts.md).
