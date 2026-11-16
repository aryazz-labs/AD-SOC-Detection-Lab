# Roadmap

## Recently validated (17 Nov 2026) ✅
All five used the dedicated `soc.testuser` account so lockouts never affect admin access.

| Detection | Technique | Validated with | What it proved |
|---|---|---|---|
| [Password Spraying](../detections/T1110.003-password-spraying/) | T1110.003 | Atomic T1110.003-1 | Threshold logic: one password, many users (6 distinct) |
| [Multiple Failed Kerberos Auth](../detections/T1110.001-kerberos-brute-force/) | T1110.001 | Manual + Atomic T1110.001-1 (`user=soc.testuser`) | 4771 `0x18` counted per account on DC01 |
| [Suspicious Account Lockout](../detections/T1110-account-lockout/) | T1110 | Manual + Atomic T1110.001-1 | 4740 correlated with the source |
| [Multiple Failed Logon (endpoint)](../detections/T1110-failed-logon-endpoint/) | T1110 | Manual `LogonUser` | Endpoint-local 4625 — see [finding 4](../findings/04-endpoint-alerts-not-art-drivable.md) |
| [Failed → Successful Logon](../detections/T1110-failed-then-successful-logon/) | T1110 | Manual `LogonUser` | Sequence 4625 → 4624 in one 10-min bin |

## Next validations

| Detection | Technique | Planned test | What it proves |
|---|---|---|---|
| Encoded PowerShell | T1059.001 | T1059.001-17 | Re-capture evidence from an earlier session's validation |
| Scheduled Task on DC01 | T1053.005 | Create a task **on the DC** after converting the alert to `coalesce()` | Both-format coverage (currently workstation-only) |

## Known issues
- **AD threshold alerts throttling — fix applied, after-test pending.** `AD - Multiple Failed Kerberos`, `AD - Password Spraying` and `AD - Suspicious Account Lockout` originally had `alert.suppress=false`, so one incident re-alerted every run (11 / 9 / 3 fires — [finding 5](../findings/05-ad-alerts-no-throttling.md)). `alert.suppress=1` (15m, keyed to `TargetUserName` / `IpAddress`) was applied 2026-11-17. **Next: re-run the atomics to confirm each incident now fires once, and capture the before/after.**
- **`SOC - PowerShell Process Execution` is noisy.** It fired at 18:15, 20:00, 20:15, 20:30 and 20:45 on 16 Nov — far more than malicious activity, matching routine PowerShell (including the test framework itself). Plan: baseline parent processes and command lines, then alert only on suspicious patterns (encoded commands, download cradles, hidden windows). Write up as a tuning finding.
- **Scheduled-task detection parses only classic-format events** → covers the workstation, not DC01. Plan: convert to the `coalesce()` pattern used by the ACCT/PRIV detections, then validate with a scheduled task created on DC01.

## Future improvements
- Apply the throttling fix to the 3 AD alerts, then document before/after (ties off finding 5).
- Add Sysmon to DC01 for process-level visibility on the domain controller.
- Build an analyst dashboard: alert volume by detection, host, and MITRE technique.
- Write incident-response runbooks for the Critical/High alerts.
- Résumé bullets + a LinkedIn write-up of the project.
- Note: Splunk is running on a trial licence; scheduled searches stop when it expires.
