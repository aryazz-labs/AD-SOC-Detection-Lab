# Roadmap

## Next validations (Active Directory attacks)
All use the dedicated `soc.testuser` account so lockouts never affect admin access.

| Detection | Technique | Planned test | What it proves |
|---|---|---|---|
| Password Spraying Detection | T1110.003 | Atomic T1110.003 against test users | Threshold logic: one password, many users |
| Multiple Failed Kerberos Auth | T1110.001 | Repeated bad passwords for `soc.testuser` | 4771 on DC01 counted over time |
| Suspicious Account Lockout | T1110 | Continue brute force until 4740 | Lockout correlation with source host |
| Failed → Successful Logon | T1110 | Bad passwords then correct password | Sequence detection (4625 → 4624) |
| Encoded PowerShell | T1059.001 | T1059.001-17 | Re-capture evidence from earlier validation |

## Known issues
- **`SOC - PowerShell Process Execution` is noisy.** It fired at 18:15, 20:00, 20:15, 20:30 and 20:45 on 16 Nov — far more than malicious activity. Likely matching routine PowerShell (including the test framework itself). Plan: baseline parent processes and command lines, then alert only on suspicious patterns (encoded commands, download cradles, hidden windows).
- **Scheduled-task detection parses only classic-format events** → covers the workstation, not DC01. Plan: convert to the `coalesce()` pattern used by the ACCT/PRIV detections, then validate with a scheduled task created on DC01.
- **Threshold alerts use 15-minute windows on a 5-minute schedule.** Intentional for slow attacks, but they need throttling to prevent repeat alerts — to be added and tested alongside their validation.

## Future improvements
- Add Sysmon to DC01 for process-level visibility on the domain controller.
- Build an analyst dashboard: alert volume by detection, hosts, and MITRE technique.
- Write incident-response runbooks for the Critical/High alerts.
- Note: Splunk is running on a trial licence; scheduled searches stop when it expires.
