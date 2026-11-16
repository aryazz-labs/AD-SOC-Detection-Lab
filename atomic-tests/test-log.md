# Atomic Red Team Test Log

All times IST, 16 November 2026. Tests run on WINDOWS-11-PRO as `CORP\Administrator`. Every test was cleaned up and the cleanup verified.

| Time | Test | Action | Expected telemetry | Observed | Alert | Cleanup |
|---|---|---|---|---|---|---|
| 08:38 | T1059.001-11 | Write + execute command in ADS | Sysmon 15 | ✅ | — (alert not yet built) | ✅ |
| 20:03 | T1059.001-11 | Re-run to test saved alert | Sysmon 15 | ✅ 20:03:49 | ✅ ADS @ 20:15:02 | ✅ |
| 20:09 | T1053.005-2 | `schtasks /Create /TN spawn` | Security 4698 | ❌ **Sysmon only** → [finding 1](../findings/01-audit-policy-reset-by-gpo.md) | ❌ | ✅ 20:13:43 (4699) |
| 20:15 | T1053.005-2 | Re-run after audit fix | Security 4698 | ✅ 20:15:09 | ✅ @ 20:20:01 | ✅ 20:22:47 (4699) |
| 20:25 | T1053.005-4 | `Register-ScheduledTask AtomicTask` | Security 4698 | ✅ 20:25:11 | ✅ @ 20:30:01 | ✅ 20:33:07 (4699) |
| 21:47 | T1136.002-1 | Domain user → Domain Admins | DC 4720, 4728 | ✅ 21:47:33 | AD ✅ / SOC ❌ → [finding 3](../findings/03-split-log-formats-blind-alerts.md) | ✅ verified `net user /domain` |
| 21:53 | T1136.001-8 | Local user → Administrators | WS 4720, 4732 | ✅ 21:53:06 | SOC ✅ / AD ❌ | ✅ verified `net user` |
| 22:17 | T1136.002-1 | Re-run against new combined alerts | DC 4720, 4728 | ✅ 22:17:00 | ✅ ACCT + PRIV (Critical) @ 22:20:02 | ✅ verified |
| 22:17 | T1136.001-8 | Re-run against new combined alerts | WS 4720, 4732 | ✅ 22:17:26 | ✅ ACCT + PRIV (High) @ 22:20:02 | ✅ verified |

## Commands used

```powershell
# One-time: module was installed with atomics in a non-default folder
$PSDefaultParameterValues = @{"Invoke-AtomicTest:PathToAtomicsFolder"="C:\AtomicRedTeam\invoke-atomicredteam\atomics"}

# Pattern for every test
Invoke-AtomicTest <Technique> -TestNumbers <N> -ShowDetails   # review exactly what will run
Invoke-AtomicTest <Technique> -TestNumbers <N> -GetPrereqs
Invoke-AtomicTest <Technique> -TestNumbers <N>               # execute
Invoke-AtomicTest <Technique> -TestNumbers <N> -Cleanup      # always clean up
```

## Safety practice
- Always reviewed `-ShowDetails` before running.
- Persistence tests (scheduled tasks, admin accounts) were cleaned up immediately after the alert was confirmed — never left overnight.
- Account-creation cleanup verified with `net user <name>` / `net user <name> /domain` → "user name could not be found".
