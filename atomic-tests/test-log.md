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

## Session 2 — 17 November 2026 (T1110 credential-access detections)

Times IST. Tests target the dedicated **`soc.testuser`** account so lockouts never touch admin access. The Win11 interactive user this session was `CORP\Administrator`, which matters for the brute-force atomic (see note). AD cmdlets (`Unlock-ADAccount`) run on **DC01** — Win11 has no RSAT.

| Time | Test | Action | Expected telemetry | Observed | Alert | Cleanup |
|---|---|---|---|---|---|---|
| 00:35 | Manual (Kerberos) | 5 bad passwords for `soc.testuser` via `net use \\%logonserver%\IPC$` | DC 4771 `0x18` ×5, then 4740 | ✅ | ✅ Kerberos @ 00:35:02 + Lockout @ 00:35:01 | ✅ `Unlock-ADAccount` |
| 01:00 | Manual (`LogonUser`) | 1 good + 5 bad local logons on WS (logon type 2) | WS 4624 ×1, 4625 ×5 (classic) | ✅ | ✅ Multiple Failed Logon @ 01:00:01 + Failed→Successful @ 01:00:00 | n/a (no persistence) |
| 01:15 | T1110.003-1 | Password spray all domain users (one password each) | DC 4771 `0x18`, 1 per user | ✅ 6 distinct users from 192.168.10.20 | ✅ Password Spraying @ 01:15:01 | ✅ `-Cleanup` |
| 01:17 | T1110.001-1 | Brute force `soc.testuser` (5 passwords via SMB→Kerberos) | DC 4771 `0x18` ×5, then 4740 | ✅ | ✅ Kerberos @ 01:20:01 + Lockout @ 01:20:01 | ✅ `-Cleanup` + `Unlock-ADAccount` |

**Result: all 5 T1110 detections validated end-to-end.** The two SOC endpoint alerts could *not* be driven by any atomic (they need workstation-local 4625, and atomics authenticate against the DC) — hence the `LogonUser` method. See [finding 4](../findings/04-endpoint-alerts-not-art-drivable.md).

### Exact commands — Session 2

```powershell
# One-time per session: atomics live in a non-default folder
$PSDefaultParameterValues = @{"Invoke-AtomicTest:PathToAtomicsFolder"="C:\AtomicRedTeam\invoke-atomicredteam\atomics"}

# --- Password spraying: T1110.003 Test 1 (the only clean 4771-0x18 match) ---
Invoke-AtomicTest T1110.003 -TestNumbers 1 -ShowDetails
Invoke-AtomicTest T1110.003 -TestNumbers 1 -GetPrereqs    # builds %temp%\users.txt from `net user /domain`
Invoke-AtomicTest T1110.003 -TestNumbers 1               # one password across all domain users (no lockouts)
Invoke-AtomicTest T1110.003 -TestNumbers 1 -Cleanup

# --- Kerberos brute force + lockout: T1110.001 Test 1 ---
# MUST override the target: the atomic defaults to %username% = the logged-in Administrator!
# And unlock the account first, or attempts return 0x12 (locked), not 0x18 (bad password).
#   (on DC01)  Unlock-ADAccount soc.testuser
Invoke-AtomicTest T1110.001 -TestNumbers 1 -ShowDetails
Invoke-AtomicTest T1110.001 -TestNumbers 1 -InputArgs @{"user"="soc.testuser"}
Invoke-AtomicTest T1110.001 -TestNumbers 1 -Cleanup
#   (on DC01)  Unlock-ADAccount soc.testuser ; Get-ADUser soc.testuser -Properties LockedOut | Select LockedOut

# Atomic note: it prints output only on SUCCESS (&& echo [*]). No output = all passwords failed = expected.
# Exit code 2 = last `net use` failed = normal for a brute force that found nothing.

# --- SOC endpoint logons: manual LogonUser (no atomic fits — see finding 4) ---
$sig = @'
[DllImport("advapi32.dll", SetLastError=true)]
public static extern bool LogonUser(string user, string domain, string pass,
  int logonType, int logonProvider, out IntPtr token);
'@
$t = Add-Type -MemberDefinition $sig -Name L -Namespace W -PassThru
$tok = [IntPtr]::Zero
# SOC - Failed Logons Followed by Successful: do the SUCCESS first (account still unlocked), then 5 fails,
# all inside one 10-minute bin (stats ignores order within the bin -> no mid-sequence unlock needed).
$t::LogonUser("soc.testuser",".","<correct-password>",2,0,[ref]$tok)                      # 4624
1..5 | ForEach-Object { $t::LogonUser("soc.testuser",".","WrongPass$_",2,0,[ref]$tok) }   # 5x 4625  (2 = INTERACTIVE)
```

---

## Commands used (Session 1 pattern)

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
