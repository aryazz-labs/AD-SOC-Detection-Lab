# Multiple Failed Kerberos Authentication — T1110.001

**Why it matters:** repeated bad-password attempts against a single account are the signature of password guessing. In an AD domain those attempts are evaluated by the **domain controller**, not the target host, so the detection lives on DC01's Security log.

## The key insight: where a failed logon lands depends on the protocol

When a workstation authenticates to a host **by hostname** (e.g. `net use \\DC01\IPC$`), Windows uses **Kerberos**. A wrong password fails at the **DC** during AS-REQ pre-authentication and writes **Event 4771 with failure code `0x18`**. The target host never sees the attempt — there is **no 4625 on the workstation**.

This is why a Kerberos brute force must be detected on the DC with 4771, and why the endpoint-based `SOC - Multiple Failed Logon` detection (which reads 4625) cannot see it — see [finding 4](../../findings/04-endpoint-alerts-not-art-drivable.md).

## Detection logic

```spl
| where Status="0x18"                               ← bad password only
| stats count as failed_attempts by TargetUserName IpAddress
| where failed_attempts >= 5
```

- **`0x18`** = "pre-authentication information was invalid" (wrong password).
- A **locked** account logs **`0x12`** instead, which is deliberately *excluded* — otherwise lockouts would inflate the count. (See [gotchas](../../active-directory/README.md) and [finding 5](../../findings/05-ad-alerts-no-throttling.md).)

## Validation

Validated two ways — a manual simulation and the matching atomic.

**1. Manual simulation** — 5 bad passwords for `soc.testuser` over Kerberos:

```powershell
# run from the workstation; fails against the DC (Kerberos), not locally
1..5 | ForEach-Object { net use \\$env:LOGONSERVER\IPC$ /user:corp.lab\soc.testuser "WrongPass$_" 2>&1 }
```

→ 5× 4771 (`0x18`) on DC01 → alert fired **00:35:02 IST**.

**2. Atomic Red Team** — `T1110.001-1`, with the target **overridden** to the test account:

```powershell
Invoke-AtomicTest T1110.001 -TestNumbers 1 -ShowDetails
# Unlock-ADAccount soc.testuser   (run on DC01 first — see below)
Invoke-AtomicTest T1110.001 -TestNumbers 1 -InputArgs @{"user"="soc.testuser"}
Invoke-AtomicTest T1110.001 -TestNumbers 1 -Cleanup
```

→ 5× 4771 (`0x18`) at ~01:17 → alert fired **01:20:01 IST**.

> ⚠️ **Two gotchas that cost time:**
> 1. The atomic's default target is `%username%` — **the logged-in user (Administrator!)**. Without `-InputArgs @{"user"="soc.testuser"}` you brute-force your own admin account and risk locking it out.
> 2. `soc.testuser` must be **unlocked first** (`Unlock-ADAccount soc.testuser` on DC01 — Win11 has no RSAT). A locked account returns `0x12`, which this detection ignores, so you'd see zero `0x18` events and think the test failed.

## Known limitation

This alert has **no throttling** (`alert.suppress=false`). On a 5-minute schedule over a 15-minute window, one incident re-alerts every run until the events age out — observed firing at 00:35, 00:40, 00:45, 00:50, 00:55, 01:00, 01:05, 01:10, then again 01:20, 01:25 off the second test. The fix is documented in [finding 5](../../findings/05-ad-alerts-no-throttling.md).
