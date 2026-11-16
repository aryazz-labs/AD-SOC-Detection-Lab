# Suspicious Account Lockout — T1110

**Why it matters:** an account lockout (**Event 4740**) is often the first thing anyone *notices* about a brute-force or spraying attack — the user calls the help desk because they're locked out. Detecting 4740 and tying it back to the **source** turns a help-desk ticket into a security signal.

## Why keep this alongside the brute-force detection?

The [Kerberos brute-force detection](../T1110.001-kerberos-brute-force/) counts `0x18` failures; this one watches for the **lockout itself**. They complement each other:

- Guessing that happens **faster than the 15-minute threshold window** might not accumulate 5 counted `0x18` events in one run — but it will still **lock the account**, and 4740 catches it.
- 4740 names the **caller** (`SubjectUserName`) and the **locked account** (`TargetUserName`), so an analyst can immediately see who/what triggered it.

## Detection logic

```spl
| rex field=_raw "<EventID[^>]*>(?<EventCode>[^<]+)"
| where EventCode="4740"
```

4740 is written on the **PDC-emulator DC** in XML format, so the event ID is parsed from the `<EventID>` element rather than the classic `EventCode` field.

> **0x18 vs 0x12 — why lockouts don't double-count.** A wrong password logs 4771 `0x18`. Once the account is **locked**, further attempts log `0x12` (account restriction), which the brute-force detection deliberately ignores. So the brute-force rule counts the *guessing*, and this rule counts the *lockout* — no overlap. See [gotchas](../../active-directory/README.md).

## Validation

**1. Manual simulation** — bad passwords for `soc.testuser` until the domain lockout threshold (5) tripped → 4740 on DC01 → alert fired **00:35:01 IST**.

**2. Atomic Red Team** — the same `T1110.001-1` run used for the brute-force detection (5 passwords, target overridden to `soc.testuser`) also crosses the lockout threshold, producing 4740 at ~01:17 → alert fired **01:20:01 IST**.

```powershell
Invoke-AtomicTest T1110.001 -TestNumbers 1 -InputArgs @{"user"="soc.testuser"}
# on DC01 afterwards (Win11 has no RSAT):
#   Unlock-ADAccount soc.testuser
#   Get-ADUser soc.testuser -Properties LockedOut | Select LockedOut   -> False
```

## Known limitation

Originally no throttling (`alert.suppress=false`): a single 4740 re-alerted on every 5-minute run until it aged out of the 15-minute window (observed 00:35 → 00:45, then 01:00 → 01:10, then 01:20 → 01:25). **Fixed 2026-11-17** — `alert.suppress=1`, 15m, keyed to `TargetUserName`. See [finding 5](../../findings/05-ad-alerts-no-throttling.md).
