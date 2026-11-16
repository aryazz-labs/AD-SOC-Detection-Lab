# Failed Logons Followed by a Successful Logon — T1110

**Why it matters:** this is the alert you most want to *not* miss. A run of failures for one account followed by a **success** in the same window is the signature of a brute force that **worked** — the attacker guessed the password and is now in. It deserves a faster response than failures alone.

## Detection logic

```spl
(EventCode=4624 OR EventCode=4625)
| eval failed=if(EventCode=4625,1,0)
| eval successful=if(EventCode=4624,1,0)
| bin _time span=10m
| stats sum(failed) as failed_attempts sum(successful) as successful_logons by _time host target_user
| where failed_attempts>=5 AND successful_logons>=1
```

Both the failures (4625) and the success (4624) are read from the **workstation** (classic `WinEventLog:Security`), so — like [SOC - Multiple Failed Logon](../T1110-failed-logon-endpoint/) — this rule sees endpoint-local logons that the DC-side Kerberos detection cannot.

## The binning trick that made validation clean

`stats` aggregates over a **10-minute bin**, so the **order of events inside the bin doesn't matter** — only the totals do. That turns a fiddly sequencing problem into a simple one:

1. Generate the **success first**, while `soc.testuser` is still **unlocked** (1× `LogonUser` with the correct password → 4624).
2. Then generate the **5 failures** (5× `LogonUser` with wrong passwords → 4625).

Because both land in the same wall-clock 10-minute boundary, the stats row shows `failed_attempts=5, successful_logons=1` and fires — **with no mid-sequence unlock needed**. Doing the failures first would lock the account before the success could be recorded.

## Validation

```powershell
# success first (account still unlocked), then 5 failures — same 10-min bin
$t::LogonUser("soc.testuser",".","<correct-password>",2,0,[ref]$tok)      # -> 4624
1..5 | ForEach-Object { $t::LogonUser("soc.testuser",".","WrongPass$_",2,0,[ref]$tok) }  # -> 5x 4625
```

→ one 10-minute bin with 5 failures + 1 success → alert fired **01:00:00 IST**.

See [finding 4](../../findings/04-endpoint-alerts-not-art-drivable.md) for why `LogonUser` (not an atomic) was the right tool, and the [test log](../../atomic-tests/test-log.md) for the full block.

## Throttling

Configured with `alert.suppress=true`, period `10m`.
