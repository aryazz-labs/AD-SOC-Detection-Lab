# Active Directory SOC Detection Lab

> I built a small Active Directory environment, forwarded its logs to Splunk, wrote detections mapped to MITRE ATT&CK, then **attacked my own lab with Atomic Red Team to prove each detection actually fires** — and fixed the gaps those tests exposed.

**What makes this project different:** it's not just a set of SPL queries. Every detection marked ✅ below was validated by a real attack simulation, with timestamped evidence from Splunk. Three of those tests revealed real problems — a silently disabled audit policy, duplicate alerting, and alerts that were blind to half the environment — and each one was diagnosed, fixed, and re-tested.

---

## At a glance

| | |
|---|---|
| **Domain** | `corp.lab` — 1 domain controller (Windows Server 2022), 1 domain-joined Windows 11 Pro workstation |
| **SIEM** | Splunk Enterprise 10.6 on AWS EC2, Universal Forwarders on both hosts |
| **Telemetry** | Windows Security log (both hosts), Sysmon (workstation) |
| **Attack simulation** | Atomic Red Team (Invoke-AtomicRedTeam) |
| **Detections validated** | 4 end-to-end (attack → log → alert), across 2 hosts and 2 log formats |
| **Gaps found & fixed** | 3 — see [Findings](#findings-what-the-attacks-revealed) |

---

## Architecture

```mermaid
flowchart LR
    subgraph AD["corp.lab (Active Directory)"]
        DC["DC01<br/>Windows Server 2022<br/>Domain Controller"]
        WS["WINDOWS-11-PRO<br/>Windows 11 Pro<br/>+ Sysmon"]
    end
    ART["Atomic Red Team<br/>(attack simulation)"] -->|runs on| WS
    WS -->|domain auth, GPO| DC
    DC -->|"UF: Security log<br/>(XmlWinEventLog)"| SPL
    WS -->|"UF: Security log (WinEventLog)<br/>+ Sysmon (XmlWinEventLog)"| SPL
    SPL["Splunk Enterprise<br/>(AWS EC2)<br/>index=windows_security"] --> AL["Scheduled alerts<br/>→ Triggered Alerts"]
```

Full build details: [`active-directory/`](active-directory/README.md)

---

## Detection results

### ✅ Validated end-to-end

| Detection | MITRE ATT&CK | Atomic test(s) | Hosts covered | Result |
|---|---|---|---|---|
| [Suspicious NTFS Alternate Data Stream](detections/T1564.004-ntfs-ads/) | T1564.004 (exec via T1059.001) | T1059.001-11 | Workstation | Fired, **High** — 0 false positives against 24h baseline |
| [Scheduled Task Creation](detections/T1053.005-scheduled-task/) | T1053.005 | T1053.005-2 (`schtasks.exe`), T1053.005-4 (PowerShell cmdlets) | Workstation | Fired for **both** creation methods |
| [New Account Created — Domain & Local](detections/T1136-account-created/) | T1136.001, T1136.002 | T1136.002-1, T1136.001-8 | DC + Workstation | Fired for **both** in one run |
| [Privileged Group Membership Added](detections/T1098-privileged-group-added/) | T1098 | Same runs as above — each test also adds the new account to a privileged group | DC + Workstation | Domain Admins → **Critical**, local Administrators → **High** |

### 🔄 Built, validation pending
Password spraying (T1110.003) · Kerberos brute force (T1110.001) · Account lockout · Failed-then-successful logon · Encoded PowerShell (T1059.001 — tested in an earlier session; re-validation with evidence planned). See [roadmap](docs/roadmap.md).

![Triggered alerts in Splunk](evidence/11-triggered-alerts.png)
*The new combined alerts (ACCT, PRIV) and the ADS alert firing in Splunk's Triggered Alerts.*

---

## Findings: what the attacks revealed

These are the most important part of the project. Each one is a problem that **only showed up because I tested the detections** instead of assuming they worked.

### 1. A Group Policy refresh was silently disabling audit logging → [details](findings/01-audit-policy-reset-by-gpo.md)
The scheduled-task attack ran, Sysmon recorded it — but **no Event 4698 was written**, so the alert never fired. Root cause: local audit settings were being reset by Group Policy on every refresh. Fixed centrally in GPO and verified on **both** hosts after `gpupdate /force`.

![Attack succeeded but auditing was off](evidence/08-atomic-test-and-audit-gap.png)

### 2. Overlapping search windows caused duplicate alerts → [details](findings/02-duplicate-alerts-window-overlap.md)
Alerts ran every 5 minutes but searched the last 15, so one malicious event fired **up to 3 times**. A hidden `earliest=-15m` inside the SPL was overriding the alert's own time range. Fixed by aligning windows to `-5m@m` → `@m`.

### 3. Two log formats meant each alert set saw only half the environment → [details](findings/03-split-log-formats-blind-alerts.md)
The DC sends XML-formatted events, the workstation sends classic events. My "AD" alerts only parsed XML; my "SOC" alerts only parsed classic. **Each missed one machine.** A domain-admin creation on the DC went undetected by one set; a local-admin creation on the workstation by the other. Replaced both pairs with format-agnostic alerts and proved coverage of both hosts in a single run.

| Attack | Old "AD" alerts | Old "SOC" alerts | **New combined alerts** |
|---|---|---|---|
| Domain admin created on DC01 | ✅ | ❌ missed | ✅ |
| Local admin created on workstation | ❌ missed | ✅ | ✅ |

---

## How to explore this repo

| Folder | What's inside |
|---|---|
| [`active-directory/`](active-directory/) | Domain design: OUs, users, GPOs and where they're linked, audit policy |
| [`detections/`](detections/) | One folder per detection: SPL, metadata (YAML), validation write-up |
| [`findings/`](findings/) | The three gaps: symptom → root cause → fix → verification |
| [`atomic-tests/`](atomic-tests/) | Timestamped log of every attack run and cleanup |
| [`evidence/`](evidence/) | All screenshots referenced in the write-ups |
| [`docs/demo-script.md`](docs/demo-script.md) | 5-minute walkthrough for presenting this project |
| [`docs/roadmap.md`](docs/roadmap.md) | What's next, including known noisy alerts |

---

## Skills demonstrated

- **Active Directory administration** — OU design, user provisioning, Group Policy creation/linking, advanced audit policy
- **SIEM engineering (Splunk)** — Universal Forwarder deployment, SPL with `rex`/`eval`/`coalesce`, scheduled alerts, throttling, alert-window design
- **Detection engineering** — baselining normal activity before writing rules, MITRE ATT&CK mapping, severity tiering, false-positive control
- **Detection validation** — adversary emulation with Atomic Red Team, evidence-based verification, safe cleanup
- **Troubleshooting** — tracing a missing alert back through Splunk → Windows Event Log → `auditpol` → Group Policy

---

## Safety notes
All attacks ran in an isolated lab. Every Atomic test was cleaned up and verified (e.g. test admin accounts confirmed deleted with `net user`). No credentials, keys, or public IPs are included in this repository; security identifiers in screenshots are partially redacted.
