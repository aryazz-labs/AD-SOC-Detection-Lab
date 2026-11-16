# 5-Minute Demo Script

Use this when presenting the project in an interview — screen-share the GitHub repo, or Splunk if the lab is running.

---

### 0:00 — The one-liner (20 sec)
> "I built a small Active Directory domain, sent its logs to Splunk, and wrote detections mapped to MITRE ATT&CK. Then I attacked my own lab with Atomic Red Team to prove each detection actually fires. The interesting part is that three of those tests failed — and fixing them taught me more than the detections did."

**Show:** README top section + architecture diagram.

### 0:20 — The environment (40 sec)
> "corp.lab has a Server 2022 domain controller and a Windows 11 workstation. I designed OUs by department and function, kept a dedicated test account for attack simulation, and manage audit policy through Group Policy. Both hosts forward to Splunk; the workstation also runs Sysmon."

**Show:** `active-directory/README.md` — OU tree and GPO links table.

### 1:00 — One detection, end to end (60 sec)
Pick **NTFS Alternate Data Stream**:
> "Before writing the rule I baselined 24 hours of ADS activity: about 1,400 benign Zone.Identifier streams from Explorer. An 'alert on everything' rule would have been useless. I excluded the benign stream names but still flag *any* stream written by PowerShell or other LOLBins. Result: the Atomic test fired at High severity, zero false positives."

**Show:** `evidence/01` (baseline) → `evidence/02` (result).

### 2:00 — Finding 1: the alert that couldn't fire (60 sec)
> "The scheduled-task attack ran successfully, but the alert stayed silent. I traced it back: Splunk was receiving other events, so not the forwarder. Windows itself hadn't written Event 4698. auditpol showed the subcategory was set to No Auditing — a Group Policy refresh had reset my earlier local change. I moved the setting into GPO, verified it on both hosts after gpupdate, re-ran the attack, and it fired."

**Show:** `evidence/08` (gap) → `evidence/09` + `20` (fixed).

### 3:00 — Finding 3: the alerts that only saw half the domain (60 sec)
> "I had two sets of account-creation alerts that looked like duplicates. Testing showed the DC sends XML-format events and the workstation sends classic ones — so one set only saw the DC, the other only the workstation. A Domain Admin creation was invisible to one of them. I replaced both with a single search that normalises both formats using coalesce, and proved it catches both hosts in one run — with Domain Admins flagged Critical."

**Show:** README comparison table → `evidence/06`.

### 4:00 — Finding 2 + what's next (40 sec)
> "I also found alerts running every 5 minutes over a 15-minute window, so one event alerted three times — partly because an inline `earliest` in the SPL overrode the alert settings. Next I'm validating the password-spraying and Kerberos brute-force detections, and tuning a PowerShell alert I've identified as too noisy."

**Show:** `docs/roadmap.md`.

### 4:40 — Close (20 sec)
> "The main thing I took away: a detection isn't done when the query works — it's done when you've attacked it and watched it fire, on every host it claims to cover."

---

## Likely follow-up questions — and where the answer is

| Question | Answer location |
|---|---|
| "Why map ADS to T1564.004 when the Atomic test is T1059.001?" | [ADS README — MITRE note](../detections/T1564.004-ntfs-ads/README.md#mitre-mapping-note) |
| "How do you avoid false positives?" | Baselining (ADS), privileged-group filter (PRIV), severity tiering |
| "Why not just shorten every alert window?" | [Finding 2 — design rule](../findings/02-duplicate-alerts-window-overlap.md#design-rule-adopted): threshold alerts need longer windows |
| "What would you do if an alert stops firing?" | [Finding 1 — investigation path](../findings/01-audit-policy-reset-by-gpo.md#investigation) |
| "How did you make sure tests didn't leave risk behind?" | [Test log — safety practice](../atomic-tests/test-log.md#safety-practice) |
| "What are the weaknesses of your lab?" | [Roadmap — known issues](roadmap.md#known-issues) |
