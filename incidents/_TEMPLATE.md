# INC-[NNN]: [Short title, e.g. RDP brute force against vm-win-01]

> **Template.** Copy to `INC-NNN-short-slug.md`, fill every section, delete the placeholders. Redact IPs, subscription/tenant IDs, and personal account names before committing.

| Field | Value |
|-------|-------|
| Incident ID (Sentinel) | [#N] |
| Detected | [YYYY-MM-DD HH:MM UTC] |
| Closed | [YYYY-MM-DD HH:MM UTC] |
| Time to closure | [N min] |
| Severity (initial -> final) | [Medium -> Medium] |
| Rule(s) that fired | [`brute-force-rdp-failed-logons.kql`](../detections/brute-force-rdp-failed-logons.kql) |
| MITRE ATT&CK | [T1110 Brute Force] |
| Affected host(s) | [vm-win-01] |
| Affected account(s) | [administrator, azureuser] |
| Source IP(s) | [redacted / x.x.x.x] |
| Final classification | [True positive - suspicious activity / Benign positive - expected / False positive - incorrect alert logic] |

## 1. What fired

One paragraph: which analytics rule raised the alert, what the alert said, how many alerts were grouped into the incident, and what entities Sentinel mapped (account, host, IP).

![Incident page](../screenshots/[INC-NNN]-incident.png)

## 2. Triage (first 5 minutes)

Answer these before investigating further:

- Is the affected host a real asset in scope? [Yes: lab VM]
- Is the activity expected? [No / Yes because ...]
- Severity reasonable? [Kept Medium because ...]
- Owner assigned: [me]. Status set to **Active**.

## 3. Investigation

### Timeline

| Time (UTC) | Source | Event |
|------------|--------|-------|
| [HH:MM:SS] | SecurityEvent 4625 | First failed logon from [IP] for account [name] |
| [HH:MM:SS] | SecurityEvent 4625 | [N]th failure; rule threshold reached |
| [HH:MM:SS] | Sentinel | Alert generated, incident #[N] created |
| [HH:MM:SS] | SecurityEvent 4624 | [Successful logon? type 10 = RDP] |
| [HH:MM:SS] | Defender device timeline | [Process events after logon, if any] |

### Queries used

```kql
// Failed logons from the source IP across all hosts
SecurityEvent
| where TimeGenerated between (datetime([start]) .. datetime([end]))
| where EventID == 4625 and IpAddress == "[IP]"
| summarize count() by TargetAccount, Computer, bin(TimeGenerated, 1m)
```

```kql
// Did the attacker ever succeed?
SecurityEvent
| where TimeGenerated between (datetime([start]) .. datetime([end]))
| where EventID == 4624 and IpAddress == "[IP]"
| project TimeGenerated, TargetAccount, LogonType, Computer
```

### What I found

- [Plain-language findings. Example: 212 failures in 9 minutes across 14 usernames, classic dictionary attack. No 4624 success from this IP. Defender device timeline shows no new processes or persistence.]
- [Context: IP geolocation / threat intel lookup result, if used.]
- [Scope: were other hosts targeted? Any other IPs doing the same?]

## 4. Containment, eradication, recovery

| Action | Done? | Evidence |
|--------|-------|----------|
| [Blocked source IP in the NSG / restricted RDP to my IP only] | [Yes] | [screenshot/NSG rule name] |
| [Confirmed no successful logon; no credential reset needed] | [Yes] | query above |
| [Isolated device in Defender] | [Not required because ...] | |
| [Reset password for targeted account] | [N/A] | |

## 5. Closure

- Classification: **[True positive - suspicious activity]**
- Comment added in Sentinel: "[one-line summary]"
- Status set to **Closed** at [HH:MM UTC].

## 6. Lessons learned

1. [Detection: what the rule got right/wrong; tuning applied and committed in `/detections`.]
2. [Process: what would make the next triage faster.]
3. [Hardening: what you changed on the VM or network as a result.]
