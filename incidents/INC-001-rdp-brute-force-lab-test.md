# INC-001: RDP brute force against vm-win-01 (lab test)

| Field | Value |
|-------|-------|
| Incident ID (Sentinel) | #1 |
| Detected | 2026-10-24 06:01 UTC |
| Closed | 2026-10-24 17:28 UTC |
| Time to detection | 8 min (last failed logon 05:53:24, alert 06:01:26) |
| Time to closure | 11 h 27 min (raised overnight, triaged the next day) |
| Severity (initial -> final) | Medium -> Medium |
| Rule(s) that fired | [`brute-force-rdp-failed-logons.kql`](../detections/brute-force-rdp-failed-logons.kql) |
| MITRE ATT&CK | T1110.001 Brute Force: Password Guessing (TA0006 Credential Access) |
| Affected host(s) | vm-win-01 |
| Affected account(s) | testuser |
| Source IP(s) | 203.0.113.10 (redacted, my home IP) |
| Final classification | Benign positive - suspicious but expected (authorized lab test) |

## 1. What fired

My scheduled analytics rule "Brute force - repeated failed logons from a single source IP" raised one Medium alert, and Sentinel created incident #1 from it six seconds later. The rule runs every 10 minutes, looks back 10 minutes, and fires when one source IP has 10 or more failed logons (Event ID 4625) against one host. The incident had one alert in the Credential Access category, and Sentinel mapped two entities: the source IP and the host vm-win-01. I did not map the account because the rule groups accounts into a set.

![Incident page](../screenshots/INC-001-incident.png)

## 2. Triage (first 5 minutes)

- Is the affected host a real asset in scope? Yes: vm-win-01 is the lab VM that sends Security events to Sentinel.
- Is the activity expected? Yes. I generated it myself to test the rule end to end, from my own IP, against my own VM.
- Severity reasonable? Kept Medium. Repeated failed RDP logons from one IP are worth a look, but on their own they do not prove a compromise.
- Owner assigned: me. Status set to **In progress**.

The incident did not show in the default incident queue at first. The queue filter "Priority score: 15-100" hid it, because Defender ranked it as low priority (one Medium alert, one lab VM). I found it with a `SecurityIncident` query and then removed the filter.

## 3. Investigation

### Timeline

| Time (UTC) | Source | Event |
|------------|--------|-------|
| 05:51:13 | Sentinel | I created the scheduled rule (every 10 min, lookback 10 min, threshold > 0) |
| 05:52:51 | SecurityEvent 4625 | First failed RDP logon for testuser from the source IP (LogonType 3) |
| 05:53:24 | SecurityEvent 4625 | 14th and last failed logon, 33 seconds after the first |
| 05:46:20 - 05:56:20 | Sentinel | Query window evaluated by the rule run that fired (shown as First/Last activity on the incident) |
| 06:01:26 | Sentinel | Alert generated |
| 06:01:32 | Sentinel | Incident #1 created |
| none | SecurityEvent 4624 | No successful logon from the source IP between 05:45 and 06:30 |
| 08:05:02 | Defender for Endpoint | vm-win-01 onboarded by Defender for Servers (after the test, so no device timeline for this window) |
| 17:28:32 | Sentinel | Investigation comment added and incident closed |

### Queries used

```kql
// Failed and successful logons against the lab VM, grouped by source IP
SecurityEvent
| where TimeGenerated between (datetime(2026-10-24 05:45) .. datetime(2026-10-24 06:30))
| where Computer startswith "vm-win-01"
| where EventID in (4624, 4625)
| where isnotempty(IpAddress) and IpAddress != "-"
| summarize Count = count(), First = min(TimeGenerated), Last = max(TimeGenerated)
    by IpAddress, EventID, TargetAccount, LogonType
| sort by First asc
```

```kql
// Did the source IP ever log on successfully?
let ip = "<source-ip>";
SecurityEvent
| where TimeGenerated between (datetime(2026-10-24 05:45) .. datetime(2026-10-24 06:30))
| where EventID == 4624 and IpAddress == ip
| project TimeGenerated, TargetAccount, LogonType, Computer
```

### What I found

- 14 failed logons (4625) for one account, testuser, from one IP in 33 seconds. All were LogonType 3, because RDP with Network Level Authentication checks the password before the session starts.
- No successful logon (4624) from that IP in the window, so the attempts did not get in.
- Only vm-win-01 was targeted, and no other IP showed the same pattern.
- The account showed up as `MicrosoftAccount\testuser`. Windows did not resolve it as a local account, which suggests it does not exist on the VM.

## 4. Containment, eradication, recovery

| Action | Done? | Evidence |
|--------|-------|----------|
| RDP limited to my home IP in the NSG | Yes, already in place before the test | NSG `vm-win-01-nsg`, inbound rule 300 |
| Confirmed no successful logon; no credential reset needed | Yes | second query above |
| Isolated device in Defender | Not required: authorized test, and the VM was not onboarded to Defender for Endpoint yet | |
| Reset password for targeted account | N/A: no logon succeeded | |

## 5. Closure

- Classification: **Benign positive - suspicious but expected**
- Comment added in Sentinel: "Investigation: 14 failed RDP logons (4625, LogonType 3) for testuser from one IP against vm-win-01, 05:52:51-05:53:24 UTC. No successful logon (4624) from that IP between 05:45 and 06:30 UTC. Source is the analyst's own IP: authorized lab test to validate the brute-force rule. No further action."
- Status set to **Closed** at 17:28 UTC.

## 6. Lessons learned

1. Detection: RDP with NLA logs failed logons as LogonType 3, not 10, so the rule does not filter on LogonType. `TargetAccount` already includes the domain in SecurityEvent; my first version added it again and showed it twice. Both fixes are in the rule file.
2. Detection: the incident's First/Last activity shows the window the rule evaluated, not the real event times. The real times come from the SecurityEvent query.
3. Process: the default incident queue filter (Priority score 15-100) can hide low-priority incidents. I now check the queue without that filter, or query `SecurityIncident` directly.
4. Process: I created this rule through the API with the technique only (T1110). I added the sub-technique T1110.001 in the portal afterwards so the incident shows the exact technique.
5. Hardening: RDP was already restricted to my IP, which is why a real attacker could not have reached this port. Next step for the lab: onboard to Defender for Endpoint before testing, so the device timeline covers the test window.
