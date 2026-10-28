# INC-002: Local account added to Administrators on vm-win-01 via Azure Run Command (lab test)

| Field | Value |
|-------|-------|
| Incident ID (Sentinel) | #2 |
| Detected | 2026-10-28 15:06 UTC |
| Closed | 2026-10-28 15:52 UTC |
| Time to detection | 6 min 35 s (group change 15:00:11, incident created 15:06:46) |
| Time to closure | 46 min (incident created 15:06:46, closed 15:52:52) |
| Severity (initial -> final) | High -> High |
| Rule(s) that fired | [`new-local-admin-added.kql`](../detections/new-local-admin-added.kql) |
| MITRE ATT&CK | T1098.007 Account Manipulation: Additional Local or Domain Groups (TA0003 Persistence, TA0004 Privilege Escalation) |
| Affected host(s) | vm-win-01 |
| Affected account(s) | t1098test (local, SID ending in -1000), created for the test |
| Actor | SYSTEM (S-1-5-18) on the VM, started by Azure Run Command from the lab owner's Azure account |
| Final classification | Benign positive - suspicious but expected (authorized lab test) |

## 1. What fired

My scheduled analytics rule "Account added to local Administrators group" raised two High alerts, and Sentinel grouped both into incident #2. The rule runs every 5 minutes, looks back 10 minutes, and fires on any Event ID 4732 where the group SID is S-1-5-32-544 (BUILTIN\Administrators). Both alerts came from the same event: two consecutive rule runs saw it, because the lookback is longer than the frequency. Sentinel mapped two entities: the host vm-win-01 and the added account by its SID.

## 2. Triage (first 5 minutes)

- Is the affected host a real asset in scope? Yes: vm-win-01 is the lab VM that sends Security events to Sentinel.
- Is the activity expected? Yes. I created the account and the group change myself through Azure Run Command to test the rule end to end.
- Severity reasonable? Kept High. A new member of the local Administrators group gives full control of the host and is a common persistence step, so it should always be reviewed.
- The incident was not at the top of the queue: Defender ranked it "low priority" (priority score 2, later 1) even though its severity is High. I opened it from the incident list with the priority filter removed.

## 3. Investigation

### Timeline

| Time (UTC) | Source | Event |
|------------|--------|-------|
| 14:24:44 | Azure Activity | Run Command on vm-win-01 to turn on process-creation auditing with command line (lab setup) |
| 14:34:57 - 14:40:10 | Azure Activity | Three Run Command calls for unrelated RDP clipboard troubleshooting; no account or group events from them |
| 14:51:24 | Sentinel | I created the scheduled rule through the API (every 5 min, lookback 10 min, threshold > 0) |
| 14:59:57 | Azure Activity | Run Command started by the lab owner's Azure account (`runCommand/action`, Started) |
| 15:00:08 | SecurityEvent 4688 | Azure guest agent starts `RunCommandExtension.exe "enable"` |
| 15:00:09 | SecurityEvent 4688 | `RunCommandExtension.exe` starts `cmd /C powershell -ExecutionPolicy Unrestricted -File script4.ps1` |
| 15:00:10 | SecurityEvent 4720 | Local account t1098test created by SYSTEM |
| 15:00:10 | SecurityEvent 4724 | Password set on t1098test by SYSTEM |
| 15:00:11 | SecurityEvent 4732 | t1098test added to BUILTIN\Administrators by SYSTEM |
| 15:00:30 | Azure Activity | Run Command finished (Succeeded) |
| 15:06:46 | Sentinel | First alert and incident #2 created |
| 15:11:46 | Sentinel | Second alert from the next rule run, linked to incident #2 ("Same Analytic Rule") |
| 15:20:33 | SecurityEvent 4688 | Same Run Command chain starts `script5.ps1` (cleanup) |
| 15:20:35 | Run Command output | t1098test removed from Administrators and deleted (no 4733 or 4726 in Sentinel, see findings) |
| 15:52:52 | Sentinel | Owner assigned, classification set and incident closed through the Sentinel REST API |

### Queries used

```kql
// Account and group changes on the lab VM
SecurityEvent
| where TimeGenerated between (datetime(2026-10-28 14:00) .. datetime(2026-10-28 16:00))
| where Computer startswith "vm-win-01"
| where EventID in (4720, 4722, 4724, 4732, 4733, 4726)
| project TimeGenerated, EventID, Activity, SubjectAccount, SubjectUserSid, TargetAccount, MemberSid
| order by TimeGenerated asc
```

```kql
// Which process made the change: the Azure Run Command chain
SecurityEvent
| where TimeGenerated between (datetime(2026-10-28 14:00) .. datetime(2026-10-28 16:00))
| where Computer startswith "vm-win-01"
| where EventID == 4688
| where CommandLine contains "RunCommand" or ParentProcessName contains "RunCommand" or NewProcessName contains "RunCommand"
| project TimeGenerated, SubjectAccount, ParentProcessName, NewProcessName, CommandLine
| order by TimeGenerated asc
```

```powershell
# Who started Run Command in Azure (Activity Log, last 6 hours)
az monitor activity-log list -g <resource-group> --offset 6h --query "[?contains(operationName.value, 'runCommand')].{time:eventTimestamp, caller:caller, operation:operationName.value, status:status.value}" -o table
```

### What I found

- Inside the VM the actor is only SYSTEM: every account event has `SubjectUserSid` S-1-5-18 and `SubjectAccount` set to the machine account. No user was logged on to the VM. Without more context, this looks like a SYSTEM process creating an administrator out of nowhere, which is how a compromise often looks.
- The 4688 events show how it happened: the Azure guest agent started the Run Command extension, which ran a PowerShell script with `-ExecutionPolicy Unrestricted` one to two seconds before the account events.
- The Azure Activity Log shows who: `runCommand/action` on vm-win-01 by the lab owner's account at 14:59:57, finished at 15:00:30. The Activity Log shows who ran a script and when, but not what the script did; the VM events show what it did. Both are needed to attribute the change.
- The removal at 15:20:35 left no 4733 or 4726 in Sentinel. Security events kept arriving until 15:21:04 (31 events after 15:20), so the agent was still sending. The data collection rule `dcr-win-security` collects only 4624, 4625, 4672, 4688, 4698, 4720, 4724, 4728, 4732, 4740 and 1102: removal from a group (4733), account deletion (4726) and account enabled (4722) are filtered out. Sentinel sees an account gain admin rights but never sees it lose them or disappear.
- The added account had `MemberName` "-" in the 4732 event, as expected for a local account. The rule maps the account entity by `MemberSid`, so the entity was still populated.

## 4. Containment, eradication, recovery

| Action | Done? | Evidence |
|--------|-------|----------|
| Removed t1098test from Administrators and deleted it | Yes, 15:20:35 UTC via Run Command | Run Command output (`t1098test removed`); 4688 for the cleanup script at 15:20:33 |
| Confirmed only the built-in lab admin account remains in Administrators | Yes | Run Command output after the removal |
| Isolated device in Defender | Not required: authorized test, actor identified | |
| VM deallocated after the test | Yes | `az vm show` power state: VM deallocated |

## 5. Closure

- Classification: **Benign positive - suspicious but expected**
- Comment added in Sentinel: "t1098test created (4720) and added to Administrators (4732) by SYSTEM via Azure Run Command at 15:00:11 UTC. Azure Activity Log: runCommand/action by the lab owner account. Authorized lab test to validate the rule. Account removed at 15:20:35 UTC; 4733/4726 not collected by the DCR."
- Status set to **Closed** at 15:52 UTC, with me as owner. I closed it through the Sentinel incidents REST API: the Defender portal was rolling out its new "Cases" view during the lab and the manage-incident controls were not where I expected them.

## 6. Lessons learned

1. Collection: the data collection rule misses the second half of the account lifecycle (4722, 4726, 4733). Next step: add them to `dcr-win-security`, then repeat the removal and confirm the events arrive.
2. Investigation: changes made through Azure Run Command appear as SYSTEM inside the VM. Attribution needs the Azure Activity Log. Run Command itself is worth a detection (who ran it, on which VM, outside a change window).
3. Detection: a 10-minute lookback on a 5-minute schedule raised two alerts for one event. Alert grouping kept them in one incident, which is the trade-off I accepted to avoid missing late events from the agent.
4. Detection: matching the group by SID (S-1-5-32-544) instead of the name "Administrators" keeps the rule working on any Windows language, and mapping the account by `MemberSid` keeps the entity populated for local accounts.
5. Process: a High-severity incident was ranked low priority (score 2, then 1). Severity alone does not bring it to the top of the queue, so I review the queue without the priority filter.
6. KQL: `has` matches whole terms only, so `has "RunCommand"` does not match `RunCommandWindows` in a path. My first process query returned nothing until I switched to `contains`.
