# INC-003: Encoded PowerShell on vm-win-01 (lab test)

| Field | Value |
|-------|-------|
| Incident ID (Sentinel) | #3 and #4 (same event, two rule runs) |
| Detected | 2026-10-28 16:21 UTC |
| Closed | 2026-10-28 16:51 UTC |
| Time to detection | 7 min 26 s (processes started 16:13:55, incident #3 created 16:21:21) |
| Time to closure | 30 min (incident #3 created 16:21:21, closed 16:51:47) |
| Severity (initial -> final) | Medium -> Medium |
| Rule(s) that fired | [`suspicious-encoded-powershell.kql`](../detections/suspicious-encoded-powershell.kql) |
| MITRE ATT&CK | T1059.001 Command and Scripting Interpreter: PowerShell (TA0002 Execution); T1027.010 Obfuscated Files or Information: Command Obfuscation (TA0005 Defense Evasion) |
| Affected host(s) | vm-win-01 |
| Affected account(s) | SYSTEM (S-1-5-18) |
| Final classification | Benign positive - suspicious but expected (authorized lab test) |

## 1. What fired

My scheduled analytics rule "PowerShell launched with an encoded command" raised two Medium alerts, and Sentinel created a separate incident for each (#3 and #4). The rule runs every 5 minutes, looks back 10 minutes, and fires on process creation events (Event ID 4688) where `powershell.exe` or `pwsh.exe` starts with any accepted prefix of `-EncodedCommand` followed by a Base64 payload. Both alerts came from the same two processes: two consecutive rule runs saw them, as in [INC-002](INC-002-local-admin-added-lab-test.md). Sentinel mapped the host, the account by SID and the process (command line and process ID).

## 2. Triage (first 5 minutes)

- Is the affected host a real asset in scope? Yes: vm-win-01 is the lab VM.
- Is the activity expected? Yes. I started the two processes myself through Azure Run Command to test the rule.
- Severity reasonable? Kept Medium. Encoded commands are common in malware and offensive tooling, but some management tools use them too, so the alert needs a look at the decoded payload before escalating.
- The payload is the first thing to check: decode it and see what it runs.

## 3. Investigation

### Timeline

| Time (UTC) | Source | Event |
|------------|--------|-------|
| 16:10:53 | Sentinel | I created the scheduled rule through the API (every 5 min, lookback 10 min, threshold > 0) |
| 16:13:55 | SecurityEvent 4688 | `powershell.exe -NoProfile -EncodedCommand VwByAGkA...dAA=` started by SYSTEM, process ID 0x3a8 (936) |
| 16:13:55 | SecurityEvent 4688 | `powershell.exe -NoProfile -enc VwByAGkA...dAA=` started by SYSTEM, process ID 0x224 (548) |
| 16:21:21 | Sentinel | First alert, incident #3 created |
| 16:26:13 | Sentinel | Second alert from the next rule run, incident #4 created |
| 16:51:47 | Sentinel | Incident #3 closed through the Sentinel REST API |
| 16:51:52 | Sentinel | Incident #4 closed through the Sentinel REST API |

### Queries used

```kql
// Everything the rule logic matches on the lab VM in the test window
SecurityEvent
| where TimeGenerated between (datetime(2026-10-28 15:00) .. datetime(2026-10-28 17:00))
| where Computer startswith "vm-win-01"
| where EventID == 4688
| where NewProcessName endswith @"\powershell.exe" or NewProcessName endswith @"\pwsh.exe"
| where CommandLine matches regex @"(?i)\s[-/\x{2013}\x{2014}\x{2015}](ec|e(n(c(o(d(e(d(c(o(m(m(a(n(d)?)?)?)?)?)?)?)?)?)?)?)?)?)\s+[A-Za-z0-9+/=]{20,}"
| project TimeGenerated, SubjectAccount, SubjectUserSid, ParentProcessName, NewProcessId, CommandLine
| order by TimeGenerated asc
```

```powershell
# Decode the payload (PowerShell encodes -EncodedCommand as UTF-16LE Base64)
[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAC0ASABvAHMAdAAgAEkATgBDADAAMAAzAC0AdABlAHMAdAA='))
```

### What I found

- The payload decodes to `Write-Host INC003-test`: it only prints text.
- Both processes ran as SYSTEM, with a `powershell.exe` parent: the script that Azure Run Command runs on the VM (the same chain as INC-002). The process IDs in the events (0x3a8, 0x224) match the IDs in the Run Command output (936, 548).
- The rule matched only these two processes. Over the same window, other PowerShell activity on the VM, mostly the Defender for Endpoint extension handler and Defender's own data collection scripts, did not match, because none of it uses `-EncodedCommand`.
- Unlike INC-002, the two alerts were not grouped into one incident. The grouping setting is "all entities match", and this rule also maps a Process entity; the two alerts most likely did not match on it.
- At 16:43:58 `SenseIR.exe` (the Defender for Endpoint response component) started a PowerShell data collection script on the VM. I did not confirm whether a Defender alert was raised for the encoded commands; no Defender incident appeared in the Sentinel incident list.

## 4. Containment, eradication, recovery

| Action | Done? | Evidence |
|--------|-------|----------|
| Confirmed the payload is harmless | Yes | decoded payload above |
| Isolated device in Defender | Not required: authorized test, payload only prints text | |
| VM deallocated after the test | Yes | `az vm show` power state: VM deallocated |

## 5. Closure

- Classification: **Benign positive - suspicious but expected** (both incidents)
- Comment added in Sentinel: "Two powershell.exe processes with -EncodedCommand and -enc at 16:13:55 UTC (payload decodes to Write-Host INC003-test), started by SYSTEM via Azure Run Command by the lab owner account. Authorized lab test to validate the rule. Incidents #3 and #4 are the same event seen by two rule runs."
- Status set to **Closed** at 16:51 UTC, with me as owner, through the Sentinel incidents REST API.

## 6. Lessons learned

1. Detection: the rule caught both the full parameter (`-EncodedCommand`) and the short form (`-enc`), and nothing else in the window. The process-path check with `endswith` and the prefix list in the regex did their job.
2. Detection: one event raised two incidents because alert grouping uses "all entities match" and this rule maps a Process entity. Next step: group by Host and Account only for this rule, then confirm that two runs land in one incident.
3. Triage: decoding the payload is the fastest way to decide. PowerShell encodes it as UTF-16LE, so a plain Base64 decode shows null bytes between letters; the decode has to use UTF-16LE (`[Text.Encoding]::Unicode`).
4. Open point: check in the Defender portal whether Defender for Endpoint raised its own alert for the encoded commands (`SenseIR.exe` ran at 16:43:58).
