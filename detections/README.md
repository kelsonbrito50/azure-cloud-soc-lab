# Detections

One analytics rule per file. Each `.kql` file starts with a comment header so the rule is self-describing when someone browses the repository.

## File naming

`<short-slug>.kql`, lowercase, hyphens, named for the behaviour detected (not the table). Examples: `brute-force-rdp-failed-logons.kql`, `new-local-admin-added.kql`.

## Header to put at the top of every rule

```kql
// Rule name:      <as it appears in Sentinel>
// Detects:        <one sentence: the behaviour, not the query>
// Data source:    <table(s) and the connector that fills them>
// MITRE ATT&CK:   <tactic> / <technique ID and name>
// Severity:       <Informational | Low | Medium | High>
// Schedule:       runs every <N> min, looks back <N> min   (lookback > frequency)
// Threshold:      generate alert when results > <N>
// Entity mapping: Account = <column>, Host = <column>, IP = <column>
// Tested:         <date> - triggered by <how you generated the activity>
// Tuning notes:   <exclusions added and why>
```

## Rules in this folder

| File | Status | Last tested |
|------|--------|-------------|
| `brute-force-rdp-failed-logons.kql` | Enabled | 2026-10-24 |
| `new-local-admin-added.kql` | Enabled | 2026-10-28 |
| `suspicious-encoded-powershell.kql` | Enabled | 2026-10-28 |
| `_TEMPLATE.kql` | Template, not deployed | n/a |

## Testing a rule before enabling it

1. Paste the query into **Logs** with a wide time range (`ago(7d)`) and check it returns the right shape of result (one row per thing you want an alert about).
2. Generate the activity on the lab VM and re-run the query with `ago(1h)`.
3. In the rule wizard, use **Results simulation** to see how often it would have fired.
4. Enable the rule, trigger the activity again, and confirm an incident is created. Record the date in the header.
