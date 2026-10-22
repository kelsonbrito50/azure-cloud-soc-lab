## Azure Cloud SOC Lab

A small security operations center in Azure. Logs from a Windows VM flow into a Log Analytics workspace, Microsoft Sentinel raises alerts from custom KQL rules, and Defender for Endpoint covers the host. Work in progress.

**Stack:** Microsoft Sentinel, Microsoft Defender for Endpoint, Log Analytics, Azure Monitor Agent, KQL

### How it works

- **Workspace:** one Log Analytics workspace in East US with Microsoft Sentinel enabled on top of it. A budget alert on the subscription keeps the lab cost in check.
- **Data sources:** Azure Activity through a subscription diagnostic setting, Microsoft Entra ID audit logs, and Windows Security events from the lab VM. Entra sign-in logs need a P1/P2 license, so they are not collected here.
- **Lab VM:** Windows Server 2025 in Central US. The subscription had no capacity for the usual small sizes in East US, so the VM runs in another region and still reports to the East US workspace. RDP is limited to my own IP and the VM shuts down every night.
- **Security events:** the Azure Monitor Agent sends a filtered set of Security log events through a data collection rule: logons, special logons, process creation with command line, scheduled tasks, account and group changes, lockouts and log clearing. Command-line auditing for process creation is turned on in the VM.

### What's next

- Onboard the VM to Defender for Endpoint
- First detection rules in KQL
