## Azure Cloud SOC Lab

A small security operations center in Azure. Logs from a Windows VM flow into a Log Analytics workspace, Microsoft Sentinel raises alerts from custom KQL rules, and Defender for Endpoint covers the host. Work in progress.

**Stack:** Microsoft Sentinel, Microsoft Defender for Endpoint, Log Analytics, Azure Monitor Agent, KQL

### How it works

- **Workspace:** one Log Analytics workspace in East US with Microsoft Sentinel enabled on top of it. A budget alert on the subscription keeps the lab cost in check.
- **Data sources:** Azure Activity through a subscription diagnostic setting, and Microsoft Entra ID audit logs. Entra sign-in logs need a P1/P2 license, so they are not collected here.

### What's next

- Windows VM sending Security events through the Azure Monitor Agent
- Onboard the VM to Defender for Endpoint
- First detection rules in KQL
