# Azure SOC Lab

## Overview

This project demonstrates the design and deployment of a Security Operations Center (SOC) in Microsoft Azure using Microsoft Sentinel. The lab simulates a small enterprise environment consisting of a Windows Server 2022 Domain Controller, a Windows 10 endpoint, and a Kali Linux attack machine.

Security telemetry is collected through Sysmon and Windows Event Logs, ingested into Azure Log Analytics, and analyzed by Microsoft Sentinel. Custom analytics rules were developed using Kusto Query Language (KQL) to detect common attacker techniques aligned with the MITRE ATT&CK framework. Infrastructure deployment and rule management are automated using Bicep to support repeatable deployments.

The goal of this project is to demonstrate practical experience with cloud SIEM engineering, threat detection, infrastructure as code, and incident generation in an Azure environment.

## Architecture

<img width="2839" height="776" alt="architecture" src="https://github.com/user-attachments/assets/69b02ddc-bf14-4748-9611-bd20dc54accb" />

| Component | Details |
|---|---|
| Domain controller | `SOC-WIN-VM1`, Windows Server 2022, static IP `10.0.0.4`, AD DS + DNS for `soc.lab.com` (set as the VNet's DNS server) |
| Endpoint | `SOC-WIN10-VM`, Windows 10 Enterprise LTSC, domain-joined, Sysmon |
| Attacker | `ATK-Kali-VM`, Kali Linux in a separate peered VNet (`Attack-VNET`), SSH key auth only |
| Telemetry | Azure Monitor Agent → Data Collection Rule → Log Analytics (`SecurityEvent`, `Event`) |
| SIEM | Microsoft Sentinel with 12 custom scheduled analytics rules and Fusion multistage detection |
| Access | Azure Bastion only. No NSG allows inbound traffic from the internet |
| Cost controls | Daily auto-shutdown, Standard SSD disks, free Developer-tier Bastion, start/stop scripts |

### Data Flow

1. Activity occurs on the Windows endpoints.
2. Sysmon and Windows Event Logs generate telemetry.
3. The Azure Monitor Agent forwards logs through a Data Collection Rule to the Log Analytics Workspace:
   Security events land in `SecurityEvent`, Sysmon and System events land in `Event`.
4. Microsoft Sentinel analyzes the logs using custom KQL analytics rules.
5. Alerts are correlated into incidents for investigation.

## Repository Layout

```
infra/
  main.bicep          Full environment: VNets, peering, Bastion, NSGs, VMs, AMA, DCR, Log Analytics, Sentinel
  detections.bicep    Sentinel analytics rules, queries loaded from detections/
  main.bicepparam     Parameters (secrets are supplied at deploy time, never stored)
detections/           One .kql file per analytics rule
scripts/
  Start-Lab.ps1       Starts the DC first, then the endpoint (and optionally Kali)
  Stop-Lab.ps1        Deallocates every VM
  Test-LabHealth.ps1  Checks Sysmon is running and each log table is receiving data
  Enable-DCAuditing.ps1  Enables the advanced audit policy the detections rely on
  Export-Detections.ps1  Pulls the live rules from Sentinel back into detections/
```

## Automated Infrastructure Deployment

The core environment and analytics rules are provisioned as Infrastructure as Code (IaC) using Azure Bicep to ensure automated, repeatable deployments.

### Infrastructure Definition Example

Each KQL file in `detections/` is the source of truth for its rule. `infra/detections.bicep` loads them with
`loadTextContent` and deploys one Sentinel scheduled rule per entry:

```bicep
var rules = [
  {
    id: 'multiple-failed-logins'
    displayName: 'Multiple Failed Logins'
    severity: 'Medium'
    query: loadTextContent('../detections/multiple-failed-logins.kql')
    tactics: [ 'CredentialAccess' ]
    techniques: [ 'T1110' ]
  }
  // ...
]

resource alertRules 'Microsoft.SecurityInsights/alertRules@2024-03-01' = [for r in rules: {
  scope: workspace
  name: guid(workspace.id, r.id)
  kind: 'Scheduled'
  properties: {
    displayName: r.displayName
    enabled: true
    severity: r.severity
    query: r.query
    queryFrequency: 'PT5M'
    queryPeriod: 'PT5M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    tactics: r.tactics
    techniques: r.techniques
    // ...
  }
}]
```

### Deployment Execution

To deploy the lab infrastructure and automated Sentinel detection rules via Azure CLI:

```powershell
# Authenticate to Azure
az login

# Kali is a Marketplace image: accept its terms once per subscription
az vm image terms accept --publisher kali-linux --offer kali --plan kali-2026-1

# Create the dedicated resource group
az group create --name SOC_LAB --location centralus

# Execute Bicep infrastructure deployment
az deployment group create `
  --resource-group SOC_LAB `
  --template-file infra/main.bicep `
  --parameters infra/main.bicepparam `
  --parameters adminPassword=<password> kaliSshPublicKey="$(Get-Content ~/.ssh/id_rsa.pub)"
```

Promoting the server to a domain controller, joining the endpoint to the domain and installing Sysmon are
done after deployment. `scripts/Enable-DCAuditing.ps1` then enables the audit subcategories the detections need.

Figure 1:

<img width="472" height="201" alt="01-bicep-deploy-terminal png" src="https://github.com/user-attachments/assets/537460c7-569a-4ba6-9541-7865f1465db0" />

### Post-Deployment Verification

Once the deployment job completes, navigate to Microsoft Sentinel > Configuration > Analytics in the Azure portal to verify that all custom KQL analytics rules were created and enabled automatically. `scripts/Test-LabHealth.ps1` confirms Sysmon is running on both Windows hosts and that each log table is receiving data.

Figure 2:

<img width="1917" height="867" alt="02-sentinel-active-rules png" src="https://github.com/user-attachments/assets/03504b90-bca9-46f4-a48c-36750ee577c5" />

## Operating the Lab

```powershell
./scripts/Start-Lab.ps1              # DC first, then Win10 (add -IncludeKali for the attacker)
./scripts/Test-LabHealth.ps1         # Sysmon running? logs arriving in each table?
./scripts/Stop-Lab.ps1               # deallocate everything
./scripts/Export-Detections.ps1      # refresh detections/ from the live Sentinel rules
```

## Features

- Azure-based SOC lab deployed in a dedicated resource group
- Microsoft Sentinel connected to a Log Analytics Workspace
- Windows Server 2022 Active Directory environment
- Windows 10 endpoint joined to the domain
- Kali Linux attack workstation in an isolated, peered virtual network
- Sysmon telemetry collection and ingestion into Sentinel through a Data Collection Rule
- Custom KQL analytics rules for threat detection
- Incident creation and alert correlation in Microsoft Sentinel
- Infrastructure as Code (IaC) deployment using Bicep, with detections stored as code
- MITRE ATT&CK mapped detections
- Attack simulation and detection validation
- Administrative access through Azure Bastion only, with no internet-facing RDP or SSH

## Technologies Used

| Category | Technologies |
| :--- | :--- |
| **Cloud & SIEM** | Microsoft Azure, Microsoft Sentinel, Log Analytics Workspace, Azure Monitor Agent, Data Collection Rules |
| **Host & Endpoint** | Active Directory DS (Windows Server 2022), Windows 10 Enterprise, Sysmon, Defender for Endpoint |
| **Detection & IaC** | Bicep (Infrastructure as Code), Kusto Query Language (KQL), PowerShell |
| **Offensive & Network** | Kali Linux (Hydra, Nmap), Azure Virtual Network, VNet Peering, Network Security Groups (NSGs), Azure Bastion |

## Detection Rules

| Rule | Event ID(s) | MITRE ATT&CK | Severity |
|------|------------:|--------------|----------|
| [Multiple Failed Logins](detections/multiple-failed-logins.kql) | 4625 | T1110 Brute Force | Medium |
| [Potential Password Spraying](detections/potential-password-spraying.kql) | 4625 | T1110.003 Password Spraying | Medium |
| [Kerberoasting](detections/kerberoasting.kql) | 4769 | T1558.003 Kerberoasting | Medium |
| [LSASS Credential Access](detections/lsass-credential-access.kql) | Sysmon 10 | T1003.001 LSASS Memory | High |
| [Encoded PowerShell Execution](detections/encoded-powershell-execution.kql) | 4688 | T1059.001 PowerShell | High |
| [User Added to Administrators Group](detections/user-added-to-administrators-group.kql) | 4732 | T1098 Account Manipulation | High |
| [New Windows Service Installed](detections/new-windows-service-installed.kql) | 7045 | T1543.003 Windows Service | High |
| [Scheduled Task Persistence](detections/scheduled-task-persistence.kql) | 4698 | T1053.005 Scheduled Task | High |
| [Defender Firewall Manipulation](detections/defender-firewall-manipulation.kql) | 4950 | T1562.004 Disable or Modify Firewall | High |
| [Successful RDP Logon Detected](detections/successful-rdp-logon-detected.kql) | 4624 (type 10) | T1021.001 Remote Desktop | Low |
| [Inbound Port Scan](detections/inbound-port-scan.kql) | Sysmon 3 | T1046 Network Service Discovery | Medium |
| [Outbound Network Scan](detections/outbound-network-scan.kql) | Sysmon 3 | T1046 Network Service Discovery | Medium |

Sentinel's built-in **Fusion** rule (Advanced Multistage Attack Detection) is also enabled to correlate alerts
into multistage incidents.

## Hardening and Troubleshooting

Issues found while reviewing the environment, and how they were resolved:

- **Sysmon logs were silently dropped.** The Data Collection Rule sent the Security, Sysmon and System channels
  to the `Microsoft-SecurityEvent` stream, which only accepts the Security channel, so the Sysmon-based detections
  (LSASS access, port scans) had no data. Fixed by splitting the rule into two data sources, with Sysmon and System
  routed through `Microsoft-Event` into the `Event` table.
- **RDP and SSH were exposed to the internet.** Every NSG allowed 3389/22 from any source, including on the domain
  controller. The rules were removed and administrative access moved to Azure Bastion.
- **Public IPs are kept for egress only.** The subnets have default outbound access disabled, so the public IPs
  are the VMs' only path to Log Analytics and Windows Update. They remain attached with no inbound rules.
- **The DC's private IP was dynamic.** A deallocate/start cycle could have changed it and broken name resolution
  for the domain. It is now static, and the VNet's DNS setting points at it so every VM, including new ones,
  resolves `soc.lab.com` without per-machine configuration.
- **Leftover resources from earlier builds** (unattached NICs, public IPs, NSGs and SSH keys) were identified and removed.
- **Disks moved from Premium to Standard SSD.** Disks bill even while VMs are deallocated, and a lab that runs a
  few hours a day doesn't need Premium performance, so this roughly halves storage cost.

## Future Improvements

- Integrate Microsoft Defender for Endpoint to expand endpoint telemetry and improve detection coverage.
- Develop additional analytics rules covering persistence, credential access, privilege escalation, and lateral movement techniques.
- Implement Sentinel automation rules and Logic Apps for automated incident response and notification.
- Deploy the `detections/` folder to Sentinel automatically from GitHub Actions (detection-as-code CI/CD).
- Add watchlists and threat intelligence feeds to enrich alerts with external indicators of compromise (IOCs).
- Create interactive Microsoft Sentinel workbooks for security monitoring and reporting.
- Deploy Microsoft Defender for Identity to monitor Active Directory authentication and identity-based attacks.
- Expand the environment with additional Windows and Linux endpoints to simulate a larger enterprise network.
- Implement Just-In-Time (JIT) VM access. *(Azure Bastion is now in place.)*
- Add scheduled threat hunting queries and hunting playbooks for proactive detection.
- Integrate Microsoft Entra ID logs to detect suspicious authentication and identity activity.
