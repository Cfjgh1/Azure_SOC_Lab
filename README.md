# Azure SOC Lab

## Overview

This project demonstrates the design and deployment of a Security Operations Center (SOC) in Microsoft Azure using Microsoft Sentinel. The lab simulates a small enterprise environment consisting of a Windows Server 2022 Domain Controller, a Windows 10 endpoint, and a Kali Linux attack machine.

Security telemetry is collected through Sysmon and Windows Event Logs, ingested into Azure Log Analytics, and analyzed by Microsoft Sentinel. Custom analytics rules were developed using Kusto Query Language (KQL) to detect common attacker techniques aligned with the MITRE ATT&CK framework. Infrastructure deployment and rule management are automated using Bicep to support repeatable deployments.

The goal of this project is to demonstrate practical experience with cloud SIEM engineering, threat detection, infrastructure as code, and incident generation in an Azure environment.

## Architecture

<img width="2839" height="776" alt="architecture" src="https://github.com/user-attachments/assets/69b02ddc-bf14-4748-9611-bd20dc54accb" />

### Data Flow

1. Activity occurs on the Windows endpoints.
2. Sysmon and Windows Event Logs generate telemetry.
3. Azure Monitor forwards logs to the Log Analytics Workspace.
4. Microsoft Sentinel analyzes the logs using custom KQL analytics rules.
5. Alerts are correlated into incidents for investigation.


## Features

- Azure-based SOC lab deployed in a dedicated resource group
- Microsoft Sentinel connected to a Log Analytics Workspace
- Windows Server 2022 Active Directory environment
- Windows 10 endpoint joined to the domain
- Kali Linux attack workstation for adversary simulation
- Sysmon telemetry collection and ingestion into Sentinel
- Custom KQL analytics rules for threat detection
- Incident creation and alert correlation in Microsoft Sentinel
- Infrastructure as Code (IaC) deployment using Bicep
- MITRE ATT&CK mapped detections
- Attack simulation and detection validation

## Technologies Used

| Category | Technologies |
| :--- | :--- |
| **Cloud & SIEM** | Microsoft Azure, Microsoft Sentinel, Log Analytics Workspace |
| **Host & Endpoint** | Active Directory DS (Windows Server 2022), Windows 10 Enterprise, Sysmon, Defender for Endpoint |
| **Detection & IaC** | Bicep (Infrastructure as Code), Kusto Query Language (KQL), PowerShell |
| **Offensive & Network** | Kali Linux (Hydra, Nmap), Azure Virtual Network, Network Security Groups (NSGs) |

## Detection Rules

| Rule | Event ID(s) | MITRE ATT&CK | Severity | Status |
|------|------------:|--------------|----------|--------|
| Brute Force Detection | 4625 | T1110 | Medium | Implemented |
| Encoded PowerShell | 4688 | T1059 | High | Implemented |
| New User Created | 4720 | T1136 | Medium | Implemented |
| Admin Group Change | 4732 | T1098 | High | Implemented |
| RDP Logon | 4624 | T1021 | Low | Implemented |
| Service Installation | 7045 | T1543 | High | Implemented |
| Defender Configuration Change | 5007 | T1562 | High | Implemented |
| Port Scan Detection | Network Events | T1046 | Medium | Implemented |

## Lab Walkthrough

*LAB WALKTHROUGH IS BEING REMADE TO ADDRESS SOUND ISSUES*

## Screenshots

## Future Improvements

- Integrate Microsoft Defender for Endpoint to expand endpoint telemetry and improve detection coverage.
- Develop additional analytics rules covering persistence, credential access, privilege escalation, and lateral movement techniques.
- Implement Sentinel automation rules and Logic Apps for automated incident response and notification.
- Add watchlists and threat intelligence feeds to enrich alerts with external indicators of compromise (IOCs).
- Create interactive Microsoft Sentinel workbooks for security monitoring and reporting.
- Deploy Microsoft Defender for Identity to monitor Active Directory authentication and identity-based attacks.
- Expand the environment with additional Windows and Linux endpoints to simulate a larger enterprise network.
- Implement Just-In-Time (JIT) VM access and Azure Bastion to improve administrative security.
- Add scheduled threat hunting queries and hunting playbooks for proactive detection.
- Integrate Microsoft Entra ID logs to detect suspicious authentication and identity activity.
