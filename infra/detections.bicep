// Sentinel scheduled analytics rules. Each query is loaded from detections/*.kql,
// so the KQL files in the repo are the source of truth.

param workspaceName string

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

// Entity mappings let Sentinel link alerts to the hosts, accounts and IPs involved.
var hostEntity = { entityType: 'Host', fieldMappings: [ { identifier: 'HostName', columnName: 'Computer' } ] }
var accountEntity = { entityType: 'Account', fieldMappings: [ { identifier: 'FullName', columnName: 'Account' } ] }

// Rules run every 5 minutes over the last 5 minutes unless frequency is set,
// in which case the lookback equals the frequency so each run covers its window exactly.
var rules = [
  {
    id: 'multiple-failed-logins'
    displayName: 'Multiple Failed Logins'
    severity: 'Medium'
    query: loadTextContent('../detections/multiple-failed-logins.kql')
    tactics: [ 'CredentialAccess' ]
    techniques: [ 'T1110' ]
    entityMappings: [ accountEntity ]
  }
  {
    id: 'potential-password-spraying'
    displayName: 'Potential Password Spraying'
    severity: 'Medium'
    query: loadTextContent('../detections/potential-password-spraying.kql')
    tactics: [ 'CredentialAccess' ]
    techniques: [ 'T1110' ]
    frequency: 'PT30M'
  }
  {
    id: 'kerberoasting'
    displayName: 'Kerberoasting'
    severity: 'Medium'
    query: loadTextContent('../detections/kerberoasting.kql')
    tactics: [ 'CredentialAccess' ]
    techniques: [ 'T1558' ]
    frequency: 'PT10M'
  }
  {
    id: 'lsass-credential-access'
    displayName: 'LSASS Credential Access'
    severity: 'High'
    query: loadTextContent('../detections/lsass-credential-access.kql')
    tactics: [ 'CredentialAccess' ]
    techniques: [ 'T1003' ]
  }
  {
    id: 'encoded-powershell-execution'
    displayName: 'Encoded PowerShell Execution'
    severity: 'High'
    query: loadTextContent('../detections/encoded-powershell-execution.kql')
    tactics: [ 'Execution' ]
    techniques: [ 'T1059' ]
    entityMappings: [ accountEntity, hostEntity ]
  }
  {
    id: 'user-added-to-administrators-group'
    displayName: 'User Added to Administrators Group'
    severity: 'High'
    query: loadTextContent('../detections/user-added-to-administrators-group.kql')
    tactics: [ 'PrivilegeEscalation', 'Persistence' ]
    techniques: [ 'T1098' ]
    entityMappings: [
      hostEntity
      accountEntity
      { entityType: 'Account', fieldMappings: [ { identifier: 'Name', columnName: 'MemberName' } ] }
    ]
  }
  {
    id: 'new-windows-service-installed'
    displayName: 'New Windows Service Installed'
    severity: 'High'
    query: loadTextContent('../detections/new-windows-service-installed.kql')
    tactics: [ 'Persistence' ]
    techniques: [ 'T1543' ]
    entityMappings: [ hostEntity, accountEntity ]
  }
  {
    id: 'scheduled-task-persistence'
    displayName: 'Scheduled Task Persistence'
    severity: 'High'
    query: loadTextContent('../detections/scheduled-task-persistence.kql')
    tactics: [ 'Persistence' ]
    techniques: [ 'T1053' ]
  }
  {
    id: 'defender-firewall-manipulation'
    displayName: 'Defender Firewall Manipulation'
    severity: 'High'
    query: loadTextContent('../detections/defender-firewall-manipulation.kql')
    tactics: [ 'DefenseEvasion' ]
    techniques: [ 'T1562' ]
  }
  {
    id: 'successful-rdp-logon-detected'
    displayName: 'Successful RDP Logon Detected'
    severity: 'Low'
    query: loadTextContent('../detections/successful-rdp-logon-detected.kql')
    tactics: [ 'LateralMovement' ]
    techniques: [ 'T1021' ]
    entityMappings: [
      hostEntity
      accountEntity
      { entityType: 'IP', fieldMappings: [ { identifier: 'Address', columnName: 'IpAddress' } ] }
    ]
  }
  {
    id: 'inbound-port-scan'
    displayName: 'Inbound Port Scan'
    severity: 'Medium'
    query: loadTextContent('../detections/inbound-port-scan.kql')
    tactics: [ 'Discovery' ]
    techniques: [ 'T1046' ]
  }
  {
    id: 'outbound-network-scan'
    displayName: 'Outbound Network Scan'
    severity: 'Medium'
    query: loadTextContent('../detections/outbound-network-scan.kql')
    tactics: [ 'Discovery' ]
    techniques: [ 'T1046' ]
  }
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
    queryFrequency: r.?frequency ?? 'PT5M'
    queryPeriod: r.?frequency ?? 'PT5M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionEnabled: false
    suppressionDuration: 'PT5H'
    tactics: r.tactics
    techniques: r.techniques
    entityMappings: r.?entityMappings
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT5H'
        matchingMethod: 'AllEntities'
      }
    }
  }
}]
