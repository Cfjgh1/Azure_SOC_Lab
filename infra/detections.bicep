// Sentinel scheduled analytics rules. Each query is loaded from detections/*.kql,
// so the KQL files in the repo are the source of truth.
// Deployed by .github/workflows/deploy-detections.yml on every push to main.

param workspaceName string

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

// Entity mappings let Sentinel link alerts to the hosts, accounts and IPs involved.
// IP entities are also what the response playbook reads to decide what to block.
var hostEntity = { entityType: 'Host', fieldMappings: [ { identifier: 'HostName', columnName: 'Computer' } ] }
var accountEntity = { entityType: 'Account', fieldMappings: [ { identifier: 'FullName', columnName: 'Account' } ] }
func ipEntity(column string) object => { entityType: 'IP', fieldMappings: [ { identifier: 'Address', columnName: column } ] }

// ruleId is the rule's resource name in Sentinel. These match the rules that already exist in the
// SOC-Logs workspace so deployments update them in place; any GUID works for a fresh workspace.
// Rules run every 5 minutes over the last 5 minutes unless frequency is set,
// in which case the lookback equals the frequency so each run covers its window exactly.
var rules = [
  {
    ruleId: '51f21bf8-f598-415b-aaac-9d6ee4a395b2'
    displayName: 'Multiple Failed Logins'
    severity: 'Medium'
    query: loadTextContent('../detections/multiple-failed-logins.kql')
    tactics: [ 'CredentialAccess' ]
    techniques: [ 'T1110' ]
    entityMappings: [ accountEntity, hostEntity, ipEntity('IpAddress') ]
  }
  {
    ruleId: 'ec8898a4-2208-493d-b7bb-ce8e2b381414'
    displayName: 'Potential Password Spraying'
    severity: 'Medium'
    query: loadTextContent('../detections/potential-password-spraying.kql')
    tactics: [ 'CredentialAccess' ]
    techniques: [ 'T1110' ]
    frequency: 'PT30M'
    entityMappings: [ ipEntity('IpAddress') ]
  }
  {
    ruleId: 'cee94d8b-22fb-4025-996a-ea14fabdb334'
    displayName: 'Kerberoasting'
    severity: 'Medium'
    query: loadTextContent('../detections/kerberoasting.kql')
    tactics: [ 'CredentialAccess' ]
    techniques: [ 'T1558' ]
    frequency: 'PT10M'
    entityMappings: [
      hostEntity
      { entityType: 'Account', fieldMappings: [ { identifier: 'Name', columnName: 'TargetUserName' } ] }
    ]
  }
  {
    ruleId: '179e0fc0-58ba-47f4-9072-e0da19c98916'
    displayName: 'LSASS Credential Access'
    severity: 'High'
    query: loadTextContent('../detections/lsass-credential-access.kql')
    tactics: [ 'CredentialAccess' ]
    techniques: [ 'T1003' ]
    entityMappings: [ hostEntity ]
  }
  {
    ruleId: '27623ea3-2d08-4c74-ba2d-b3e950aaea64'
    displayName: 'Encoded PowerShell Execution'
    severity: 'High'
    query: loadTextContent('../detections/encoded-powershell-execution.kql')
    tactics: [ 'Execution' ]
    techniques: [ 'T1059' ]
    entityMappings: [ accountEntity, hostEntity ]
  }
  {
    ruleId: 'dfdf211f-be73-4e5f-8110-3038bc41dbc2'
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
    ruleId: '8d4a1a69-10b7-41b2-91d8-137ebe1f9bf8'
    displayName: 'New Windows Service Installed'
    severity: 'High'
    query: loadTextContent('../detections/new-windows-service-installed.kql')
    tactics: [ 'Persistence' ]
    techniques: [ 'T1543' ]
    entityMappings: [ hostEntity, accountEntity ]
  }
  {
    ruleId: 'b45ad940-c7e0-4c94-ad76-58d660a5704d'
    displayName: 'Scheduled Task Persistence'
    severity: 'High'
    query: loadTextContent('../detections/scheduled-task-persistence.kql')
    tactics: [ 'Persistence' ]
    techniques: [ 'T1053' ]
    entityMappings: [
      hostEntity
      { entityType: 'Account', fieldMappings: [ { identifier: 'Name', columnName: 'SubjectUserName' } ] }
    ]
  }
  {
    ruleId: '7fa7b36f-e86a-40a9-b7da-4eed747b6191'
    displayName: 'Defender Firewall Manipulation'
    severity: 'High'
    query: loadTextContent('../detections/defender-firewall-manipulation.kql')
    tactics: [ 'DefenseEvasion' ]
    techniques: [ 'T1562' ]
    entityMappings: [ hostEntity, accountEntity ]
  }
  {
    ruleId: '1f2afd11-c785-440a-932e-b421e3ba9735'
    displayName: 'Successful RDP Logon Detected'
    severity: 'Low'
    query: loadTextContent('../detections/successful-rdp-logon-detected.kql')
    tactics: [ 'LateralMovement' ]
    techniques: [ 'T1021' ]
    entityMappings: [ hostEntity, accountEntity, ipEntity('IpAddress') ]
  }
  {
    ruleId: '7e74201b-a4c9-4993-b794-c2f70b530208'
    displayName: 'Inbound Port Scan'
    severity: 'Medium'
    query: loadTextContent('../detections/inbound-port-scan.kql')
    tactics: [ 'Discovery' ]
    techniques: [ 'T1046' ]
    entityMappings: [ hostEntity, ipEntity('SourceIp') ]
  }
  {
    ruleId: 'e9458f40-2b1a-4b09-a82f-da4ced4f2c13'
    displayName: 'Outbound Network Scan'
    severity: 'Medium'
    query: loadTextContent('../detections/outbound-network-scan.kql')
    tactics: [ 'Discovery' ]
    techniques: [ 'T1046' ]
    entityMappings: [ hostEntity, ipEntity('DestinationIp') ]
  }
]

resource alertRules 'Microsoft.SecurityInsights/alertRules@2024-03-01' = [for r in rules: {
  scope: workspace
  name: r.ruleId
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
