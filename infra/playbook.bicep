// SOAR playbook: runs on every new Sentinel incident.
//  1. Pulls IP entities from the incident, ignoring internal / protected ranges.
//  2. For brute-force, spraying and port-scan incidents, adds those IPs to a deny rule
//     (AutoBlock-Attackers) on the Windows VMs' NSGs.
//  3. Comments on the incident with what it found and did.
//  4. Emails a summary through Outlook.com.
//
// The Outlook.com connection must be authorized once in the portal after deployment
// (Logic App > API connections > outlook-soc-response > Edit API connection > Authorize).

param location string = resourceGroup().location
param workspaceName string = 'SOC-Logs'
param playbookName string = 'SOC-Incident-Response'

@description('Where incident emails are sent.')
param notificationEmail string

@description('Object ID of the "Azure Security Insights" service principal in this tenant (lets Sentinel run the playbook).')
param sentinelServicePrincipalId string

@description('NSGs that receive the AutoBlock-Attackers deny rule.')
param nsgNames array = [ 'SOC-WIN-VM1-nsg', 'SOC-WIN10-VM-nsg' ]

@description('Incidents with these titles (analytics rule names) trigger IP containment.')
param containmentRules array = [ 'Multiple Failed Logins', 'Potential Password Spraying', 'Inbound Port Scan' ]

@description('IP prefixes that are never blocked: the SOC subnet itself, loopback, and empty values from logs.')
param protectedPrefixes array = [ '10.0.', '127.', '0.', '-' ]

var blockRuleName = 'AutoBlock-Attackers'
var armUrl = environment().resourceManager                      // https://management.azure.com/
var armBase = substring(armUrl, 0, length(armUrl) - 1)          // without the trailing slash
var nsgIds = [for n in nsgNames: resourceId('Microsoft.Network/networkSecurityGroups', n)]

// Logic Apps expression that keeps an entity only if it's an IPv4 address outside protectedPrefixes.
var addr = 'string(item()?[\'properties\']?[\'address\'])'
var prefixChecks = join(map(protectedPrefixes, p => 'not(startsWith(${addr}, \'${p}\'))'), ', ')
var ipFilter = '@and(equals(item()?[\'kind\'], \'Ip\'), not(empty(${addr})), not(contains(${addr}, \':\')), ${prefixChecks})'

// ---------------------------------------------------------------- Connections

resource sentinelConnection 'Microsoft.Web/connections@2016-06-01' = {
  name: 'azuresentinel-soc-response'
  location: location
  kind: 'V1'
  properties: {
    displayName: 'Sentinel (managed identity)'
    api: { id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuresentinel') }
    parameterValueType: 'Alternative'
  }
}

resource outlookConnection 'Microsoft.Web/connections@2016-06-01' = {
  name: 'outlook-soc-response'
  location: location
  properties: {
    displayName: 'Outlook.com (authorize in portal)'
    api: { id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'outlook') }
  }
}

// ---------------------------------------------------------------- Playbook

resource playbook 'Microsoft.Logic/workflows@2019-05-01' = {
  name: playbookName
  location: location
  identity: { type: 'SystemAssigned' }
  properties: {
    state: 'Enabled'
    parameters: {
      '$connections': {
        value: {
          azuresentinel: {
            connectionId: sentinelConnection.id
            connectionName: sentinelConnection.name
            id: sentinelConnection.properties.api.id
            connectionProperties: { authentication: { type: 'ManagedServiceIdentity' } }
          }
          outlook: {
            connectionId: outlookConnection.id
            connectionName: outlookConnection.name
            id: outlookConnection.properties.api.id
          }
        }
      }
    }
    definition: {
      '$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
      contentVersion: '1.0.0.0'
      parameters: {
        '$connections': { type: 'Object', defaultValue: {} }
      }
      triggers: {
        Microsoft_Sentinel_incident: {
          type: 'ApiConnectionWebhook'
          inputs: {
            host: { connection: { name: '@parameters(\'$connections\')[\'azuresentinel\'][\'connectionId\']' } }
            body: { callback_url: '@{listCallbackUrl()}' }
            path: '/incident-creation'
          }
        }
      }
      actions: {
        Init_ContainmentNote: {
          type: 'InitializeVariable'
          runAfter: {}
          inputs: {
            variables: [
              { name: 'ContainmentNote', type: 'string', value: 'No containment: rule is not in the containment list, or the incident has no external IPv4 addresses.' }
            ]
          }
        }
        Filter_external_IPs: {
          type: 'Query'
          runAfter: { Init_ContainmentNote: [ 'Succeeded' ] }
          inputs: {
            from: '@coalesce(triggerBody()?[\'object\']?[\'properties\']?[\'relatedEntities\'], json(\'[]\'))'
            where: ipFilter
          }
        }
        Select_addresses: {
          type: 'Select'
          runAfter: { Filter_external_IPs: [ 'Succeeded' ] }
          inputs: {
            from: '@body(\'Filter_external_IPs\')'
            select: '@string(item()?[\'properties\']?[\'address\'])'
          }
        }
        Unique_IPs: {
          type: 'Compose'
          runAfter: { Select_addresses: [ 'Succeeded' ] }
          inputs: '@union(body(\'Select_addresses\'), body(\'Select_addresses\'))'
        }
        Should_contain: {
          type: 'If'
          runAfter: { Unique_IPs: [ 'Succeeded' ] }
          expression: '@and(contains(json(\'${string(containmentRules)}\'), triggerBody()?[\'object\']?[\'properties\']?[\'title\']), greater(length(outputs(\'Unique_IPs\')), 0))'
          actions: {
            For_each_NSG: {
              type: 'Foreach'
              foreach: nsgIds
              runtimeConfiguration: { concurrency: { repetitions: 1 } }
              actions: {
                Get_block_rule: {
                  type: 'Http'
                  inputs: {
                    method: 'GET'
                    uri: '@{concat(\'${armBase}\',items(\'For_each_NSG\'), \'/securityRules/${blockRuleName}?api-version=2024-05-01\')}'
                    authentication: { type: 'ManagedServiceIdentity', audience: armUrl }
                  }
                }
                // Runs whether or not the rule exists yet: a 404 just means start from an empty list.
                Put_block_rule: {
                  type: 'Http'
                  runAfter: { Get_block_rule: [ 'Succeeded', 'Failed' ] }
                  inputs: {
                    method: 'PUT'
                    uri: '@{concat(\'${armBase}\',items(\'For_each_NSG\'), \'/securityRules/${blockRuleName}?api-version=2024-05-01\')}'
                    authentication: { type: 'ManagedServiceIdentity', audience: armUrl }
                    body: {
                      properties: {
                        description: 'Managed by the ${playbookName} playbook. Clear with scripts/Clear-AutoBlocks.ps1.'
                        priority: 100
                        direction: 'Inbound'
                        access: 'Deny'
                        protocol: '*'
                        sourcePortRange: '*'
                        destinationPortRange: '*'
                        destinationAddressPrefix: '*'
                        sourceAddressPrefixes: '@union(coalesce(body(\'Get_block_rule\')?[\'properties\']?[\'sourceAddressPrefixes\'], json(\'[]\')), outputs(\'Unique_IPs\'))'
                      }
                    }
                  }
                }
              }
            }
            Set_ContainmentNote: {
              type: 'SetVariable'
              runAfter: { For_each_NSG: [ 'Succeeded' ] }
              inputs: {
                name: 'ContainmentNote'
                value: 'Blocked inbound traffic from @{join(outputs(\'Unique_IPs\'), \', \')} on ${join(nsgNames, ', ')} (rule ${blockRuleName}).'
              }
            }
          }
          else: { actions: {} }
        }
        Containment_failed: {
          type: 'SetVariable'
          runAfter: { Should_contain: [ 'Failed', 'TimedOut' ] }
          inputs: {
            name: 'ContainmentNote'
            value: 'Containment FAILED for @{join(outputs(\'Unique_IPs\'), \', \')}. Check the playbook run history.'
          }
        }
        Comment_on_incident: {
          type: 'Http'
          runAfter: {
            Should_contain: [ 'Succeeded', 'Failed', 'TimedOut', 'Skipped' ]
            Containment_failed: [ 'Succeeded', 'Skipped' ]
          }
          inputs: {
            method: 'PUT'
            uri: '@{concat(\'${armBase}\',triggerBody()?[\'object\']?[\'id\'], \'/comments/\', guid(), \'?api-version=2024-03-01\')}'
            authentication: { type: 'ManagedServiceIdentity', audience: armUrl }
            body: {
              properties: {
                message: '<b>${playbookName}</b><br/>External IPs: @{if(empty(outputs(\'Unique_IPs\')), \'none\', join(outputs(\'Unique_IPs\'), \', \'))}<br/>@{variables(\'ContainmentNote\')}'
              }
            }
          }
        }
        Send_email: {
          type: 'ApiConnection'
          runAfter: { Comment_on_incident: [ 'Succeeded', 'Failed' ] }
          inputs: {
            host: { connection: { name: '@parameters(\'$connections\')[\'outlook\'][\'connectionId\']' } }
            method: 'post'
            path: '/v2/Mail'
            body: {
              To: notificationEmail
              Subject: '[Sentinel] @{triggerBody()?[\'object\']?[\'properties\']?[\'severity\']}: @{triggerBody()?[\'object\']?[\'properties\']?[\'title\']} (#@{triggerBody()?[\'object\']?[\'properties\']?[\'incidentNumber\']})'
              Body: '<p><b>@{triggerBody()?[\'object\']?[\'properties\']?[\'title\']}</b></p><p>Severity: @{triggerBody()?[\'object\']?[\'properties\']?[\'severity\']}<br/>Created: @{triggerBody()?[\'object\']?[\'properties\']?[\'createdTimeUtc\']}<br/>Entities: @{length(coalesce(triggerBody()?[\'object\']?[\'properties\']?[\'relatedEntities\'], json(\'[]\')))}<br/>External IPs: @{if(empty(outputs(\'Unique_IPs\')), \'none\', join(outputs(\'Unique_IPs\'), \', \'))}</p><p>@{variables(\'ContainmentNote\')}</p><p><a href="@{triggerBody()?[\'object\']?[\'properties\']?[\'incidentUrl\']}">Open incident in Sentinel</a></p>'
              Importance: 'Normal'
            }
          }
        }
      }
      outputs: {}
    }
  }
}

// ---------------------------------------------------------------- Permissions

var roles = {
  sentinelResponder: '3e150937-b8fe-4cfb-8069-0eaf05ecd056'
  sentinelAutomationContributor: 'f4c81013-99ee-4d62-a7ee-b3f1f648599a'
  networkContributor: '4d97b98b-1d4f-4787-a291-c67834d212e7'
}

// Playbook can read incidents and add comments.
resource playbookResponder 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, playbook.id, roles.sentinelResponder)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.sentinelResponder)
    principalId: playbook.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// Playbook can edit only the two NSGs it blocks on.
resource nsgs 'Microsoft.Network/networkSecurityGroups@2024-05-01' existing = [for n in nsgNames: {
  name: n
}]

resource playbookNsgContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for (n, i) in nsgNames: {
  scope: nsgs[i]
  name: guid(nsgs[i].id, playbook.id, roles.networkContributor)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.networkContributor)
    principalId: playbook.identity.principalId
    principalType: 'ServicePrincipal'
  }
}]

// Sentinel itself needs this to run playbooks in this resource group from automation rules.
resource sentinelRunsPlaybooks 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, sentinelServicePrincipalId, roles.sentinelAutomationContributor)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.sentinelAutomationContributor)
    principalId: sentinelServicePrincipalId
    principalType: 'ServicePrincipal'
  }
}

// ---------------------------------------------------------------- Automation rule

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

resource runPlaybookOnIncident 'Microsoft.SecurityInsights/automationRules@2024-03-01' = {
  scope: workspace
  name: guid(workspace.id, playbook.id)
  properties: {
    displayName: 'Run ${playbookName} on new incidents'
    order: 1
    triggeringLogic: {
      isEnabled: true
      triggersOn: 'Incidents'
      triggersWhen: 'Created'
    }
    actions: [
      {
        order: 1
        actionType: 'RunPlaybook'
        actionConfiguration: {
          logicAppResourceId: playbook.id
          tenantId: subscription().tenantId
        }
      }
    ]
  }
  dependsOn: [ sentinelRunsPlaybooks ]
}

output playbookPrincipalId string = playbook.identity.principalId
