// Sends the subscription's activity log (who changed what in Azure) to the Sentinel workspace, where it lands in
// the AzureActivity table. The Security Control Tampering rule depends on it. Ingestion of this table is free.
//   az deployment sub create -l centralus -f infra/activity-log.bicep -p workspaceId=<workspace resource ID>
targetScope = 'subscription'

@description('Resource ID of the Log Analytics workspace.')
param workspaceId string

var categories = [ 'Administrative', 'Security', 'Policy', 'Alert' ]

resource activityToSentinel 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'soc-activity-to-sentinel'
  properties: {
    workspaceId: workspaceId
    logs: [for c in categories: { category: c, enabled: true }]
  }
}
