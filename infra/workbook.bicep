// Sentinel workbook: incidents, time to incident, rules that have fired, automatic containment and log delay.
// The layout and queries are in workbooks/soc-lab-overview.json.
//   az deployment group create -g SOC_Lab -f infra/workbook.bicep
param location string = resourceGroup().location
param workspaceName string = 'SOC-Logs'

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

resource workbook 'Microsoft.Insights/workbooks@2023-06-01' = {
  name: guid(workspace.id, 'soc-lab-overview')
  location: location
  kind: 'shared'
  properties: {
    displayName: 'SOC Lab Overview'
    category: 'sentinel'
    sourceId: workspace.id
    serializedData: string(loadJsonContent('workbooks/soc-lab-overview.json'))
  }
}
