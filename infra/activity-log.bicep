// Subscription scope: send the Azure Activity Log (who changed what in the control plane)
// to the lab workspace. Activity Log ingestion into Log Analytics is free.
//
// az deployment sub create -l <region> -n sc500-activity-log \
//   -f infra/activity-log.bicep -p workspaceId=<workspace resource id>

targetScope = 'subscription'

@description('Resource ID of the Log Analytics workspace created by main.bicep.')
param workspaceId string

var categories = [
  'Administrative'
  'Security'
  'Policy'
  'Alert'
]

resource activityToWorkspace 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'sc500-activity-to-law'
  properties: {
    workspaceId: workspaceId
    logs: [for category in categories: {
      category: category
      enabled: true
    }]
  }
}
