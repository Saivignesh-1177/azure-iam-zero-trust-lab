// Azure IAM Zero Trust Lab - resource group scope
//
// What this builds (all free / near-free):
//   - user-assigned managed identity (the workload's ONLY identity)
//   - RBAC-mode Key Vault, default-deny firewall, soft delete + purge protection
//   - two secrets: the one the app needs, and a decoy it must NOT be able to read
//   - Key Vault Secrets User scoped to ONE secret (not the vault, not the RG)
//   - Log Analytics workspace + Key Vault AuditEvent logs
//   - free activity-log alerts for RBAC / vault / logging tampering
//   - optional: a B1s probe VM with no public IP, no inbound, locked egress
//
// Every design decision is traced in ../threat-model.md and ../controls/control-mapping.csv.

targetScope = 'resourceGroup'

@description('Azure region. Defaults to the resource group location.')
param location string = resourceGroup().location

@description('Short unique suffix (lowercase letters/digits) used to build globally unique names.')
@minLength(3)
@maxLength(11)
param suffix string

@description('Object ID of the human admin who seeds and rotates secrets. Empty = no admin data-plane role.')
param adminPrincipalId string = ''

@allowed([
  'User'
  'Group'
])
param adminPrincipalType string = 'User'

@description('Public IPv4 addresses/CIDRs allowed through the Key Vault firewall, e.g. ["203.0.113.10"].')
param allowedIpRanges array = []

@description('Principal ID of the Azure Arc-enabled on-prem server (VirtualBox VM) that runs the app. Empty = not onboarded yet.')
param arcPrincipalId string = ''

@description('Deploy the optional B1s probe VM that proves the identity works (and is limited).')
param deployWorkload bool = false

@description('SSH public key for the probe VM. Password login is always disabled. Required when deployWorkload = true.')
param vmSshPublicKey string = ''

param vmAdminUsername string = 'azureuser'

@description('Standard_B1s is covered by the Azure free account (750 h/month for 12 months).')
param vmSize string = 'Standard_B1s'

@description('Lock VM egress down to Key Vault + Storage service tags (deny Internet).')
param restrictEgress bool = true

@description('Email for free activity-log alerts on RBAC / vault / diagnostic-setting changes. Empty = no alerts.')
param alertEmail string = ''

@description('Log Analytics daily ingestion cap in GB. 0.15 GB/day keeps you inside the 5 GB/month free allowance.')
param logDailyCapGb string = '0.15'

@description('Generated at deploy time; nobody ever sees it. Redeploying rotates it.')
@secure()
param appSecretValue string = newGuid()

@description('Decoy secret the workload must be denied. Generated at deploy time.')
@secure()
param decoySecretValue string = newGuid()

@description('Secret expiry (ISO 8601). Default = 90 days from deployment.')
param expiryDate string = dateTimeAdd(utcNow(), 'P90D')

param tags object = {
  project: 'azure-iam-zero-trust-lab'
  environment: 'lab'
  owner: 'security-engineering'
  dataClassification: 'synthetic'
}

// ---------------------------------------------------------------------------
// Names and built-in role IDs (role GUIDs are identical in every tenant)
// ---------------------------------------------------------------------------
var identityName = 'sc500-mi-${suffix}'
var vaultName = 'sc500kv${suffix}'
var workspaceName = 'sc500-law-${suffix}'
var vnetName = 'sc500-vnet-${suffix}'
var subnetName = 'snet-workload'
var nsgName = 'sc500-nsg-${suffix}'
var vmName = 'sc500-vm-${suffix}'
var appSecretName = 'app-db-password'
var decoySecretName = 'unrelated-team-secret'

var kvSecretsUserRoleId = '4633458b-17de-408a-b874-0445c86b69e6'
var kvSecretsOfficerRoleId = 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7'

// Control-plane operations an attacker would use to escalate, destroy, or go dark.
var watchedOperations = [
  'Microsoft.Authorization/roleAssignments/write'
  'Microsoft.Authorization/roleAssignments/delete'
  'Microsoft.KeyVault/vaults/write'
  'Microsoft.KeyVault/vaults/delete'
  'Microsoft.Insights/diagnosticSettings/delete'
]

var egressRules = [
  {
    name: 'allow-keyvault-443'
    properties: {
      priority: 100
      direction: 'Outbound'
      access: 'Allow'
      protocol: 'Tcp'
      sourceAddressPrefix: 'VirtualNetwork'
      sourcePortRange: '*'
      destinationAddressPrefix: 'AzureKeyVault'
      destinationPortRange: '443'
    }
  }
  {
    // VM agent / run-command extension packages come from Azure Storage.
    name: 'allow-storage-443'
    properties: {
      priority: 110
      direction: 'Outbound'
      access: 'Allow'
      protocol: 'Tcp'
      sourceAddressPrefix: 'VirtualNetwork'
      sourcePortRange: '*'
      destinationAddressPrefix: 'Storage'
      destinationPortRange: '443'
    }
  }
  {
    name: 'deny-internet-outbound'
    properties: {
      priority: 4000
      direction: 'Outbound'
      access: 'Deny'
      protocol: '*'
      sourceAddressPrefix: '*'
      sourcePortRange: '*'
      destinationAddressPrefix: 'Internet'
      destinationPortRange: '*'
    }
  }
]

var inboundRules = [
  {
    name: 'deny-all-inbound'
    properties: {
      priority: 4096
      direction: 'Inbound'
      access: 'Deny'
      protocol: '*'
      sourceAddressPrefix: '*'
      sourcePortRange: '*'
      destinationAddressPrefix: '*'
      destinationPortRange: '*'
    }
  }
]

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------
resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: workspaceName
  location: location
  tags: tags
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
    workspaceCapping: {
      dailyQuotaGb: json(logDailyCapGb)
    }
  }
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------
resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: identityName
  location: location
  tags: tags
}

// ---------------------------------------------------------------------------
// Optional network for the probe VM (deployed before the vault so the VNet rule can reference it)
// ---------------------------------------------------------------------------
resource nsg 'Microsoft.Network/networkSecurityGroups@2023-11-01' = if (deployWorkload) {
  name: nsgName
  location: location
  tags: tags
  properties: {
    securityRules: restrictEgress ? concat(inboundRules, egressRules) : inboundRules
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2023-11-01' = if (deployWorkload) {
  name: vnetName
  location: location
  tags: tags
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.20.0.0/24'
      ]
    }
    subnets: [
      {
        name: subnetName
        properties: {
          addressPrefix: '10.20.0.0/27'
          networkSecurityGroup: {
            id: nsg.id
          }
          // Free alternative to a Private Endpoint: traffic to Key Vault rides the Azure backbone
          // and the vault can trust this subnet by name.
          serviceEndpoints: [
            {
              service: 'Microsoft.KeyVault'
            }
          ]
          // Set explicitly so behaviour does not change with Azure's default-outbound retirement.
          // Egress is still filtered by the NSG above.
          defaultOutboundAccess: true
        }
      }
    ]
  }
}

var workloadSubnetId = resourceId('Microsoft.Network/virtualNetworks/subnets', vnetName, subnetName)

// ---------------------------------------------------------------------------
// Key Vault
// ---------------------------------------------------------------------------
resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: vaultName
  location: location
  tags: tags
  dependsOn: [
    vnet
  ]
  properties: {
    tenantId: subscription().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
    enablePurgeProtection: true // irreversible by design: even an Owner cannot purge for 7 days
    enabledForDeployment: false
    enabledForDiskEncryption: false
    enabledForTemplateDeployment: false
    publicNetworkAccess: 'Enabled'
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'None'
      ipRules: [for ip in allowedIpRanges: {
        value: ip
      }]
      virtualNetworkRules: deployWorkload
        ? [
            {
              id: workloadSubnetId
              ignoreMissingVnetServiceEndpoint: false
            }
          ]
        : []
    }
  }
}

resource appSecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: vault
  name: appSecretName
  properties: {
    value: appSecretValue
    contentType: 'text/plain'
    attributes: {
      enabled: true
      exp: dateTimeToEpoch(expiryDate)
    }
  }
}

resource decoySecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: vault
  name: decoySecretName
  properties: {
    value: decoySecretValue
    contentType: 'text/plain'
    attributes: {
      enabled: true
      exp: dateTimeToEpoch(expiryDate)
    }
  }
}

// Least privilege: the workload can read exactly ONE secret. Not the decoy, not the vault.
resource workloadSecretReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(appSecret.id, identity.id, kvSecretsUserRoleId)
  scope: appSecret
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', kvSecretsUserRoleId)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
    description: 'Workload may read only ${appSecretName} (NIST AC-6).'
  }
}

// Same least-privilege grant for the on-prem server: its Azure Arc system-assigned identity
// may read only app-db-password. Hybrid workloads get no wider rights than cloud ones.
resource arcSecretReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(arcPrincipalId)) {
  name: guid(appSecret.id, arcPrincipalId, kvSecretsUserRoleId)
  scope: appSecret
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', kvSecretsUserRoleId)
    principalId: arcPrincipalId
    principalType: 'ServicePrincipal'
    description: 'On-prem Arc server may read only ${appSecretName} (NIST AC-6, IA-9).'
  }
}

// The human admin manages secrets in THIS vault only - no Owner/Contributor needed day to day.
resource adminSecretsOfficer 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(adminPrincipalId)) {
  name: guid(vault.id, adminPrincipalId, kvSecretsOfficerRoleId)
  scope: vault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', kvSecretsOfficerRoleId)
    principalId: adminPrincipalId
    principalType: adminPrincipalType
    description: 'Lab admin manages secrets in this vault only (NIST AC-6(1)).'
  }
}

resource vaultDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'kv-audit-to-law'
  scope: vault
  properties: {
    workspaceId: workspace.id
    logs: [
      {
        category: 'AuditEvent'
        enabled: true
      }
    ]
  }
}

// ---------------------------------------------------------------------------
// Free detective controls: activity-log alerts
// ---------------------------------------------------------------------------
resource actionGroup 'Microsoft.Insights/actionGroups@2023-01-01' = if (!empty(alertEmail)) {
  name: 'sc500-ag-${suffix}'
  location: 'global'
  tags: tags
  properties: {
    groupShortName: 'sc500sec'
    enabled: true
    emailReceivers: [
      {
        name: 'secops'
        emailAddress: alertEmail
        useCommonAlertSchema: true
      }
    ]
  }
}

resource tamperAlerts 'Microsoft.Insights/activityLogAlerts@2020-10-01' = [for op in watchedOperations: if (!empty(alertEmail)) {
  name: 'sc500-alert-${toLower(replace(replace(op, 'Microsoft.', ''), '/', '-'))}'
  location: 'global'
  tags: tags
  properties: {
    enabled: true
    scopes: [
      resourceGroup().id
    ]
    condition: {
      allOf: [
        {
          field: 'category'
          equals: 'Administrative'
        }
        {
          field: 'operationName'
          equals: op
        }
      ]
    }
    actions: {
      actionGroups: [
        {
          actionGroupId: actionGroup.id
        }
      ]
    }
    description: 'Zero Trust lab: alert on ${op} (NIST AC-6(9), SI-4).'
  }
}]

// ---------------------------------------------------------------------------
// Optional probe VM: no public IP, no inbound, password login disabled
// ---------------------------------------------------------------------------
resource nic 'Microsoft.Network/networkInterfaces@2023-11-01' = if (deployWorkload) {
  name: '${vmName}-nic'
  location: location
  tags: tags
  dependsOn: [
    vnet
  ]
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          privateIPAllocationMethod: 'Dynamic'
          subnet: {
            id: workloadSubnetId
          }
        }
      }
    ]
  }
}

resource vm 'Microsoft.Compute/virtualMachines@2024-03-01' = if (deployWorkload) {
  name: vmName
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${identity.id}': {}
    }
  }
  properties: {
    hardwareProfile: {
      vmSize: vmSize
    }
    osProfile: {
      computerName: vmName
      adminUsername: vmAdminUsername
      linuxConfiguration: {
        disablePasswordAuthentication: true
        provisionVMAgent: true
        ssh: {
          publicKeys: [
            {
              path: '/home/${vmAdminUsername}/.ssh/authorized_keys'
              keyData: vmSshPublicKey
            }
          ]
        }
      }
    }
    storageProfile: {
      imageReference: {
        publisher: 'Canonical'
        offer: '0001-com-ubuntu-server-jammy'
        sku: '22_04-lts-gen2'
        version: 'latest'
      }
      osDisk: {
        createOption: 'FromImage'
        deleteOption: 'Delete'
        // 64 GB Premium SSD = P6, which the free account covers (2 x P6 for 12 months).
        diskSizeGB: 64
        managedDisk: {
          storageAccountType: 'Premium_LRS'
        }
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: nic.id
          properties: {
            deleteOption: 'Delete'
          }
        }
      ]
    }
    securityProfile: {
      securityType: 'TrustedLaunch'
      uefiSettings: {
        secureBootEnabled: true
        vTpmEnabled: true
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Outputs - identifiers only, never secret values
// ---------------------------------------------------------------------------
output managedIdentityId string = identity.id
output identityClientId string = identity.properties.clientId
output identityPrincipalId string = identity.properties.principalId
output keyVaultId string = vault.id
output keyVaultName string = vault.name
output keyVaultUri string = vault.properties.vaultUri
output appSecretName string = appSecretName
output decoySecretName string = decoySecretName
output workspaceId string = workspace.id
output workspaceCustomerId string = workspace.properties.customerId
output vmName string = deployWorkload ? vmName : ''
