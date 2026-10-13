// SOC lab: AD domain controller + Win10 endpoint (SOC_Vnet), Kali attacker (Attack-VNET),
// Log Analytics + Sentinel, AMA with a DCR for Security / Sysmon / System events.
// Target state: no inbound internet rules (access via Bastion), Standard HDD disks,
// static DC IP, VNet DNS pointed at the DC.

targetScope = 'resourceGroup'

param location string = resourceGroup().location

@description('Local admin username for the Windows VMs and Kali.')
param adminUsername string

@secure()
@description('Local admin password for the Windows VMs.')
param adminPassword string

@description('SSH public key for the Kali VM (ssh-rsa ...).')
param kaliSshPublicKey string

@description('Daily auto-shutdown time (HHmm, UTC).')
param shutdownTime string = '1900'

param vmSize string = 'Standard_D2s_v3'
param dcPrivateIp string = '10.0.0.4'
param workspaceName string = 'SOC-Logs'
param retentionInDays int = 30

@description('Daily ingestion cap (GB) so a noisy VM left running cannot run up the bill.')
param dailyCapGb int = 1

// ---------------------------------------------------------------- Networking

resource socVnet 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: 'SOC_Vnet'
  location: location
  properties: {
    addressSpace: { addressPrefixes: [ '10.0.0.0/16' ] }
    dhcpOptions: { dnsServers: [ dcPrivateIp ] }
    subnets: [
      {
        name: 'SOC_Subent'
        properties: {
          addressPrefix: '10.0.0.0/24'
          defaultOutboundAccess: false
        }
      }
    ]
  }
}

resource attackVnet 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: 'Attack-VNET'
  location: location
  properties: {
    addressSpace: { addressPrefixes: [ '10.1.0.0/16' ] }
    subnets: [
      {
        name: 'ATK'
        properties: {
          addressPrefix: '10.1.0.0/24'
          defaultOutboundAccess: false
        }
      }
    ]
  }
}

resource socToAttack 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings@2024-05-01' = {
  parent: socVnet
  name: 'Attk'
  properties: {
    remoteVirtualNetwork: { id: attackVnet.id }
    allowVirtualNetworkAccess: true
  }
}

resource attackToSoc 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings@2024-05-01' = {
  parent: attackVnet
  name: 'SOC'
  properties: {
    remoteVirtualNetwork: { id: socVnet.id }
    allowVirtualNetworkAccess: true
  }
}

// Developer SKU Bastion is free but only reaches VMs in its own VNet, hence one per VNet.
resource socBastion 'Microsoft.Network/bastionHosts@2024-05-01' = {
  name: 'SOC_Vnet-bastion'
  location: location
  sku: { name: 'Developer' }
  properties: {
    virtualNetwork: { id: socVnet.id }
  }
}

resource attackBastion 'Microsoft.Network/bastionHosts@2024-05-01' = {
  name: 'Attack-VNET-bastion'
  location: location
  sku: { name: 'Developer' }
  properties: {
    virtualNetwork: { id: attackVnet.id }
  }
}

// ---------------------------------------------------------------- VMs

// The subnets have default outbound access disabled, so each VM keeps a public IP
// purely for outbound traffic (AMA -> Log Analytics, updates). The NSGs have no
// inbound allow rules, so the default DenyAllInBound applies.
var windowsVms = [
  {
    name: 'SOC-WIN-VM1'
    privateIp: dcPrivateIp
    image: {
      publisher: 'MicrosoftWindowsServer'
      offer: 'WindowsServer'
      sku: '2022-datacenter-g2'
      version: 'latest'
    }
  }
  {
    name: 'SOC-WIN10-VM'
    privateIp: '10.0.0.5'
    image: {
      publisher: 'MicrosoftWindowsDesktop'
      offer: 'Windows-10'
      sku: 'win10-21h2-ent-ltsc-g2'
      version: 'latest'
    }
  }
]

resource winNsg 'Microsoft.Network/networkSecurityGroups@2024-05-01' = [for vm in windowsVms: {
  name: '${vm.name}-nsg'
  location: location
  properties: { securityRules: [] }
}]

resource winPip 'Microsoft.Network/publicIPAddresses@2024-05-01' = [for vm in windowsVms: {
  name: '${vm.name}-ip'
  location: location
  sku: { name: 'Standard' }
  properties: { publicIPAllocationMethod: 'Static' }
}]

resource winNic 'Microsoft.Network/networkInterfaces@2024-05-01' = [for (vm, i) in windowsVms: {
  name: '${toLower(vm.name)}-nic'
  location: location
  properties: {
    networkSecurityGroup: { id: winNsg[i].id }
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          subnet: { id: socVnet.properties.subnets[0].id }
          privateIPAllocationMethod: 'Static'
          privateIPAddress: vm.privateIp
          publicIPAddress: { id: winPip[i].id }
        }
      }
    ]
  }
}]

resource winVm 'Microsoft.Compute/virtualMachines@2024-07-01' = [for (vm, i) in windowsVms: {
  name: vm.name
  location: location
  identity: { type: 'SystemAssigned' }
  properties: {
    hardwareProfile: { vmSize: vmSize }
    osProfile: {
      computerName: vm.name
      adminUsername: adminUsername
      adminPassword: adminPassword
    }
    storageProfile: {
      imageReference: vm.image
      osDisk: {
        createOption: 'FromImage'
        managedDisk: { storageAccountType: 'Standard_LRS' }
      }
    }
    networkProfile: {
      networkInterfaces: [ { id: winNic[i].id } ]
    }
    securityProfile: {
      securityType: 'TrustedLaunch'
      uefiSettings: { secureBootEnabled: true, vTpmEnabled: true }
    }
  }
}]

resource winAma 'Microsoft.Compute/virtualMachines/extensions@2024-07-01' = [for (vm, i) in windowsVms: {
  parent: winVm[i]
  name: 'AzureMonitorWindowsAgent'
  location: location
  properties: {
    publisher: 'Microsoft.Azure.Monitor'
    type: 'AzureMonitorWindowsAgent'
    typeHandlerVersion: '1.0'
    autoUpgradeMinorVersion: true
    enableAutomaticUpgrade: true
  }
}]

resource winShutdown 'Microsoft.DevTestLab/schedules@2018-09-15' = [for (vm, i) in windowsVms: {
  name: 'shutdown-computevm-${vm.name}'
  location: location
  properties: {
    status: 'Enabled'
    taskType: 'ComputeVmShutdownTask'
    dailyRecurrence: { time: shutdownTime }
    timeZoneId: 'UTC'
    targetResourceId: winVm[i].id
  }
}]

resource kaliNsg 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: 'ATK-Kali-VM-nsg'
  location: location
  properties: { securityRules: [] }
}

resource kaliPip 'Microsoft.Network/publicIPAddresses@2024-05-01' = {
  name: 'ATK-Kali-VM-ip'
  location: location
  sku: { name: 'Standard' }
  properties: { publicIPAllocationMethod: 'Static' }
}

resource kaliNic 'Microsoft.Network/networkInterfaces@2024-05-01' = {
  name: 'atk-kali-vm-nic'
  location: location
  properties: {
    networkSecurityGroup: { id: kaliNsg.id }
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          subnet: { id: attackVnet.properties.subnets[0].id }
          privateIPAllocationMethod: 'Dynamic'
          publicIPAddress: { id: kaliPip.id }
        }
      }
    ]
  }
}

// Kali is a Marketplace image: accept its terms once per subscription with
//   az vm image terms accept --publisher kali-linux --offer kali --plan kali-2026-1
resource kaliVm 'Microsoft.Compute/virtualMachines@2024-07-01' = {
  name: 'ATK-Kali-VM'
  location: location
  plan: {
    publisher: 'kali-linux'
    product: 'kali'
    name: 'kali-2026-1'
  }
  properties: {
    hardwareProfile: { vmSize: vmSize }
    osProfile: {
      computerName: 'ATK-Kali-VM'
      adminUsername: adminUsername
      linuxConfiguration: {
        disablePasswordAuthentication: true
        ssh: {
          publicKeys: [
            {
              path: '/home/${adminUsername}/.ssh/authorized_keys'
              keyData: kaliSshPublicKey
            }
          ]
        }
      }
    }
    storageProfile: {
      imageReference: {
        publisher: 'kali-linux'
        offer: 'kali'
        sku: 'kali-2026-1'
        version: 'latest'
      }
      osDisk: {
        createOption: 'FromImage'
        managedDisk: { storageAccountType: 'Standard_LRS' }
      }
    }
    networkProfile: {
      networkInterfaces: [ { id: kaliNic.id } ]
    }
  }
}

resource kaliShutdown 'Microsoft.DevTestLab/schedules@2018-09-15' = {
  name: 'shutdown-computevm-ATK-Kali-VM'
  location: location
  properties: {
    status: 'Enabled'
    taskType: 'ComputeVmShutdownTask'
    dailyRecurrence: { time: '1700' }
    timeZoneId: 'UTC'
    targetResourceId: kaliVm.id
  }
}

// ---------------------------------------------------------------- Logging / Sentinel

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: workspaceName
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: retentionInDays
    workspaceCapping: { dailyQuotaGb: dailyCapGb }
  }
}

resource sentinel 'Microsoft.SecurityInsights/onboardingStates@2024-03-01' = {
  scope: workspace
  name: 'default'
  properties: {}
}

// Security events -> SecurityEvent table; Sysmon + System -> Event table.
// (Microsoft-SecurityEvent only accepts the Security channel, so the others need their own stream.)
resource dcr 'Microsoft.Insights/dataCollectionRules@2022-06-01' = {
  name: 'dcr-soc-windows-security'
  location: location
  kind: 'Windows'
  properties: {
    dataSources: {
      windowsEventLogs: [
        {
          name: 'securityEvents'
          streams: [ 'Microsoft-SecurityEvent' ]
          xPathQueries: [ 'Security!*' ]
        }
        {
          name: 'sysmonAndSystemEvents'
          streams: [ 'Microsoft-Event' ]
          xPathQueries: [
            'Microsoft-Windows-Sysmon/Operational!*'
            'System!*'
          ]
        }
      ]
    }
    destinations: {
      logAnalytics: [
        {
          name: 'DataCollectionEvent'
          workspaceResourceId: workspace.id
        }
      ]
    }
    dataFlows: [
      { streams: [ 'Microsoft-SecurityEvent' ], destinations: [ 'DataCollectionEvent' ] }
      { streams: [ 'Microsoft-Event' ], destinations: [ 'DataCollectionEvent' ] }
    ]
  }
}

resource dcrAssociation 'Microsoft.Insights/dataCollectionRuleAssociations@2022-06-01' = [for (vm, i) in windowsVms: {
  scope: winVm[i]
  name: 'dcr-soc-windows-security-association'
  properties: {
    dataCollectionRuleId: dcr.id
  }
}]

module detections 'detections.bicep' = {
  name: 'sentinel-detections'
  params: {
    workspaceName: workspace.name
  }
  dependsOn: [ sentinel ]
}

output dcPrivateIp string = dcPrivateIp
output workspaceId string = workspace.properties.customerId
