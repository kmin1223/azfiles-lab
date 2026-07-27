// =============================================================================
// Azure Files Identity-Based Auth Lab - Session 1 (On-Prem AD DS simulation)
// Deploys: VNet (DNS -> DC), DC VM, Client VM, Storage Account + File Share
// The DC VM simulates the "on-premises" AD DS environment.
// =============================================================================

@description('Location for all resources')
param location string = resourceGroup().location

@description('Admin username for both VMs (also becomes domain admin)')
param adminUsername string = 'labadmin'

@description('Admin password for VMs / domain admin / lab users')
@secure()
param adminPassword string

@description('Resource name prefix')
param prefix string = 'azflab'

@description('VM size')
param vmSize string = 'Standard_B2ms'

// Bypasses internal subscription policies; harmless in personal subscriptions
var labTags = {
  SecurityControl: 'ignore'
}

var saName = toLower('${prefix}${uniqueString(resourceGroup().id)}')
var vnetName = '${prefix}-vnet'
var dcName = '${prefix}-dc'
var clientName = '${prefix}-cli'
var dcIp = '10.100.0.4'

// ---------------------------------------------------------------- Networking
resource nsg 'Microsoft.Network/networkSecurityGroups@2023-09-01' = {
  name: '${prefix}-nsg'
  location: location
  tags: labTags
  properties: {
    securityRules: [
      {
        name: 'Allow-RDP'
        properties: {
          priority: 1000
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: 'AzureCloud' // team connects via Azure VPN
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '3389'
        }
      }
    ]
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2023-09-01' = {
  name: vnetName
  location: location
  tags: labTags
  properties: {
    addressSpace: { addressPrefixes: [ '10.100.0.0/16' ] }
    dhcpOptions: { dnsServers: [ dcIp ] } // clients resolve AD via the DC
    subnets: [
      {
        name: 'lab'
        properties: {
          addressPrefix: '10.100.0.0/24'
          networkSecurityGroup: { id: nsg.id }
        }
      }
    ]
  }
}

// ------------------------------------------------------------------- Helpers
var vms = [
  { name: dcName, ip: dcIp, static: true }
  { name: clientName, ip: '', static: false }
]

resource pips 'Microsoft.Network/publicIPAddresses@2023-09-01' = [for vm in vms: {
  name: '${vm.name}-pip'
  location: location
  tags: labTags
  sku: { name: 'Standard' }
  properties: { publicIPAllocationMethod: 'Static' }
}]

resource nics 'Microsoft.Network/networkInterfaces@2023-09-01' = [for (vm, i) in vms: {
  name: '${vm.name}-nic'
  location: location
  tags: labTags
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          subnet: { id: vnet.properties.subnets[0].id }
          privateIPAllocationMethod: vm.static ? 'Static' : 'Dynamic'
          privateIPAddress: vm.static ? vm.ip : null
          publicIPAddress: { id: pips[i].id }
        }
      }
    ]
  }
}]

resource vmRes 'Microsoft.Compute/virtualMachines@2023-09-01' = [for (vm, i) in vms: {
  name: vm.name
  location: location
  tags: labTags
  properties: {
    hardwareProfile: { vmSize: vmSize }
    osProfile: {
      computerName: vm.name
      adminUsername: adminUsername
      adminPassword: adminPassword
      windowsConfiguration: {
        enableAutomaticUpdates: true
        provisionVMAgent: true
      }
    }
    storageProfile: {
      imageReference: {
        publisher: 'MicrosoftWindowsServer'
        offer: 'WindowsServer'
        sku: '2022-datacenter-azure-edition'
        version: 'latest'
      }
      osDisk: {
        createOption: 'FromImage'
        managedDisk: { storageAccountType: 'StandardSSD_LRS' }
      }
    }
    networkProfile: {
      networkInterfaces: [ { id: nics[i].id } ]
    }
    diagnosticsProfile: { bootDiagnostics: { enabled: true } }
  }
}]

// ------------------------------------------------------------------- Storage
resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: saName
  location: location
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  tags: labTags
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowSharedKeyAccess: true // needed for kerb key + demo comparisons
    supportsHttpsTrafficOnly: true
  }
}

resource fileSvc 'Microsoft.Storage/storageAccounts/fileServices@2023-01-01' = {
  parent: sa
  name: 'default'
}

resource share 'Microsoft.Storage/storageAccounts/fileServices/shares@2023-01-01' = {
  parent: fileSvc
  name: 'labshare'
  properties: { shareQuota: 100 }
}

// ------------------------------------------------------------------- Outputs
output storageAccountName string = saName
output dcVmName string = dcName
output clientVmName string = clientName
output dcPublicIp string = pips[0].properties.ipAddress
output clientPublicIp string = pips[1].properties.ipAddress
output vnetName string = vnetName
output nsgName string = '${prefix}-nsg'
