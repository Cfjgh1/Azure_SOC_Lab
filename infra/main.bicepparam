using 'main.bicep'

param adminUsername = 'labadmin'

// Supply the secrets at deploy time instead of storing them here:
//   az deployment group create -g SOC_Lab -f infra/main.bicep -p infra/main.bicepparam `
//     -p adminPassword=<password> kaliSshPublicKey="$(Get-Content ~/.ssh/id_rsa.pub)"
param adminPassword = ''
param kaliSshPublicKey = ''
