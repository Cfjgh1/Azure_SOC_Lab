# Starts the lab. The DC starts first so the Win10 VM can find the domain when it boots.
param(
    [string]$ResourceGroup = 'SOC_Lab',
    [switch]$IncludeKali
)

Write-Host 'Starting domain controller (SOC-WIN-VM1)...'
az vm start -g $ResourceGroup -n SOC-WIN-VM1

Write-Host 'Starting SOC-WIN10-VM...'
$vms = @('SOC-WIN10-VM')
if ($IncludeKali) { $vms += 'ATK-Kali-VM' }
$ids = $vms | ForEach-Object { az vm show -g $ResourceGroup -n $_ --query id -o tsv }
az vm start --ids $ids

az vm list -g $ResourceGroup -d --query "[].{name:name, power:powerState, privateIp:privateIps}" -o table
Write-Host 'Connect through Bastion in the Azure portal (VM > Connect > Bastion).'
