# Starts the lab. The DC starts first so the Win10 VM can find the domain when it boots.
# Each VM gets an egress-only public IP first (Stop-Lab.ps1 removes them to save cost): the subnets have
# default outbound access disabled, and the NSGs allow no inbound traffic from the internet.
param(
    [string]$ResourceGroup = 'SOC_Lab',
    [switch]$IncludeKali
)

function Add-EgressIp([string]$VmName) {
    $nicId = az vm show -g $ResourceGroup -n $VmName --query "networkProfile.networkInterfaces[0].id" -o tsv
    $nic = az network nic show --ids $nicId -o json | ConvertFrom-Json
    $cfg = $nic.ipConfigurations[0]
    if ($cfg.publicIPAddress) { return }

    $pipName = "$VmName-egress-ip"
    az network public-ip create -g $ResourceGroup -n $pipName --sku Standard --allocation-method Static -o none
    az network nic ip-config update -g $ResourceGroup --nic-name $nic.name -n $cfg.name --public-ip-address $pipName -o none
    Write-Host "Attached $pipName to $VmName"
}

$vms = @('SOC-WIN-VM1', 'SOC-WIN10-VM')
if ($IncludeKali) { $vms += 'ATK-Kali-VM' }
foreach ($vm in $vms) { Add-EgressIp $vm }

Write-Host 'Starting domain controller (SOC-WIN-VM1)...'
az vm start -g $ResourceGroup -n SOC-WIN-VM1

Write-Host "Starting $($vms[1..($vms.Count - 1)] -join ', ')..."
$ids = $vms[1..($vms.Count - 1)] | ForEach-Object { az vm show -g $ResourceGroup -n $_ --query id -o tsv }
az vm start --ids $ids

az vm list -g $ResourceGroup -d --query "[].{name:name, power:powerState, privateIp:privateIps}" -o table
Write-Host 'Connect through Bastion in the Azure portal (VM > Connect > Bastion).'
Write-Host 'When finished, run ./scripts/Stop-Lab.ps1 (auto-shutdown deallocates VMs but leaves the public IPs).'
