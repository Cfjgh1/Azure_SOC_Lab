# Starts the lab. The DC starts first so the Win10 VM can find the domain when it boots.
# Each VM gets an egress-only public IP first (Stop-Lab.ps1 removes them to save cost): the subnets have
# default outbound access disabled, and the NSGs allow no inbound traffic from the internet.
# Always start VMs through this script; a plain `az vm start` or a portal Start leaves the VM with no
# internet access, so its logs never reach Sentinel.
#
#   ./scripts/Start-Lab.ps1                     # DC + Win10
#   ./scripts/Start-Lab.ps1 -IncludeKali        # DC + Win10 + Kali
#   ./scripts/Start-Lab.ps1 -Vm SOC-WIN-VM1     # just the named VM(s)
param(
    [string]$ResourceGroup = 'SOC_Lab',
    [switch]$IncludeKali,
    [string[]]$Vm
)

$dc = 'SOC-WIN-VM1'

function Add-EgressIp([string]$VmName) {
    $nicId = az vm show -g $ResourceGroup -n $VmName --query "networkProfile.networkInterfaces[0].id" -o tsv
    $nic = az network nic show --ids $nicId -o json | ConvertFrom-Json
    $cfg = $nic.ipConfigurations[0]
    if ($cfg.publicIPAddress) { return }

    $pipName = "$VmName-egress-ip"
    az network public-ip create -g $ResourceGroup -n $pipName --sku Standard --allocation-method Static -o none 3>$null
    az network nic ip-config update -g $ResourceGroup --nic-name $nic.name -n $cfg.name --public-ip-address $pipName -o none
    Write-Host "Attached $pipName to $VmName"
}

if ($Vm) { $vms = $Vm }
else {
    $vms = @($dc, 'SOC-WIN10-VM')
    if ($IncludeKali) { $vms += 'ATK-Kali-VM' }
}
foreach ($v in $vms) { Add-EgressIp $v }

if ($vms -contains $dc) {
    Write-Host "Starting domain controller ($dc)..."
    az vm start -g $ResourceGroup -n $dc
}
$others = @($vms | Where-Object { $_ -ne $dc })
if ($others) {
    Write-Host "Starting $($others -join ', ')..."
    $ids = $others | ForEach-Object { az vm show -g $ResourceGroup -n $_ --query id -o tsv }
    az vm start --ids $ids
}

az vm list -g $ResourceGroup -d --query "[].{name:name, power:powerState, privateIp:privateIps, egressIp:publicIps}" -o table
Write-Host 'Connect through Bastion in the Azure portal (VM > Connect > Bastion).'
Write-Host 'Logs can take 10-15 minutes to reach Sentinel after a cold start.'
Write-Host 'When finished, run ./scripts/Stop-Lab.ps1 (auto-shutdown deallocates VMs but leaves the public IPs).'
