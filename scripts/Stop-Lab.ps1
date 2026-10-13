# Deallocates every VM in the lab, then removes their public IPs.
# The subnets have default outbound access disabled, so the public IPs exist only to give running VMs
# egress (Log Analytics, updates). They bill by the hour whether or not a VM is running, so they are
# deleted while the lab is off and recreated by Start-Lab.ps1.
param(
    [string]$ResourceGroup = 'SOC_Lab',
    [switch]$KeepPublicIps
)

$ids = az vm list -g $ResourceGroup --query "[].id" -o tsv
az vm deallocate --ids $ids

if (-not $KeepPublicIps) {
    foreach ($nic in (az network nic list -g $ResourceGroup -o json | ConvertFrom-Json)) {
        foreach ($cfg in $nic.ipConfigurations | Where-Object { $_.publicIPAddress }) {
            $pipName = ($cfg.publicIPAddress.id -split '/')[-1]
            az network nic ip-config update -g $ResourceGroup --nic-name $nic.name -n $cfg.name --remove publicIpAddress -o none
            az network public-ip delete -g $ResourceGroup -n $pipName
            Write-Host "Removed public IP $pipName from $($nic.name)"
        }
    }
}

az vm list -g $ResourceGroup -d --query "[].{name:name, power:powerState, publicIp:publicIps}" -o table
