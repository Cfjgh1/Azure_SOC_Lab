# Shows and removes the AutoBlock-Attackers deny rules the response playbook adds to the NSGs.
param(
    [string]$ResourceGroup = 'SOC_Lab',
    [string[]]$NsgNames = @('SOC-WIN-VM1-nsg', 'SOC-WIN10-VM-nsg'),
    [switch]$WhatIf
)

foreach ($nsg in $NsgNames) {
    $ips = az network nsg rule show -g $ResourceGroup --nsg-name $nsg -n AutoBlock-Attackers `
        --query "sourceAddressPrefixes" -o tsv 2>$null
    if ($LASTEXITCODE -ne 0) { Write-Host "$nsg : no AutoBlock rule"; continue }
    Write-Host "$nsg : blocking $($ips -join ', ')"
    if (-not $WhatIf) {
        az network nsg rule delete -g $ResourceGroup --nsg-name $nsg -n AutoBlock-Attackers
        Write-Host "$nsg : rule removed"
    }
}
