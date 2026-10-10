# Exports the workspace's scheduled Sentinel analytics rules into detections/ as one .kql file per rule,
# with the rule's metadata in a header comment. Re-run after changing rules in the portal.
param(
    [string]$ResourceGroup = 'SOC_Lab',
    [string]$Workspace = 'SOC-Logs',
    [string]$OutDir = (Join-Path $PSScriptRoot '..\detections')
)

$sub = az account show --query id -o tsv
$url = "https://management.azure.com/subscriptions/$sub/resourceGroups/$ResourceGroup/providers/" +
       "Microsoft.OperationalInsights/workspaces/$Workspace/providers/Microsoft.SecurityInsights/alertRules?api-version=2024-03-01"
$rules = (az rest --method get --url $url -o json | ConvertFrom-Json).value | Where-Object kind -eq 'Scheduled'

New-Item -ItemType Directory -Force $OutDir | Out-Null
foreach ($r in $rules) {
    $p = $r.properties
    $file = ($p.displayName.ToLower() -replace '[^a-z0-9]+', '-').Trim('-') + '.kql'
    $header = @(
        "// Name:       $($p.displayName)"
        "// Severity:   $($p.severity)"
        "// Frequency:  $($p.queryFrequency)   Lookback: $($p.queryPeriod)"
        "// Tactics:    $(if ($p.tactics) { $p.tactics -join ', ' } else { '-' })"
        "// Techniques: $(if ($p.techniques) { $p.techniques -join ', ' } else { '-' })"
        "// Enabled:    $($p.enabled)"
        ''
    )
    ($header + $p.query.TrimEnd()) -join "`n" | Out-File (Join-Path $OutDir $file) -Encoding utf8
    Write-Host "Exported $file"
}
