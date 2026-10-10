# Checks that Sysmon is installed on both Windows VMs and that each log table is receiving data.
# The VMs must be running (use Start-Lab.ps1 first).
param(
    [string]$ResourceGroup = 'SOC_Lab',
    [string]$Workspace = 'SOC-Logs'
)

foreach ($vm in 'SOC-WIN-VM1', 'SOC-WIN10-VM') {
    Write-Host "== Sysmon on $vm =="
    az vm run-command invoke -g $ResourceGroup -n $vm --command-id RunPowerShellScript `
        --scripts "Get-Service Sysmon*, SysmonDrv -ErrorAction SilentlyContinue | Select-Object Name, Status | Format-Table | Out-String" `
        --query "value[0].message" -o tsv
}

Write-Host '== Rows per table, last 24h =='
$wsId = az monitor log-analytics workspace show -g $ResourceGroup -n $Workspace --query id -o tsv
$body = Join-Path $env:TEMP 'soc-lab-query.json'
@{ query = 'union withsource=Table SecurityEvent, Event, Heartbeat | where TimeGenerated > ago(24h) | summarize Rows=count() by Table, Computer | order by Table' } |
    ConvertTo-Json | Out-File $body -Encoding ascii
az rest --method post --url "https://api.loganalytics.io/v1$wsId/query" --resource https://api.loganalytics.io `
    --body "@$body" --query "tables[0].rows" -o json
