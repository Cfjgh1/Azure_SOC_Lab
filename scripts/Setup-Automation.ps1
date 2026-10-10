# One-time setup for the lab's automation. Run as a subscription Owner, signed in to both az and gh.
#
#   -Pipeline : creates the Entra ID app GitHub Actions signs in as (OIDC, no secret), trusts only
#               this repo's main branch, grants it Microsoft Sentinel Contributor on the resource group,
#               and stores the IDs as GitHub repo variables.
#   -Playbook : deploys infra/playbook.bicep (Logic App, connections, role assignments, automation rule).
param(
    [switch]$Pipeline,
    [switch]$Playbook,
    [string]$NotificationEmail,
    [string]$ResourceGroup = 'SOC_Lab',
    [string]$Repo = 'Cfjgh1/Azure_SOC_Lab'
)

$sub    = az account show --query id -o tsv
$tenant = az account show --query tenantId -o tsv
$rgId   = "/subscriptions/$sub/resourceGroups/$ResourceGroup"

if ($Pipeline) {
    $appName = 'github-azure-soc-lab-detections'
    $appId = az ad app list --display-name $appName --query "[0].appId" -o tsv
    if (-not $appId) { $appId = az ad app create --display-name $appName --query appId -o tsv }
    $spId = az ad sp list --filter "appId eq '$appId'" --query "[0].id" -o tsv
    if (-not $spId) { $spId = az ad sp create --id $appId --query id -o tsv }
    Write-Host "App: $appName ($appId)"

    $subject = "repo:${Repo}:environment:sentinel"
    $existing = az ad app federated-credential list --id $appId --query "[?subject=='$subject'].name" -o tsv
    if (-not $existing) {
        $fc = Join-Path $env:TEMP 'soc-lab-fc.json'
        @{ name = 'github-sentinel-env'; issuer = 'https://token.actions.githubusercontent.com'; subject = $subject
           audiences = @('api://AzureADTokenExchange'); description = 'GitHub Actions deploy job (environment: sentinel)' } |
            ConvertTo-Json | Out-File $fc -Encoding ascii
        az ad app federated-credential create --id $appId --parameters "@$fc" | Out-Null
    }
    Write-Host "Federated credential: $subject"

    # New service principals can take a few seconds to replicate before a role can be assigned.
    for ($i = 0; $i -lt 6; $i++) {
        az role assignment create --assignee-object-id $spId --assignee-principal-type ServicePrincipal `
            --role 'Microsoft Sentinel Contributor' --scope $rgId -o none 2>$null
        if ($LASTEXITCODE -eq 0) { break }
        Start-Sleep 10
    }
    Write-Host "Role: Microsoft Sentinel Contributor on $ResourceGroup"

    gh api -X PUT "repos/$Repo/environments/sentinel" --silent
    gh variable set AZURE_CLIENT_ID --repo $Repo --body $appId
    gh variable set AZURE_TENANT_ID --repo $Repo --body $tenant
    gh variable set AZURE_SUBSCRIPTION_ID --repo $Repo --body $sub
    Write-Host 'GitHub environment "sentinel" and repo variables set.'
}

if ($Playbook) {
    if (-not $NotificationEmail) { throw 'Pass -NotificationEmail <address> with -Playbook.' }
    # "Azure Security Insights" is Sentinel's first-party app; its object ID differs per tenant.
    $sentinelSp = az ad sp show --id 98785600-1bb7-4fb9-b9fa-19afe2c8a360 --query id -o tsv
    az deployment group create -g $ResourceGroup -n soc-playbook -f (Join-Path $PSScriptRoot '..\infra\playbook.bicep') `
        -p notificationEmail=$NotificationEmail sentinelServicePrincipalId=$sentinelSp `
        --query properties.provisioningState -o tsv
    Write-Host ''
    Write-Host 'Last step: authorize the Outlook.com connection in the portal:'
    Write-Host "  $ResourceGroup > outlook-soc-response > Edit API connection > Authorize > Save"
}

if (-not ($Pipeline -or $Playbook)) { Write-Host 'Specify -Pipeline and/or -Playbook.' }
