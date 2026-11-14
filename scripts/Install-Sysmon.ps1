# Installs Sysmon on a Windows lab VM with the same configuration the lab runs:
# the SwiftOnSecurity baseline, plus logging of process access to lsass.exe (event 10), which the
# LSASS Credential Access rule needs. Safe to run again: it updates the configuration if Sysmon is already installed.
# The VM needs internet access, so start it with Start-Lab.ps1 first.
#   az vm run-command invoke -g SOC_Lab -n SOC-WIN10-VM --command-id RunPowerShellScript --scripts @scripts/Install-Sysmon.ps1
param(
    [string]$InstallDir = 'C:\ProgramData\SysmonSetup'
)
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

New-Item -ItemType Directory -Force $InstallDir | Out-Null
$zip    = Join-Path $InstallDir 'Sysmon.zip'
$config = Join-Path $InstallDir 'sysmonconfig-export.xml'

Invoke-WebRequest 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile $zip -UseBasicParsing
Expand-Archive $zip -DestinationPath $InstallDir -Force
Invoke-WebRequest 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml' `
    -OutFile $config -UseBasicParsing

# The baseline leaves the ProcessAccess include list empty, so Sysmon logs no process access at all.
$xml = New-Object System.Xml.XmlDocument
$xml.PreserveWhitespace = $true
$xml.Load($config)
$node = $xml.SelectSingleNode("//EventFiltering//ProcessAccess[@onmatch='include']")
if (-not $node) { throw 'No ProcessAccess include block found in the baseline configuration.' }
if (-not $node.SelectSingleNode("TargetImage[contains(., 'lsass.exe')]")) {
    $rule = $xml.CreateElement('TargetImage')
    $rule.SetAttribute('condition', 'end with')
    $rule.InnerText = 'lsass.exe'
    [void]$node.AppendChild($rule)
    $xml.Save($config)
}

# Sysmon prints its banner to stderr, so run it through cmd to keep PowerShell from treating that as an error.
$exe = Join-Path $InstallDir 'Sysmon64.exe'
if (Get-Service Sysmon64 -ErrorAction SilentlyContinue) {
    cmd /c "`"$exe`" -c `"$config`" 2>&1" | Select-String 'updated|error|invalid'
} else {
    cmd /c "`"$exe`" -accepteula -i `"$config`" 2>&1" | Select-String 'installed|started|error|invalid'
}
Get-Service Sysmon64 | ForEach-Object { "{0}: {1}" -f $_.Name, $_.Status }
