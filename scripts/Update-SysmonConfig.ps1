# Makes Sysmon log process access to lsass.exe (event 10), which the LSASS Credential Access rule needs.
# The base config has an empty ProcessAccess include list, so Sysmon logs no process access at all.
# Safe to run more than once. Run on both Windows VMs:
#   az vm run-command invoke -g SOC_Lab -n SOC-WIN-VM1 --command-id RunPowerShellScript --scripts @scripts/Update-SysmonConfig.ps1
param(
    [string]$ConfigPath = 'C:\Users\socadmin\Downloads\Sysmon\sysmonconfig-export.xml'
)
$ErrorActionPreference = 'Stop'

$sysmon = (Get-ChildItem C:\Windows\Sysmon*.exe | Select-Object -First 1).FullName
$xml = New-Object System.Xml.XmlDocument
$xml.PreserveWhitespace = $true
$xml.Load($ConfigPath)

$node = $xml.SelectSingleNode("//EventFiltering//ProcessAccess[@onmatch='include']")
if (-not $node) { throw "No ProcessAccess include block found in $ConfigPath" }

if ($node.SelectSingleNode("TargetImage[contains(., 'lsass.exe')]")) {
    "lsass.exe is already in the config"
} else {
    Copy-Item $ConfigPath "$ConfigPath.bak" -Force
    $rule = $xml.CreateElement('TargetImage')
    $rule.SetAttribute('condition', 'end with')
    $rule.InnerText = 'lsass.exe'
    [void]$node.AppendChild($rule)
    $xml.Save($ConfigPath)
    "Added lsass.exe to ProcessAccess (backup: $ConfigPath.bak)"
}

# Sysmon prints its banner to stderr, so run it through cmd to keep PowerShell from treating that as an error.
cmd /c "`"$sysmon`" -c `"$ConfigPath`" 2>&1" | Select-String 'updated|error|invalid'
cmd /c "`"$sysmon`" -c 2>&1" | Select-String -Context 0,1 'ProcessAccess'
