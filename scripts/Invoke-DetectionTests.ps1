# Generates harmless activity that each of these Sentinel rules should detect, then cleans up.
# Run on a Windows lab VM after Enable-DCAuditing.ps1 (works on any host, not just the DC):
#   az vm run-command invoke -g SOC_Lab -n SOC-WIN10-VM --command-id RunPowerShellScript --scripts @scripts/Invoke-DetectionTests.ps1
#
#   Rule                                 Event
#   New Windows Service Installed        7045 (System) / 4697 (Security)
#   Scheduled Task Persistence           4698
#   User Added to Administrators Group   4732
#   Encoded PowerShell Execution         4688 with -EncodedCommand
$ErrorActionPreference = 'Continue'
$tag = 'SOCLab-Test'

"[1] Service install"
sc.exe create "$tag-Svc" binPath= "C:\Windows\System32\cmd.exe /c exit" start= demand | Out-Null
sc.exe delete "$tag-Svc" | Out-Null

"[2] Scheduled task that runs PowerShell"
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -Command "exit"'
Register-ScheduledTask -TaskName "$tag-Task" -Action $action -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddYears(1)) -Force | Out-Null
Unregister-ScheduledTask -TaskName "$tag-Task" -Confirm:$false

"[3] Local user added to Administrators"
$pw = ConvertTo-SecureString ([guid]::NewGuid().ToString() + 'Aa1!') -AsPlainText -Force
New-LocalUser -Name "$tag-User" -Password $pw -Description 'Temporary detection test account' | Out-Null
Add-LocalGroupMember -Group Administrators -Member "$tag-User"
Remove-LocalGroupMember -Group Administrators -Member "$tag-User"
Remove-LocalUser -Name "$tag-User"

"[4] Encoded PowerShell command"
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Output '$tag'"))
powershell.exe -NoProfile -EncodedCommand $enc | Out-Null

"Done at $((Get-Date).ToUniversalTime().ToString('HH:mm:ss')) UTC. Cleanup: service, task and user removed."
