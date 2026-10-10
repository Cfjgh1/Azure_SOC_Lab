# Turns on the advanced audit subcategories the Sentinel rules rely on.
# Run on the domain controller (SOC-WIN-VM1), e.g.:
#   az vm run-command invoke -g SOC_Lab -n SOC-WIN-VM1 --command-id RunPowerShellScript --scripts @scripts/Enable-DCAuditing.ps1
# For a durable setting, put the same subcategories in the Default Domain Controllers Policy GPO.

$subcategories = @(
    'Kerberos Authentication Service',       # 4768, 4771
    'Kerberos Service Ticket Operations',    # 4769
    'Credential Validation',                 # 4776
    'Logon',                                 # 4624, 4625
    'Security Group Management',             # 4728, 4732, 4756
    'User Account Management',               # 4720, 4722, 4738
    'Directory Service Access',              # 4662
    'Directory Service Changes',             # 5136, 5137
    'Security System Extension',             # 4697
    'Other Object Access Events',            # 4698 (scheduled tasks)
    'Process Creation'                       # 4688
)

foreach ($s in $subcategories) {
    auditpol /set /subcategory:"$s" /success:enable /failure:enable | Out-Null
}

# Include the command line in 4688 events.
New-Item -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
    -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord

auditpol /get /category:* | Select-String ($subcategories -join '|')
