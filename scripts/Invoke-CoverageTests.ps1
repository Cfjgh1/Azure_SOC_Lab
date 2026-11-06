# Harmless activity for the rules Invoke-DetectionTests.ps1 doesn't cover. Each test cleans up after itself.
#   az vm run-command invoke -g SOC_Lab -n SOC-WIN10-VM --command-id RunPowerShellScript --scripts @scripts/Invoke-CoverageTests.ps1 --parameters Test=OutboundScan
#
#   Test          Run on    Rule                              What it does
#   Lsass         Windows   LSASS Credential Access           Opens a handle to lsass.exe and closes it. Reads no memory.
#   Firewall      Windows   Defender Firewall Manipulation    Turns the Private profile off for 5 seconds (unused on domain-joined VMs)
#   Kerberoast    DC        Kerberoasting                     Requests RC4 tickets for a temporary service account, then deletes it
#   OutboundScan  Win10     Outbound Network Scan             Connects from PowerShell to 150 ports on the DC
param(
    [ValidateSet('Lsass', 'Firewall', 'Kerberoast', 'OutboundScan')]
    [string[]]$Test = @('Lsass', 'Firewall'),
    [string]$ScanTarget = '10.0.0.4'
)

function Now { (Get-Date).ToUniversalTime().ToString('HH:mm:ss') + ' UTC' }

if ($Test -contains 'Lsass') {
    Add-Type -Namespace SocLab -Name Native -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true)] public static extern System.IntPtr OpenProcess(uint access, bool inherit, int pid);
[DllImport("kernel32.dll")] public static extern bool CloseHandle(System.IntPtr handle);
'@
    $id = (Get-Process lsass).Id
    # 0x1010 = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ. The handle is closed without being used.
    $handle = [SocLab.Native]::OpenProcess(0x1010, $false, $id)
    if ($handle -eq [IntPtr]::Zero) { "[Lsass] OpenProcess failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())" }
    else { [void][SocLab.Native]::CloseHandle($handle); "[Lsass] Opened and closed a handle at $(Now)" }
}

if ($Test -contains 'Firewall') {
    try {
        Set-NetFirewallProfile -Profile Private -Enabled False
        "[Firewall] Private profile off at $(Now)"
        Start-Sleep -Seconds 5
    } finally {
        Set-NetFirewallProfile -Profile Private -Enabled True
        "[Firewall] Private profile back on at $(Now): enabled=$((Get-NetFirewallProfile -Profile Private).Enabled)"
    }
}

if ($Test -contains 'Kerberoast') {
    $name = 'svc-soclab-test'
    $spn = 'soclab/test.soc.lab.com'
    $password = ConvertTo-SecureString (([guid]::NewGuid().ToString() + [guid]::NewGuid().ToString()) + 'Aa1!') -AsPlainText -Force
    try {
        # 4 = RC4 only, so the KDC issues the ticket type the rule looks for.
        New-ADUser -Name $name -AccountPassword $password -Enabled $true -ServicePrincipalNames $spn `
            -OtherAttributes @{ 'msDS-SupportedEncryptionTypes' = 4 } -Description 'Temporary detection test account'
        Start-Sleep -Seconds 5
        foreach ($i in 1..3) {
            klist purge | Out-Null
            klist get $spn | Select-String 'KerbTicket Encryption Type|Error|failed' | Select-Object -First 2 | ForEach-Object { "[Kerberoast] request ${i}: $($_.ToString().Trim())" }
        }
        "[Kerberoast] Requested tickets at $(Now)"
    } finally {
        klist purge | Out-Null
        Remove-ADUser -Identity $name -Confirm:$false -ErrorAction SilentlyContinue
        "[Kerberoast] Test account removed: $(-not (Get-ADUser -Filter "SamAccountName -eq '$name'"))"
    }
}

if ($Test -contains 'OutboundScan') {
    $open = 0
    foreach ($port in 1000..1149) {
        $client = New-Object Net.Sockets.TcpClient
        $wait = $client.ConnectAsync($ScanTarget, $port)
        if ($wait.Wait(150) -and $client.Connected) { $open++ }
        $client.Dispose()
    }
    "[OutboundScan] 150 ports tried on $ScanTarget, $open open, finished at $(Now)"
}
