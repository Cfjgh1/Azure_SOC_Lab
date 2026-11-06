#!/bin/bash
# Tests for the rules that need traffic from the attacker VNet. Run on ATK-Kali-VM:
#   az vm run-command invoke -g SOC_Lab -n ATK-Kali-VM --command-id RunShellScript --scripts @scripts/Invoke-KaliTests.sh
#
#   Potential Password Spraying   One failed logon each for 12 usernames that don't exist
#   Inbound Port Scan             TCP connect scan of the top 1000 ports on the DC
#
# Both rules are on the playbook's containment list, so expect this VM's IP to be blocked within about 10 minutes
# (spraying can take up to 30). Remove the block afterwards with scripts/Clear-AutoBlocks.ps1.
target=10.0.0.4

echo "Spray started $(date -u +%H:%M:%S) UTC"
for i in $(seq -w 1 12); do
  smbclient -L "//$target" -U "SOC\\spraytest$i%WrongPassword1" >/dev/null 2>&1
done
echo "Spray finished $(date -u +%H:%M:%S) UTC"

echo "Scan started $(date -u +%H:%M:%S) UTC"
nmap -sT -Pn -T4 --top-ports 1000 "$target" | tail -2
echo "Scan finished $(date -u +%H:%M:%S) UTC"
