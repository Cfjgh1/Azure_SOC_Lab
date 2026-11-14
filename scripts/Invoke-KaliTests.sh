#!/bin/bash
# Tests for the rules that need traffic from the attacker VNet. Run on ATK-Kali-VM:
#   az vm run-command invoke -g SOC_Lab -n ATK-Kali-VM --command-id RunShellScript --scripts @scripts/Invoke-KaliTests.sh
# Pass the tests to run as parameters (default: all three), for example: --parameters bruteforce
#
#   scan         Inbound Port Scan             TCP connect scan of the top 1000 ports on the DC
#   bruteforce   Multiple Failed Logins        6 failed logons for one username that does not exist
#   spray        Potential Password Spraying   One failed logon each for 12 usernames that do not exist
#
# All three rules are on the playbook containment list, so expect this VM to be blocked within about 10 minutes
# (spraying can take up to 30). The block expires after 24 hours; remove it sooner with scripts/Clear-AutoBlocks.ps1.
target=10.0.0.4
tests="${*:-scan bruteforce spray}"

for t in $tests; do
  echo "$t started $(date -u +%H:%M:%S) UTC"
  case "$t" in
    scan)
      nmap -sT -Pn -T4 --top-ports 1000 "$target" | tail -2 ;;
    bruteforce)
      for i in 1 2 3 4 5 6; do
        smbclient -L "//$target" -U 'SOC\soclab-test%WrongPassword1' >/dev/null 2>&1
      done ;;
    spray)
      for i in $(seq -w 1 12); do
        smbclient -L "//$target" -U "SOC\spraytest$i%WrongPassword1" >/dev/null 2>&1
      done ;;
    *) echo "unknown test: $t" ;;
  esac
  echo "$t finished $(date -u +%H:%M:%S) UTC"
done
