# Deallocates every VM in the lab so compute stops billing (disks still bill).
param([string]$ResourceGroup = 'SOC_Lab')

$ids = az vm list -g $ResourceGroup --query "[].id" -o tsv
az vm deallocate --ids $ids
az vm list -g $ResourceGroup -d --query "[].{name:name, power:powerState}" -o table
