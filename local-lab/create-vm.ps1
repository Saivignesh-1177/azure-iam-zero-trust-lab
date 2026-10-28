<#
.SYNOPSIS
  Build the on-prem workload VM (zt-app-01) in VirtualBox from the verified Ubuntu 24.04 cloud OVA.

.DESCRIPTION
  - imports the OVA (2 vCPU, 2 GB RAM)
  - NIC1 NAT (egress to Azure), NIC2 host-only 192.168.56.10 (lab network, SSH + app)
  - attaches a cloud-init seed ISO that hardens the OS at first boot (see cloud-init/user-data.yaml)
  - logs the serial console to a file so first boot can be debugged without a GUI
  - boots headless and waits until SSH answers

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File local-lab\create-vm.ps1
#>
param(
  [string]$VmName   = "zt-app-01",
  [string]$LabDir   = "$env:USERPROFILE\Downloads\virtualbox\zt-lab",
  [string]$Ova      = "$env:USERPROFILE\Downloads\virtualbox\zt-lab\images\ubuntu-24.04-server-cloudimg-amd64.ova",
  [string]$Python   = "python",
  [int]$MemoryMb    = 2048,
  [int]$Cpus        = 1,   # 1 vCPU: Linux SMP boot can hang when VirtualBox runs on the Hyper-V (NEM) backend
  [string]$LabIp    = "192.168.56.10"
)
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false
$vb   = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
$repo = Split-Path $PSScriptRoot -Parent
$keys = Join-Path $repo ".state\vbox"
New-Item -ItemType Directory -Force $keys, "$LabDir\vms" | Out-Null

if ((& $vb list vms) -match "`"$VmName`"") { throw "VM '$VmName' already exists. Delete it first: VBoxManage unregistervm $VmName --delete" }
if (-not (Test-Path $Ova)) { throw "OVA not found: $Ova" }

# 1. SSH key for the lab (private key stays in .state\, which is gitignored)
$key = Join-Path $keys "zt_lab_ed25519"
if (-not (Test-Path $key)) { ssh-keygen -t ed25519 -N '""' -C "zt-lab" -f $key -q }

# 2. cloud-init seed ISO
$seed = Join-Path $LabDir "vms\$VmName-seed.iso"
& $Python (Join-Path $PSScriptRoot "make-seed.py") "$key.pub" $seed $VmName
if ($LASTEXITCODE) { throw "seed ISO build failed" }

# 3. Import the OVA with our sizing
& $vb import $Ova --vsys 0 --vmname $VmName --cpus $Cpus --memory $MemoryMb --basefolder "$LabDir\vms"
if ($LASTEXITCODE) { throw "import failed" }

# 4. Networking + console log
$hostOnly = "VirtualBox Host-Only Ethernet Adapter"
& $vb modifyvm $VmName --nic1 nat --nic2 hostonly --hostonlyadapter2 $hostOnly `
  --cableconnected1 on --cableconnected2 on --audio-enabled off --usb off `
  --uart1 0x3F8 4 --uartmode1 file "$LabDir\vms\$VmName-console.log" --graphicscontroller vmsvga

# 5. Seed ISO on the IDE controller (the Ubuntu OVA already ships one, and VirtualBox allows only one)
$ide = (& $vb showvminfo $VmName --machinereadable | Select-String '^storagecontrollername\d+="(.+)"' |
        ForEach-Object { $_.Matches[0].Groups[1].Value }) | Where-Object { $_ -match "IDE" } | Select-Object -First 1
if (-not $ide) { $ide = "IDE"; & $vb storagectl $VmName --name $ide --add ide }
& $vb storageattach $VmName --storagectl $ide --port 1 --device 0 --type dvddrive --medium $seed
if ($LASTEXITCODE) { throw "could not attach seed ISO" }

# 6. Boot headless and wait for SSH on the lab network
& $vb startvm $VmName --type headless
Write-Host "Booting $VmName - first boot installs updates, allow 3-8 minutes..."
$deadline = (Get-Date).AddMinutes(15)
do {
  Start-Sleep -Seconds 15
  $up = Test-NetConnection $LabIp -Port 22 -InformationLevel Quiet -WarningAction SilentlyContinue
  Write-Host -NoNewline "."
} until ($up -or (Get-Date) -gt $deadline)
if (-not $up) { throw "SSH not reachable on $LabIp. Check $LabDir\vms\$VmName-console.log" }

Write-Host "`nSSH is up. Waiting for cloud-init to finish..."
ssh -i $key -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$keys\known_hosts" "ztadmin@$LabIp" "cloud-init status --wait; cloud-init status --long | head -5"
Write-Host "`nReady:  ssh -i $key -o UserKnownHostsFile=$keys\known_hosts ztadmin@$LabIp"
