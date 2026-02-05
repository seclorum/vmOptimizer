# This Powershell script will inspect the local Windows VM configuration, as well 
# as any Virtualbox VM instances it finds locally, and produce a report with
# suggested optimization changes to produce more productive VM's on the local
# system.

#Requires -RunAsAdministrator

Write-Host "VirtualBox VM Optimization Checklist - Host & VM Checks (Windows 11)" -ForegroundColor Cyan
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host ""

# Function to get host resources
function Get-HostResources {
    $cpuCores = (Get-WmiObject Win32_Processor | Measure-Object -Property NumberOfCores -Sum).Sum
    $logicalProcessors = (Get-WmiObject Win32_Processor | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
    $totalRAMGB = [math]::Round(((Get-WmiObject Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1GB), 0)
    return @{
        Cores = $cpuCores
        LogicalProcessors = $logicalProcessors
        RAMGB = $totalRAMGB
    }
}

$hostResources = Get-HostResources
Write-Host "Host Resources Detected:" -ForegroundColor Cyan
Write-Host "  - Physical CPU Cores: $($hostResources.Cores)" -ForegroundColor White
Write-Host "  - Logical Processors: $($hostResources.LogicalProcessors)" -ForegroundColor White
Write-Host "  - Total RAM: $($hostResources.RAMGB) GB" -ForegroundColor White
Write-Host ""

# 1. Check if Hyper-V (or conflicting features) are enabled
Write-Host "1. Checking Hyper-V status..." -ForegroundColor Yellow

$hyperVFeature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction SilentlyContinue
$hypervisorPresent = (Get-ComputerInfo).HyperVisorPresent

if ($hyperVFeature -and $hyperVFeature.State -eq "Enabled") {
    Write-Host "   [X] Hyper-V is ENABLED -> This severely impacts VirtualBox performance" -ForegroundColor Red
    Write-Host "       Recommendation: Disable Hyper-V + reboot" -ForegroundColor Red
    Write-Host "       Quick command:  bcdedit /set hypervisorlaunchtype off" -ForegroundColor Gray
    Write-Host "                       Then reboot (or use: Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All)" -ForegroundColor Gray
} 
elseif ($hypervisorPresent) {
    Write-Host "   [?] A hypervisor is present (Hyper-V or another) -> VirtualBox may run slowly" -ForegroundColor Yellow
    Write-Host "       Check: bcdedit /enum | findstr hypervisorlaunchtype" -ForegroundColor Gray
}
else {
    Write-Host "   [OK] Hyper-V appears disabled / no hypervisor detected" -ForegroundColor Green
}

# Also check related features that can interfere
$hvPlatform = Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -ErrorAction SilentlyContinue
if ($hvPlatform -and $hvPlatform.State -eq "Enabled") {
    Write-Host "   [X] Virtual Machine Platform is ENABLED -> Can conflict" -ForegroundColor Red
}

$memoryIntegrity = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -ErrorAction SilentlyContinue
if ($memoryIntegrity -and $memoryIntegrity.Enabled -eq 1) {
    Write-Host "   [X] Memory Integrity (Core Isolation) is ENABLED -> Often conflicts with VirtualBox" -ForegroundColor Red
    Write-Host "       Recommendation: Disable in Windows Security -> Device security -> Core isolation" -ForegroundColor Gray
}

Write-Host ""

# 2. Check active power plan
Write-Host "2. Checking active Power Plan..." -ForegroundColor Yellow
$activeScheme = powercfg /getactivescheme
if ($activeScheme -match "High performance|Ultimate Performance") {
    Write-Host "   [OK] Active plan looks good: $activeScheme" -ForegroundColor Green
} else {
    Write-Host "   [X] Not on High/Ultimate Performance" -ForegroundColor Red
    Write-Host "       Current: $activeScheme" -ForegroundColor Red
    Write-Host "       Recommendation: Switch to 'High performance' in Settings -> System -> Power & battery" -ForegroundColor Gray
    Write-Host "       Or run: powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" -ForegroundColor Gray
    Write-Host "               (for Ultimate: powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61)" -ForegroundColor Gray
}
Write-Host ""

# 3. Check if hardware virtualization (VT-x/AMD-V) is enabled in firmware
Write-Host "3. Checking Hardware Virtualization (VT-x/AMD-V) status..." -ForegroundColor Yellow
$computerInfo = Get-ComputerInfo

if ($computerInfo.HyperVRequirementVirtualizationFirmwareEnabled -eq $true) {
    Write-Host "   [OK] Virtualization enabled in firmware (BIOS/UEFI)" -ForegroundColor Green
} else {
    Write-Host "   [X] Virtualization DISABLED in firmware" -ForegroundColor Red
    Write-Host "       You must enable VT-x / AMD-V / SVM in BIOS/UEFI setup" -ForegroundColor Red
    Write-Host "       (Restart PC -> enter BIOS -> look for Virtualization / CPU features)" -ForegroundColor Gray
}

if ($computerInfo.HyperVRequirementVMMonitorModeExtensions -eq $true) {
    Write-Host "   [OK] VM Monitor Mode Extensions (usually good)" -ForegroundColor Green
}
Write-Host ""

# 4. Scan VirtualBox VMs and check settings
Write-Host "4. Scanning VirtualBox VMs for optimization..." -ForegroundColor Yellow

# Assume VBoxManage is in PATH; if not, set $vboxManagePath = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
$vboxManagePath = "VBoxManage.exe"

# Get list of VMs
$vms = & $vboxManagePath list vms
if ($vms.Count -eq 0) {
    Write-Host "   [i] No VMs found on this system." -ForegroundColor White
} else {
    foreach ($vmLine in $vms) {
        if ($vmLine -match '"(.*?)" {(.*?)}') {
            $vmName = $Matches[1]
            $vmUUID = $Matches[2]
            
            Write-Host "   Checking VM: $vmName ($vmUUID)" -ForegroundColor Cyan
            
            # Get VM info
            $vmInfo = & $vboxManagePath showvminfo $vmUUID --machinereadable
            
            # Parse key settings
            $cpus = ($vmInfo | Where-Object { $_ -match '^cpus=' }) -replace 'cpus=', ''
            $memory = ($vmInfo | Where-Object { $_ -match '^memory=' }) -replace 'memory=', ''
            $vram = ($vmInfo | Where-Object { $_ -match '^vram=' }) -replace 'vram=', ''
            $accelerate3D = ($vmInfo | Where-Object { $_ -match '^accelerate3d=' }) -replace 'accelerate3d=', ''
            $graphicsController = ($vmInfo | Where-Object { $_ -match '^graphicscontroller=' }) -replace 'graphicscontroller=', ''
            $hwvirtEx = ($vmInfo | Where-Object { $_ -match '^hwvirtex=' }) -replace 'hwvirtex=', ''
            $nestedPaging = ($vmInfo | Where-Object { $_ -match '^nestedpaging=' }) -replace 'nestedpaging=', ''
            $paravirtProvider = ($vmInfo | Where-Object { $_ -match '^paravirtprovider=' }) -replace 'paravirtprovider=', ''
            $storageController = ($vmInfo | Where-Object { $_ -match '^nic1=' }) -replace 'nic1=', ''  # Basic check for network, but extend for storage
            
            # Check CPU
            if ([int]$cpus -gt ([math]::Round(0.7 * $hostResources.LogicalProcessors))) {
                Write-Host "     [X] CPU cores allocated ($cpus) > 70% of host logical processors ($($hostResources.LogicalProcessors)) -> Risk of host slowdown" -ForegroundColor Red
            } else {
                Write-Host "     [OK] CPU cores: $cpus" -ForegroundColor Green
            }
            
            # Check RAM
            $memoryGB = [math]::Round([int]$memory / 1024, 0)
            if ($memoryGB -gt ([math]::Round(0.5 * $hostResources.RAMGB))) {
                Write-Host "     [X] RAM allocated ($memoryGB GB) > 50% of host RAM ($($hostResources.RAMGB) GB) -> Risk of swapping" -ForegroundColor Red
            } else {
                Write-Host "     [OK] RAM: $memoryGB GB" -ForegroundColor Green
            }
            
            # Check Video Memory
            if ([int]$vram -lt 128) {
                Write-Host "     [X] Video memory ($vram MB) < 128 MB -> Increase for better graphics" -ForegroundColor Red
            } else {
                Write-Host "     [OK] Video memory: $vram MB" -ForegroundColor Green
            }
            
            # Check 3D Acceleration
            if ($accelerate3D -ne 'on') {
                Write-Host "     [X] 3D Acceleration is OFF -> Enable for better GUI performance" -ForegroundColor Red
            } else {
                Write-Host "     [OK] 3D Acceleration: ON" -ForegroundColor Green
            }
            
            # Check Graphics Controller
            if ($graphicsController -ne 'VBoxSVGA') {
                Write-Host "     [X] Graphics controller ($graphicsController) != VBoxSVGA -> Change to VBoxSVGA for best compatibility" -ForegroundColor Red
            } else {
                Write-Host "     [OK] Graphics controller: VBoxSVGA" -ForegroundColor Green
            }
            
            # Check Hardware Virtualization
            if ($hwvirtEx -ne 'on' -or $nestedPaging -ne 'on') {
                Write-Host "     [X] VT-x/AMD-V or Nested Paging is OFF -> Enable in Acceleration tab" -ForegroundColor Red
            } else {
                Write-Host "     [OK] VT-x/AMD-V and Nested Paging: ON" -ForegroundColor Green
            }
            
            # Check Paravirtualization
            if ($paravirtProvider -ne 'KVM' -and $paravirtProvider -ne 'HyperV') {
                Write-Host "     [?] Paravirtualization Interface ($paravirtProvider) != KVM or Hyper-V -> Consider KVM for better performance" -ForegroundColor Yellow
            } else {
                Write-Host "     [OK] Paravirtualization Interface: $paravirtProvider" -ForegroundColor Green
            }
            
            # Note on Guest Additions and Storage (can't fully parse storage here, but suggest)
            Write-Host "     [i] Guest Additions: Check inside VM (cannot detect from host)" -ForegroundColor White
            Write-Host "     [i] Storage: Review in VM Settings -> Use SATA/AHCI or VirtIO for best I/O" -ForegroundColor White
            Write-Host ""
        }
    }
}

# 5. Quick note about Guest Additions (global)
Write-Host "5. Guest Additions check (Global)" -ForegroundColor Yellow
Write-Host "   [i] Cannot reliably detect from host. For each VM:" -ForegroundColor White
Write-Host "       - Check if VBoxTray.exe is running (Task Manager in guest)" -ForegroundColor White
Write-Host "       - Or: Look for 'Oracle VM VirtualBox Graphics Adapter' in Device Manager (guest)" -ForegroundColor White
Write-Host "       - Best: Run VirtualBox -> VM -> Devices -> Insert Guest Additions CD" -ForegroundColor White
Write-Host "         (then install inside guest if not already present)" -ForegroundColor White
Write-Host ""

# 6. Summary / next steps
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "Summary & Recommended Next Steps:" -ForegroundColor Cyan
Write-Host ""

if ($hyperVFeature -and $hyperVFeature.State -eq "Enabled") {
    Write-Host "-> Priority #1: Disable Hyper-V (use bcdedit method + reboot)" -ForegroundColor Red
}
if ($memoryIntegrity -and $memoryIntegrity.Enabled -eq 1) {
    Write-Host "-> Disable Memory Integrity in Windows Security" -ForegroundColor Red
}
if ($computerInfo.HyperVRequirementVirtualizationFirmwareEnabled -ne $true) {
    Write-Host "-> Enable Virtualization in BIOS/UEFI" -ForegroundColor Red
}

Write-Host "-> For each VM: Address [X] items in VirtualBox GUI -> Settings" -ForegroundColor White
Write-Host "-> After fixes -> reboot host, then test VM performance" -ForegroundColor White
Write-Host "  - System -> Acceleration: Enable VT-x/AMD-V + Nested Paging" -ForegroundColor White
Write-Host "  - Display: Enable 3D Acceleration, set Video Memory >=128 MB, Controller = VBoxSVGA" -ForegroundColor White
Write-Host "  - Install Guest Additions inside every VM" -ForegroundColor White
Write-Host "  - Don't over-allocate CPU/RAM (use <=70% cores, <=50% RAM)" -ForegroundColor White

Write-Host ""
Write-Host "Script finished." -ForegroundColor Cyan
