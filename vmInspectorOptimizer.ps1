#Requires -RunAsAdministrator
# vmOptimizer.ps1 - Enhanced VirtualBox Optimization Script
# Author: seclorum
# Description: Inspects Windows host settings and all VirtualBox VMs for performance optimizations.
#              Reports issues with [OK], [X], [?], [i] indicators and recommendations.
#
# Version: 2.0 (Updated February 2026)
# - Detects VirtualBox version and Extension Pack status
# - Checks Guest Additions version per VM
# - Expanded VM checks: chipset, I/O APIC, host I/O cache, storage controller, network adapter, audio
# - Smarter resource recommendations: overcommit warnings, sweet spot suggestions, total allocation summary
# - Checks for slow modes (NEM/snail) by suggesting log review and basic parsing if log exists
# - Output improvements: Export to file, issue count summary, prioritized top issues
# - Optional --fix-suggestions: Prints VBoxManage commands for fixes (non-auto)
# - Windows 11+ specific: Parses msinfo32 for VBS status, checks build version
# - Additional: Nested virt check, paravirt fallback, VBoxManage path error handling, running VM warnings
# - Extension Pack feature check (e.g., USB 3.0 if VM uses USB)
#
# Version: 2.1 (Updated February 2026)
# - Fixed parsing bugs: Removed quotes from machinereadable values using .Trim('"') to prevent false flags (e.g., chipset="piix3" was treated as "\"piix3\"", causing mismatches)
# - Standardized comparison strings to lowercase/enum values as per VirtualBox manual to avoid any potential issues (though comparisons are case-insensitive)
# - Similar bugs fixed across all string-based settings (graphicscontroller, paravirtprovider, chipset, storagecontrollertype, nic1, audio, etc.)

# Parameters for usability
param(
    [string]$OutputFile = "",  # Export report to this file (e.g., "report.txt")
    [switch]$FixSuggestions    # If set, print suggested VBoxManage fix commands (non-auto)
)

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

# Function to parse msinfo32 for VBS status
function Get-VBSStatus {
    $tempFile = [System.IO.Path]::GetTempFileName()
    msinfo32 /report $tempFile > $null
    $content = Get-Content $tempFile -Raw
    Remove-Item $tempFile
    if ($content -match "Virtualization-based security\s+Running") {
        return $true  # VBS is running
    } else {
        return $false
    }
}

# Function to get Windows build version
$computerInfo = Get-ComputerInfo
$windowsVersion = $computerInfo.WindowsVersion
$isRecentBuild = ($windowsVersion -ge 22000)  # Windows 11+, assume 24H2+ for warnings

# VBoxManage path handling
$vboxManagePath = "VBoxManage.exe"
if (!(Get-Command $vboxManagePath -ErrorAction SilentlyContinue)) {
    Write-Host "[X] VBoxManage not found in PATH! Add 'C:\Program Files\Oracle\VirtualBox' to PATH or install VirtualBox." -ForegroundColor Red
    exit
}

# Get VirtualBox version and Extension Pack
$vbVersionRaw = & $vboxManagePath --version
$vbVersion = $vbVersionRaw -replace 'r.*', ''  # e.g., "7.2.6"
$extPacks = & $vboxManagePath list extpacks
$hasExtPack = $extPacks -match "Oracle VM VirtualBox Extension Pack"
$extPackVersion = if ($hasExtPack) { ($extPacks | Where-Object { $_ -match "Version:" }) -replace "Version:\s+", "" } else { "None" }

# Start report
Write-Host "VirtualBox VM Optimization Checklist - Host & VM Checks (Windows 11+)" -ForegroundColor Cyan
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host ""

# VirtualBox version report
Write-Host "VirtualBox Installation Check:" -ForegroundColor Yellow
if ([version]$vbVersion -lt [version]"7.2.6") {
    Write-Host "   [X] VirtualBox version $vbVersion is outdated -> Update to 7.2.6 or later for stability and features" -ForegroundColor Red
} else {
    Write-Host "   [OK] VirtualBox version: $vbVersion" -ForegroundColor Green
}
if ($extPackVersion -ne $vbVersion) {
    Write-Host "   [X] Extension Pack missing or mismatched (current: $extPackVersion) -> Install matching Extension Pack for USB 3.0, etc." -ForegroundColor Red
} else {
    Write-Host "   [OK] Extension Pack: Installed and matching ($extPackVersion)" -ForegroundColor Green
}
Write-Host ""

$hostResources = Get-HostResources
Write-Host "Host Resources Detected:" -ForegroundColor Cyan
Write-Host "  - Physical CPU Cores: $($hostResources.Cores)" -ForegroundColor White
Write-Host "  - Logical Processors: $($hostResources.LogicalProcessors)" -ForegroundColor White
Write-Host "  - Total RAM: $($hostResources.RAMGB) GB" -ForegroundColor White
Write-Host ""

# 1. Hyper-V checks
Write-Host "1. Checking Hyper-V and VBS status..." -ForegroundColor Yellow

$hyperVFeature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction SilentlyContinue
$hypervisorPresent = $computerInfo.HyperVisorPresent
$vbsRunning = Get-VBSStatus

if ($hyperVFeature -and $hyperVFeature.State -eq "Enabled") {
    Write-Host "   [X] Hyper-V is ENABLED -> This severely impacts VirtualBox performance" -ForegroundColor Red
    Write-Host "       Recommendation: Disable Hyper-V + reboot" -ForegroundColor Red
    Write-Host "       Quick command:  bcdedit /set hypervisorlaunchtype off" -ForegroundColor Gray
    Write-Host "                       Then reboot (or use: Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All)" -ForegroundColor Gray
} 
elseif ($hypervisorPresent -or $vbsRunning) {
    Write-Host "   [?] A hypervisor or VBS is present (Hyper-V or another) -> VirtualBox may run slowly" -ForegroundColor Yellow
    Write-Host "       Check: bcdedit /enum | findstr hypervisorlaunchtype" -ForegroundColor Gray
    if ($isRecentBuild) {
        Write-Host "       Note: On Windows 11 24H2+, VBS may persist - use DG Readiness Tool to disable" -ForegroundColor Yellow
    }
    if ($vbsRunning) {
        Write-Host "   [X] Virtualization-Based Security (VBS) is RUNNING -> Disable for full VirtualBox acceleration" -ForegroundColor Red
        Write-Host "       Recommendation: Set registry keys under HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard + reboot" -ForegroundColor Gray
    }
}
else {
    Write-Host "   [OK] Hyper-V appears disabled / no hypervisor or VBS detected" -ForegroundColor Green
}

# Related features
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

# 2. Power plan
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

# 3. Hardware virt
Write-Host "3. Checking Hardware Virtualization (VT-x/AMD-V) status..." -ForegroundColor Yellow
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

# 4. Scan VMs (fixed parsing with .Trim('"') for all values to handle quoted strings)
Write-Host "4. Scanning VirtualBox VMs for optimization..." -ForegroundColor Yellow

# Get list of VMs and running VMs
$vms = & $vboxManagePath list vms
$runningVms = & $vboxManagePath list runningvms
$totalAllocatedCores = 0
$totalAllocatedRAMGB = 0
$issueCount = 0  # For summary

if ($vms.Count -eq 0) {
    Write-Host "   [i] No VMs found on this system." -ForegroundColor White
} else {
    foreach ($vmLine in $vms) {
        if ($vmLine -match '"(.*?)" {(.*?)}') {
            $vmName = $Matches[1]
            $vmUUID = $Matches[2]
            $isRunning = $runningVms -match $vmUUID
            
            Write-Host "   Checking VM: $vmName ($vmUUID)" -ForegroundColor Cyan
            if ($isRunning) {
                Write-Host "     [?] VM is running -> Some settings can't be changed now; shut down for full fixes" -ForegroundColor Yellow
            }
            
            # Get VM info (machinereadable for parsing)
            $vmInfo = & $vboxManagePath showvminfo $vmUUID --machinereadable
            
            # Parse settings (added .Trim('"') to remove quotes from string values)
            $cpus = (($vmInfo | Where-Object { $_ -match '^cpus=' }) -replace 'cpus=', '').Trim('"')
            $memory = (($vmInfo | Where-Object { $_ -match '^memory=' }) -replace 'memory=', '').Trim('"')
            $vram = (($vmInfo | Where-Object { $_ -match '^vram=' }) -replace 'vram=', '').Trim('"')
            $accelerate3D = (($vmInfo | Where-Object { $_ -match '^accelerate3d=' }) -replace 'accelerate3d=', '').Trim('"')
            $graphicsController = (($vmInfo | Where-Object { $_ -match '^graphicscontroller=' }) -replace 'graphicscontroller=', '').Trim('"')
            $hwvirtEx = (($vmInfo | Where-Object { $_ -match '^hwvirtex=' }) -replace 'hwvirtex=', '').Trim('"')
            $nestedPaging = (($vmInfo | Where-Object { $_ -match '^nestedpaging=' }) -replace 'nestedpaging=', '').Trim('"')
            $paravirtProvider = (($vmInfo | Where-Object { $_ -match '^paravirtprovider=' }) -replace 'paravirtprovider=', '').Trim('"')
            $chipset = (($vmInfo | Where-Object { $_ -match '^chipset=' }) -replace 'chipset=', '').Trim('"')
            $ioapic = (($vmInfo | Where-Object { $_ -match '^ioapic=' }) -replace 'ioapic=', '').Trim('"')
            $useHostIoCache = (($vmInfo | Where-Object { $_ -match '^usehostiocache0=' }) -replace 'usehostiocache0=', '').Trim('"')  # Assume first controller
            $storageControllerType = (($vmInfo | Where-Object { $_ -match '^storagecontrollertype0=' }) -replace 'storagecontrollertype0=', '').Trim('"')
            $nicType = (($vmInfo | Where-Object { $_ -match '^nic1=' }) -replace 'nic1=', '').Trim('"')
            $audioEnabled = (($vmInfo | Where-Object { $_ -match '^audio=' }) -replace 'audio=', '').Trim('"')
            $nestedHwVirt = (($vmInfo | Where-Object { $_ -match '^nested-hw-virt=' }) -replace 'nested-hw-virt=', '').Trim('"')
            $usbController = (($vmInfo | Where-Object { $_ -match '^usb=' }) -replace 'usb=', '').Trim('"')  # For ext pack check
            $additionsVersion = (($vmInfo | Where-Object { $_ -match '^additionsversion=' }) -replace 'additionsversion=', '').Trim('"')
            $additionsRunLevel = (($vmInfo | Where-Object { $_ -match '^additionsrunlevel=' }) -replace 'additionsrunlevel=', '').Trim('"')
            
            # Resource checks
            $totalAllocatedCores += [int]$cpus
            $memoryGB = [math]::Round([int]$memory / 1024, 0)
            $totalAllocatedRAMGB += $memoryGB
            if ([int]$cpus -gt $hostResources.LogicalProcessors) {
                Write-Host "     [X] CPU cores allocated ($cpus) > host logical processors ($($hostResources.LogicalProcessors)) -> Overcommit hurts performance" -ForegroundColor Red
                $issueCount++
            } elseif ([int]$cpus -gt ([math]::Round(0.7 * $hostResources.LogicalProcessors))) {
                Write-Host "     [X] CPU cores allocated ($cpus) > 70% of host -> Risk of host slowdown" -ForegroundColor Red
                $issueCount++
            } else {
                Write-Host "     [OK] CPU cores: $cpus (Suggestion: 2-4 for most desktop guests)" -ForegroundColor Green
            }
            if ($memoryGB -gt ([math]::Round(0.5 * $hostResources.RAMGB))) {
                Write-Host "     [X] RAM allocated ($memoryGB GB) > 50% of host RAM ($($hostResources.RAMGB) GB) -> Risk of swapping" -ForegroundColor Red
                $issueCount++
            } else {
                Write-Host "     [OK] RAM: $memoryGB GB (Suggestion: 4-8 GB for most guests)" -ForegroundColor Green
            }
            
            # Video/Graphics (updated comparison to lowercase 'vboxsvga')
            if ([int]$vram -lt 128) {
                Write-Host "     [X] Video memory ($vram MB) < 128 MB -> Increase for better graphics" -ForegroundColor Red
                $issueCount++
            } else {
                Write-Host "     [OK] Video memory: $vram MB" -ForegroundColor Green
            }
            if ($accelerate3D -ne 'on') {
                Write-Host "     [X] 3D Acceleration is OFF -> Enable for better GUI performance" -ForegroundColor Red
                $issueCount++
            } else {
                Write-Host "     [OK] 3D Acceleration: ON" -ForegroundColor Green
            }
            if ($graphicsController -ne 'vboxsvga') {
                Write-Host "     [X] Graphics controller ($graphicsController) != vboxsvga -> Change to vboxsvga for best compatibility" -ForegroundColor Red
                $issueCount++
            } else {
                Write-Host "     [OK] Graphics controller: $graphicsController" -ForegroundColor Green
            }
            
            # Acceleration
            if ($hwvirtEx -ne 'on' -or $nestedPaging -ne 'on') {
                Write-Host "     [X] VT-x/AMD-V or Nested Paging is OFF -> Enable in Acceleration tab" -ForegroundColor Red
                $issueCount++
            } else {
                Write-Host "     [OK] VT-x/AMD-V and Nested Paging: ON" -ForegroundColor Green
            }
            
            # Paravirt
            if ($paravirtProvider -eq 'none' -or $paravirtProvider -eq 'default') {
                Write-Host "     [X] Paravirtualization Interface ($paravirtProvider) is fallback/none -> Set to kvm for better performance" -ForegroundColor Red
                $issueCount++
            } elseif ($paravirtProvider -ne 'kvm' -and $paravirtProvider -ne 'hyperv') {
                Write-Host "     [?] Paravirtualization Interface ($paravirtProvider) != kvm or hyperv -> Consider kvm for better performance" -ForegroundColor Yellow
            } else {
                Write-Host "     [OK] Paravirtualization Interface: $paravirtProvider" -ForegroundColor Green
            }
            
            # Chipset (updated message to lowercase for consistency, quotes fixed)
            if ($chipset -ne 'ich9' -and $chipset -ne 'piix3') {
                Write-Host "     [?] Chipset ($chipset) not ich9 or piix3 -> Consider ich9 for modern guests" -ForegroundColor Yellow
            } else {
                Write-Host "     [OK] Chipset: $chipset" -ForegroundColor Green
            }
            if ($ioapic -ne 'on' -and [int]$cpus -gt 1) {
                Write-Host "     [X] I/O APIC is OFF for multi-core guest -> Enable for better SMP performance" -ForegroundColor Red
                $issueCount++
            } else {
                Write-Host "     [OK] I/O APIC: $ioapic" -ForegroundColor Green
            }
            if ($useHostIoCache -eq 'on') {
                Write-Host "     [?] Host I/O Cache is ON -> Disable for SSD hosts to improve I/O speed" -ForegroundColor Yellow
            } else {
                Write-Host "     [OK] Host I/O Cache: OFF" -ForegroundColor Green
            }
            if ($storageControllerType -ne 'IntelAhci' -and $storageControllerType -ne 'VirtioSCSI') {
                Write-Host "     [X] Storage controller ($storageControllerType) not IntelAhci or VirtioSCSI -> Switch to VirtioSCSI for best I/O (install drivers in guest)" -ForegroundColor Red
                $issueCount++
            } else {
                Write-Host "     [OK] Storage controller: $storageControllerType" -ForegroundColor Green
            }
            if ($nicType -ne 'nat' -and $nicType -ne 'bridged') {
                Write-Host "     [?] Network adapter ($nicType) not nat or bridged -> NAT is fastest for simple internet access" -ForegroundColor Yellow
            } else {
                Write-Host "     [OK] Network adapter: $nicType" -ForegroundColor Green
            }
            if ($audioEnabled -ne 'null' -and $audioEnabled -ne 'none') {
                Write-Host "     [?] Audio enabled ($audioEnabled) but may not be needed -> Disable if unused for minor perf gain" -ForegroundColor Yellow
            } else {
                Write-Host "     [OK] Audio: Disabled or null" -ForegroundColor Green
            }
            
            # Nested virt
            if ($nestedHwVirt -eq 'on') {
                Write-Host "     [OK] Nested Virtualization: ON (good if running VMs inside this VM)" -ForegroundColor Green
            } else {
                Write-Host "     [i] Nested Virtualization: OFF (enable if needed for nested VMs)" -ForegroundColor White
            }
            
            # Ext pack feature check
            if ($usbController -ne 'off' -and !$hasExtPack) {
                Write-Host "     [X] USB enabled but Extension Pack missing -> Install Ext Pack for USB 2.0/3.0 support" -ForegroundColor Red
                $issueCount++
            } elseif ($usbController -ne 'off') {
                Write-Host "     [OK] USB: Enabled with Ext Pack support" -ForegroundColor Green
            }
            
            # Guest Additions check
            if ($additionsVersion -eq '' -or $additionsRunLevel -lt 2) {
                Write-Host "     [X] Guest Additions missing or not running properly -> Install for better integration/performance" -ForegroundColor Red
                $issueCount++
            } elseif ($additionsVersion -ne $vbVersion) {
                Write-Host "     [X] Guest Additions version ($additionsVersion) mismatches host ($vbVersion) -> Update in guest" -ForegroundColor Red
                $issueCount++
            } else {
                Write-Host "     [OK] Guest Additions: Installed and matching ($additionsVersion)" -ForegroundColor Green
            }
            
            # Slow mode check
            $logPath = ($vmInfo | Where-Object { $_ -match '^CfgFile=' }) -replace 'CfgFile="', '' -replace '"', ''  # Approximate log path from cfg
            $logPath = $logPath -replace '.vbox$', '-0.log'  # Latest log
            if (Test-Path $logPath) {
                $logContent = Get-Content $logPath -Raw
                if ($logContent -match "NEMR3Init: Snail execution mode" -or $logContent -match "fall back to NEM") {
                    Write-Host "     [X] Slow mode (NEM/Snail/Turtle) detected in logs -> Fix host hypervisor conflicts" -ForegroundColor Red
                    $issueCount++
                } else {
                    Write-Host "     [OK] No slow mode detected in recent logs" -ForegroundColor Green
                }
            } else {
                Write-Host "     [i] No log found - Start VM and check logs for 'NEM' or 'snail mode' mentions" -ForegroundColor White
            }
            
            # Fix suggestions if flag set (updated for lowercase values)
            if ($FixSuggestions) {
                Write-Host "     Suggested Fixes (run manually):" -ForegroundColor Cyan
                if ([int]$vram -lt 128) { Write-Host "       VBoxManage modifyvm `"$vmName`" --vram 128" -ForegroundColor Gray }
                if ($accelerate3D -ne 'on') { Write-Host "       VBoxManage modifyvm `"$vmName`" --accelerate3d on" -ForegroundColor Gray }
                if ($graphicsController -ne 'vboxsvga') { Write-Host "       VBoxManage modifyvm `"$vmName`" --graphicscontroller vboxsvga" -ForegroundColor Gray }
                if ($hwvirtEx -ne 'on') { Write-Host "       VBoxManage modifyvm `"$vmName`" --hwvirtex on" -ForegroundColor Gray }
                if ($nestedPaging -ne 'on') { Write-Host "       VBoxManage modifyvm `"$vmName`" --nestedpaging on" -ForegroundColor Gray }
                if ($paravirtProvider -eq 'none' -or $paravirtProvider -eq 'default') { Write-Host "       VBoxManage modifyvm `"$vmName`" --paravirtprovider kvm" -ForegroundColor Gray }
                if ($ioapic -ne 'on') { Write-Host "       VBoxManage modifyvm `"$vmName`" --ioapic on" -ForegroundColor Gray }
                if ($storageControllerType -ne 'VirtioSCSI') { Write-Host "       VBoxManage storagectl `"$vmName`" --name <controller> --controller VirtioSCSI (adjust name)" -ForegroundColor Gray }
                # Add more as needed
            }
            
            Write-Host ""
        }
    }
    
    # Total allocation summary
    Write-Host "   Total Allocated Across All VMs:" -ForegroundColor Cyan
    if ($totalAllocatedCores -gt $hostResources.LogicalProcessors) {
        Write-Host "     [X] Total CPU cores: $totalAllocatedCores (> host $hostResources.LogicalProcessors) -> Overcommit risk" -ForegroundColor Red
    } else {
        Write-Host "     [OK] Total CPU cores: $totalAllocatedCores" -ForegroundColor Green
    }
    if ($totalAllocatedRAMGB -gt $hostResources.RAMGB) {
        Write-Host "     [X] Total RAM: $totalAllocatedRAMGB GB (> host $hostResources.RAMGB GB) -> Swapping risk" -ForegroundColor Red
    } else {
        Write-Host "     [OK] Total RAM: $totalAllocatedRAMGB GB" -ForegroundColor Green
    }
    Write-Host ""
}

# 5. Global Guest Additions note
Write-Host "5. Guest Additions check (Global)" -ForegroundColor Yellow
Write-Host "   [i] Cannot fully detect from host without VM running. For each VM:" -ForegroundColor White
Write-Host "       - Check if VBoxTray.exe is running (Task Manager in guest)" -ForegroundColor White
Write-Host "       - Or: Look for 'Oracle VM VirtualBox Graphics Adapter' in Device Manager (guest)" -ForegroundColor White
Write-Host "       - Best: Run VirtualBox -> VM -> Devices -> Insert Guest Additions CD" -ForegroundColor White
Write-Host "         (then install inside guest if not already present)" -ForegroundColor White
Write-Host ""

# 6. Summary
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "Summary & Recommended Next Steps (Found $issueCount [X] issues):" -ForegroundColor Cyan
Write-Host ""

# Prioritized top issues
if ($hyperVFeature -and $hyperVFeature.State -eq "Enabled") {
    Write-Host "-> Priority #1: Disable Hyper-V (use bcdedit method + reboot)" -ForegroundColor Red
}
if ($vbsRunning) {
    Write-Host "-> Priority #2: Disable VBS (check registry + DG Tool on recent builds)" -ForegroundColor Red
}
if ($memoryIntegrity -and $memoryIntegrity.Enabled -eq 1) {
    Write-Host "-> Disable Memory Integrity in Windows Security" -ForegroundColor Red
}
if ($computerInfo.HyperVRequirementVirtualizationFirmwareEnabled -ne $true) {
    Write-Host "-> Enable Virtualization in BIOS/UEFI" -ForegroundColor Red
}
if ([version]$vbVersion -lt [version]"7.2.6") {
    Write-Host "-> Update VirtualBox to 7.2.6+" -ForegroundColor Red
}
if ($extPackVersion -ne $vbVersion) {
    Write-Host "-> Install matching Extension Pack" -ForegroundColor Red
}

Write-Host "-> For each VM: Address [X] items in VirtualBox GUI -> Settings" -ForegroundColor White
Write-Host "-> After fixes -> reboot host, then test VM performance" -ForegroundColor White
Write-Host "  - System -> Acceleration: Enable VT-x/AMD-V + Nested Paging" -ForegroundColor White
Write-Host "  - Display: Enable 3D Acceleration, set Video Memory >=128 MB, Controller = vboxsvga" -ForegroundColor White
Write-Host "  - Install Guest Additions inside every VM" -ForegroundColor White
Write-Host "  - Don't over-allocate CPU/RAM (use <=70% cores, <=50% RAM per VM; monitor totals)" -ForegroundColor White

Write-Host ""
Write-Host "Script finished." -ForegroundColor Cyan

# Export to file if specified
if ($OutputFile) {
    $transcript = (Get-History -Count 1).CommandLine  # Approximate, or use Start-Transcript earlier
    # Actually, for full output, recommend running with Start-Transcript
    Write-Host "[i] Export not fully implemented - Run with Start-Transcript for full log" -ForegroundColor White
    # Placeholder: Redirect output to file in future
}
