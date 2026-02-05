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
#
# Version: 2.2 (Updated February 2026)
# - Fixed array parsing error: Introduced Get-SettingValue helper to safely handle single values
#   and prevent [Object[]].Trim() failures when multiple lines match a key
# - Made several comparisons case-insensitive (.ToLower()) for robustness
# - Updated log path extraction to use helper function
#
# Version: 2.3 (February 2026)
# - Fixed numeric parsing with [int]::TryParse to prevent cast exceptions
# - Improved Get-SettingValue to reliably strip key= prefix and quotes
# - Fixed chipset logic using -notin
# - Cleaned displayed values (no key prefixes or trailing quotes)
# - Prevented invalid totals and comparison errors

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
        Cores              = $cpuCores
        LogicalProcessors  = $logicalProcessors
        RAMGB              = $totalRAMGB
    }
}

# Function to parse msinfo32 for VBS status
function Get-VBSStatus {
    # Check if Virtualization Based Security is active via registry
    $vbsKey = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -ErrorAction SilentlyContinue
    $vbsRunning = $vbsKey -and $vbsKey.EnableVirtualizationBasedSecurity -eq 1

    # Optional: also check Credential Guard (often tied to VBS)
    $cgKey = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -ErrorAction SilentlyContinue
    $cgActive = $cgKey -and $cgKey.LsaCfgFlags -gt 0

    return $vbsRunning -or $cgActive
}

# Safe setting value extractor
function Get-SettingValue($vmInfo, $pattern) {
    $match = $vmInfo | Where-Object { $_ -match $pattern } | Select-Object -First 1
    if ($match) {
        $value = $match -replace "^$pattern", ""
        return $value.Trim().Trim('"').Trim()
    }
    return ""
}

$computerInfo = Get-ComputerInfo
$windowsVersion = $computerInfo.WindowsVersion
$isRecentBuild = ($windowsVersion -ge 22000)

$vboxManagePath = "VBoxManage.exe"
if (!(Get-Command $vboxManagePath -ErrorAction SilentlyContinue)) {
    Write-Host "[X] VBoxManage not found in PATH! Add 'C:\Program Files\Oracle\VirtualBox' to PATH." -ForegroundColor Red
    exit
}

$vbVersionRaw = & $vboxManagePath --version
$vbVersion = $vbVersionRaw -replace 'r.*', ''
$extPacks = & $vboxManagePath list extpacks
$hasExtPack = $extPacks -match "Oracle VM VirtualBox Extension Pack"
$extPackVersion = if ($hasExtPack) { ($extPacks | Where-Object { $_ -match "Version:" } | Select-Object -First 1) -replace "Version:\s+", "" } else { "None" }

Write-Host "VirtualBox VM Optimization Checklist - Host & VM Checks (Windows 11+)" -ForegroundColor Cyan
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "VirtualBox Installation Check:" -ForegroundColor Yellow
if ([version]$vbVersion -lt [version]"7.2.6") {
    Write-Host "   [X] VirtualBox version $vbVersion is outdated -> Update to 7.2.6 or later" -ForegroundColor Red
} else {
    Write-Host "   [OK] VirtualBox version: $vbVersion" -ForegroundColor Green
}
if ($extPackVersion -ne $vbVersion) {
    Write-Host "   [X] Extension Pack missing or mismatched ($extPackVersion) -> Install matching version" -ForegroundColor Red
} else {
    Write-Host "   [OK] Extension Pack: Installed and matching" -ForegroundColor Green
}
Write-Host ""

$hostResources = Get-HostResources
Write-Host "Host Resources Detected:" -ForegroundColor Cyan
Write-Host "  - Physical CPU Cores: $($hostResources.Cores)" -ForegroundColor White
Write-Host "  - Logical Processors: $($hostResources.LogicalProcessors)" -ForegroundColor White
Write-Host "  - Total RAM: $($hostResources.RAMGB) GB" -ForegroundColor White
Write-Host ""

Write-Host "1. Checking Hyper-V and VBS status..." -ForegroundColor Yellow
$hyperVFeature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction SilentlyContinue
$hypervisorPresent = $computerInfo.HyperVisorPresent
$vbsRunning = Get-VBSStatus

if ($hyperVFeature -and $hyperVFeature.State -eq "Enabled") {
    Write-Host "   [X] Hyper-V is ENABLED" -ForegroundColor Red
    Write-Host "       Quick disable: bcdedit /set hypervisorlaunchtype off + reboot" -ForegroundColor Gray
} elseif ($hypervisorPresent -or $vbsRunning) {
    Write-Host "   [?] Hypervisor or VBS present -> Likely causing slow NEM mode" -ForegroundColor Yellow
    if ($vbsRunning) {
        Write-Host "   [X] VBS is RUNNING" -ForegroundColor Red
    }
    if ($isRecentBuild) { Write-Host "       Windows 11 24H2+ note: VBS may persist - try DG Readiness Tool" -ForegroundColor Yellow }
} else {
    Write-Host "   [OK] No conflicting hypervisor/VBS detected" -ForegroundColor Green
}

$hvPlatform = Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -ErrorAction SilentlyContinue
if ($hvPlatform.State -eq "Enabled") { Write-Host "   [X] Virtual Machine Platform ENABLED" -ForegroundColor Red }

$memoryIntegrity = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -ErrorAction SilentlyContinue
if ($memoryIntegrity.Enabled -eq 1) {
    Write-Host "   [X] Memory Integrity (Core Isolation) ENABLED" -ForegroundColor Red
    Write-Host "       Disable via Windows Security -> Device security -> Core isolation" -ForegroundColor Gray
}

Write-Host ""

Write-Host "2. Checking active Power Plan..." -ForegroundColor Yellow
$activeScheme = powercfg /getactivescheme
if ($activeScheme -match "High performance|Ultimate Performance") {
    Write-Host "   [OK] $activeScheme" -ForegroundColor Green
} else {
    Write-Host "   [X] Not on High/Ultimate Performance: $activeScheme" -ForegroundColor Red
    Write-Host "       Set High performance: powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" -ForegroundColor Gray
}
Write-Host ""

Write-Host "3. Checking Hardware Virtualization status..." -ForegroundColor Yellow
if ($computerInfo.HyperVRequirementVirtualizationFirmwareEnabled -eq $true) {
    Write-Host "   [OK] VT-x/AMD-V enabled in BIOS" -ForegroundColor Green
} else {
    Write-Host "   [X] Virtualization DISABLED in BIOS/UEFI" -ForegroundColor Red
    Write-Host "       Enable VT-x/AMD-V/SVM in BIOS setup" -ForegroundColor Gray
}
Write-Host ""

Write-Host "4. Scanning VirtualBox VMs..." -ForegroundColor Yellow

$vms = & $vboxManagePath list vms
$runningVms = & $vboxManagePath list runningvms
$totalAllocatedCores = 0
$totalAllocatedRAMGB = 0
$issueCount = 0

if ($vms.Count -eq 0) {
    Write-Host "   [i] No VMs found." -ForegroundColor White
} else {
    foreach ($vmLine in $vms) {
        if ($vmLine -match '"(.*?)" {(.*?)}') {
            $vmName = $Matches[1]
            $vmUUID = $Matches[2]
            $isRunning = $runningVms -match $vmUUID
            
            Write-Host "   Checking VM: $vmName ($vmUUID)" -ForegroundColor Cyan
            if ($isRunning) {
                Write-Host "     [?] VM is running -> Shut down to change some settings" -ForegroundColor Yellow
            }
            
            $vmInfo = & $vboxManagePath showvminfo $vmUUID --machinereadable
            
            # Parse all settings safely
            $cpus              = Get-SettingValue $vmInfo '^cpus='
            $memory            = Get-SettingValue $vmInfo '^memory='
            $vram              = Get-SettingValue $vmInfo '^vram='
            $accelerate3D      = Get-SettingValue $vmInfo '^accelerate3d='
            $graphicsController= Get-SettingValue $vmInfo '^graphicscontroller='
            $hwvirtEx          = Get-SettingValue $vmInfo '^hwvirtex='
            $nestedPaging      = Get-SettingValue $vmInfo '^nestedpaging='
            $paravirtProvider  = Get-SettingValue $vmInfo '^paravirtprovider='
            $chipset           = Get-SettingValue $vmInfo '^chipset='
            $ioapic            = Get-SettingValue $vmInfo '^ioapic='
            $useHostIoCache    = Get-SettingValue $vmInfo '^usehostiocache0='
            $storageControllerType = Get-SettingValue $vmInfo '^storagecontrollertype0='
            $nicType           = Get-SettingValue $vmInfo '^nic1='
            $audioEnabled      = Get-SettingValue $vmInfo '^audio='
            $nestedHwVirt      = Get-SettingValue $vmInfo '^nested-hw-virt='
            $usbController     = Get-SettingValue $vmInfo '^usb='
            $additionsVersion  = Get-SettingValue $vmInfo '^additionsversion='
            $additionsRunLevel = Get-SettingValue $vmInfo '^additionsrunlevel='
            
            # Safe numeric conversion
            $cpusInt = 0
            [int]::TryParse($cpus, [ref]$cpusInt) | Out-Null
            
            $memoryInt = 0
            [int]::TryParse($memory, [ref]$memoryInt) | Out-Null
            
            $vramInt = 0
            [int]::TryParse($vram, [ref]$vramInt) | Out-Null
            
            $runLevelInt = 0
            [int]::TryParse($additionsRunLevel, [ref]$runLevelInt) | Out-Null
            
            # Resource accumulation
            $totalAllocatedCores += $cpusInt
            $memoryGB = [math]::Round($memoryInt / 1024, 0)
            $totalAllocatedRAMGB += $memoryGB
            
            # CPU check
            if ($cpusInt -gt $hostResources.LogicalProcessors) {
                Write-Host "     [X] CPU cores ($cpusInt) > host logical ($($hostResources.LogicalProcessors))" -ForegroundColor Red
                $issueCount++
            } elseif ($cpusInt -gt [math]::Round(0.7 * $hostResources.LogicalProcessors)) {
                Write-Host "     [X] CPU cores ($cpusInt) > 70% host" -ForegroundColor Red
                $issueCount++
            } else {
                Write-Host "     [OK] CPU cores: $cpusInt" -ForegroundColor Green
            }
            
            # RAM check
            if ($memoryGB -gt [math]::Round(0.5 * $hostResources.RAMGB)) {
                Write-Host "     [X] RAM ($memoryGB GB) > 50% host ($($hostResources.RAMGB) GB)" -ForegroundColor Red
                $issueCount++
            } else {
                Write-Host "     [OK] RAM: $memoryGB GB" -ForegroundColor Green
            }
            
            # Video memory
            if ($vramInt -lt 128) {
                Write-Host "     [X] Video memory ($vramInt MB) < 128 MB" -ForegroundColor Red
                $issueCount++
            } else {
                Write-Host "     [OK] Video memory: $vramInt MB" -ForegroundColor Green
            }
            
            # 3D Acceleration
            if ($accelerate3D -ne 'on') {
                Write-Host "     [X] 3D Acceleration OFF" -ForegroundColor Red
                $issueCount++
            } else {
                Write-Host "     [OK] 3D Acceleration ON" -ForegroundColor Green
            }
            
            # Graphics controller
            if ($graphicsController.ToLower() -ne 'vboxsvga') {
		Write-Host "     [X] Graphics controller ($graphicsController) != vboxsvga -> Change to vboxsvga for Windows or vmsvga for Linux" -ForegroundColor Red
                $issueCount++
            } else {
                Write-Host "     [OK] Graphics controller: $graphicsController" -ForegroundColor Green
            }
            
            # Hardware virt
            if ($hwvirtEx -ne 'on' -or $nestedPaging -ne 'on') {
                Write-Host "     [X] VT-x/AMD-V or Nested Paging OFF" -ForegroundColor Red
                $issueCount++
            } else {
                Write-Host "     [OK] VT-x/AMD-V + Nested Paging ON" -ForegroundColor Green
            }
            
            # Paravirt
            $paravirtLower = $paravirtProvider.ToLower()
            if ($paravirtLower -in 'none','default') {
                Write-Host "     [X] Paravirtualization ($paravirtProvider) fallback -> Set to kvm" -ForegroundColor Red
                $issueCount++
            } elseif ($paravirtLower -notin 'kvm','hyperv') {
                Write-Host "     [?] Paravirtualization ($paravirtProvider) -> Consider kvm" -ForegroundColor Yellow
            } else {
                Write-Host "     [OK] Paravirtualization: $paravirtProvider" -ForegroundColor Green
            }
            
            # Chipset
            $chipsetLower = $chipset.ToLower()
            if ($chipsetLower -notin 'ich9','piix3') {
                Write-Host "     [?] Chipset ($chipset) not ich9 or piix3 -> Consider ich9 for modern guests" -ForegroundColor Yellow
            } elseif ($chipsetLower -eq 'piix3') {
                Write-Host "     [OK] Chipset: piix3 (default, reliable; consider ich9 for modern OSes / more devices)" -ForegroundColor Green
            } else {
                Write-Host "     [OK] Chipset: $chipset" -ForegroundColor Green
            }            
            # I/O APIC
            if ($ioapic -ne 'on' -and $cpusInt -gt 1) {
                Write-Host "     [X] I/O APIC OFF (multi-core guest)" -ForegroundColor Red
                $issueCount++
            } else {
                Write-Host "     [OK] I/O APIC: $ioapic" -ForegroundColor Green
            }
            
            # Host I/O Cache
	    if ($useHostIoCache -ne 'on') {
		Write-Host "     [?] Host I/O Cache OFF -> Enable for better performance (risk on host crash)" -ForegroundColor Yellow
	    } else {
		Write-Host "     [OK] Host I/O Cache: ON" -ForegroundColor Green
	    }
            
            # Storage controller
            if ($storageControllerType -notin 'IntelAhci','VirtioSCSI') {
                Write-Host "     [X] Storage controller ($storageControllerType) -> Prefer VirtioSCSI" -ForegroundColor Red
                $issueCount++
            } else {
                Write-Host "     [OK] Storage controller: $storageControllerType" -ForegroundColor Green
            }
            
            # Network
            $nicLower = $nicType.ToLower()
            if ($nicLower -notin 'nat','bridged') {
                Write-Host "     [?] Network ($nicType) -> NAT fastest for basic use" -ForegroundColor Yellow
            } else {
                Write-Host "     [OK] Network: $nicType" -ForegroundColor Green
            }
            
            # Audio
            if ($audioEnabled -notin 'null','none') {
                Write-Host "     [?] Audio enabled ($audioEnabled) -> Disable if unused" -ForegroundColor Yellow
            } else {
                Write-Host "     [OK] Audio: $audioEnabled" -ForegroundColor Green
            }
            
            # Nested virt
            if ($nestedHwVirt -eq 'on') {
                Write-Host "     [OK] Nested Virtualization ON" -ForegroundColor Green
            } else {
                Write-Host "     [i] Nested Virtualization OFF" -ForegroundColor White
            }
            
            # USB + Ext Pack
            if ($usbController -ne 'off' -and !$hasExtPack) {
                Write-Host "     [X] USB enabled but no Ext Pack" -ForegroundColor Red
                $issueCount++
            } elseif ($usbController -ne 'off') {
                Write-Host "     [OK] USB enabled with Ext Pack" -ForegroundColor Green
            }
            
            # Guest Additions
            if ([string]::IsNullOrEmpty($additionsVersion) -or $runLevelInt -lt 2) {
                Write-Host "     [X] Guest Additions missing or not running" -ForegroundColor Red
                $issueCount++
            } elseif ($additionsVersion -ne $vbVersion) {
                Write-Host "     [X] Guest Additions version mismatch ($additionsVersion vs host $vbVersion)" -ForegroundColor Red
                $issueCount++
            } else {
                Write-Host "     [OK] Guest Additions: $additionsVersion" -ForegroundColor Green
            }
            
            # Slow mode in log
            $cfgFile = Get-SettingValue $vmInfo '^CfgFile='
            if ($cfgFile) {
                $logPath = $cfgFile -replace '\.vbox$', '-0.log'
                if (Test-Path $logPath) {
                    $logContent = Get-Content $logPath -Raw -ErrorAction SilentlyContinue
                    if ($logContent -match "Snail execution mode|fall back to NEM") {
                        Write-Host "     [X] Slow NEM/snail mode in logs" -ForegroundColor Red
                        $issueCount++
                    } else {
                        Write-Host "     [OK] No slow mode in logs" -ForegroundColor Green
                    }
                } else {
                    Write-Host "     [i] Log not found - start VM to generate" -ForegroundColor White
                }
            }
            
            # Fix suggestions
            if ($FixSuggestions) {
                Write-Host "     Suggested Fixes (manual):" -ForegroundColor Cyan
                if ($vramInt -lt 128)                  { Write-Host "       VBoxManage modifyvm `"$vmName`" --vram 128" -ForegroundColor Gray }
                if ($accelerate3D -ne 'on')            { Write-Host "       VBoxManage modifyvm `"$vmName`" --accelerate3d on" -ForegroundColor Gray }
                if ($graphicsController.ToLower() -ne 'vboxsvga') { Write-Host "       VBoxManage modifyvm `"$vmName`" --graphicscontroller vboxsvga" -ForegroundColor Gray }
                if ($hwvirtEx -ne 'on')                { Write-Host "       VBoxManage modifyvm `"$vmName`" --hwvirtex on" -ForegroundColor Gray }
                if ($nestedPaging -ne 'on')            { Write-Host "       VBoxManage modifyvm `"$vmName`" --nestedpaging on" -ForegroundColor Gray }
                if ($paravirtLower -in 'none','default') { Write-Host "       VBoxManage modifyvm `"$vmName`" --paravirtprovider kvm" -ForegroundColor Gray }
                if ($ioapic -ne 'on')                  { Write-Host "       VBoxManage modifyvm `"$vmName`" --ioapic on" -ForegroundColor Gray }
            }
            
            Write-Host ""
        }
    }
    
    Write-Host "   Total Allocated:" -ForegroundColor Cyan
    if ($totalAllocatedCores -gt $hostResources.LogicalProcessors) {
        Write-Host "     [X] Total CPU: $totalAllocatedCores > host $($hostResources.LogicalProcessors)" -ForegroundColor Red
    } else {
        Write-Host "     [OK] Total CPU: $totalAllocatedCores" -ForegroundColor Green
    }
    if ($totalAllocatedRAMGB -gt $hostResources.RAMGB) {
        Write-Host "     [X] Total RAM: $totalAllocatedRAMGB GB > host $($hostResources.RAMGB) GB" -ForegroundColor Red
    } else {
        Write-Host "     [OK] Total RAM: $totalAllocatedRAMGB GB" -ForegroundColor Green
    }
    Write-Host ""
}

Write-Host "5. Guest Additions check (Global)" -ForegroundColor Yellow
Write-Host "   [i] Verify inside guest: VBoxTray.exe running, Oracle graphics in Device Manager" -ForegroundColor White
Write-Host "   [i] Insert Guest Additions CD via VirtualBox menu if needed" -ForegroundColor White
Write-Host ""

Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "Summary & Next Steps (Found $issueCount [X] issues):" -ForegroundColor Cyan
Write-Host ""

if ($vbsRunning) { Write-Host "-> Priority: Disable VBS" -ForegroundColor Red }
if ($memoryIntegrity.Enabled -eq 1) { Write-Host "-> Disable Memory Integrity" -ForegroundColor Red }
if ($computerInfo.HyperVRequirementVirtualizationFirmwareEnabled -ne $true) { Write-Host "-> Enable BIOS Virtualization" -ForegroundColor Red }
if ([version]$vbVersion -lt [version]"7.2.6") { Write-Host "-> Update VirtualBox" -ForegroundColor Red }
if ($extPackVersion -ne $vbVersion) { Write-Host "-> Install Extension Pack" -ForegroundColor Red }

Write-Host "-> Address [X] items in VM Settings" -ForegroundColor White
Write-Host "-> Reboot host after host fixes" -ForegroundColor White
Write-Host "-> Test VM performance post-changes" -ForegroundColor White

Write-Host ""
Write-Host "Script finished." -ForegroundColor Cyan

if ($OutputFile) {
    Write-Host "[i] For full export: Run script with Start-Transcript -Path '$OutputFile'" -ForegroundColor White
}
