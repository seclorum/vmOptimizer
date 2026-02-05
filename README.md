# vmOptimizer

A Windows PowerShell script that inspects local Windows VM-related configuration options as well as VirtualBox VM instances, and provides a detailed report of recommended changes to improve VirtualBox VM performance on Windows hosts.

## Features

- Detects host-level blockers (Hyper-V, Memory Integrity, power plan, BIOS virtualization)
- Scans all configured VirtualBox VMs
- Checks key VM settings: CPU/RAM allocation, video memory, 3D acceleration, graphics controller, hardware virtualization, paravirtualization
- Provides clear `[OK]`, `[X]`, `[?]`, and `[i]` indicators with actionable recommendations
- Helps eliminate common "turtle mode" (slow NEM fallback) issues

## Example Report

```text
VirtualBox VM Optimization Checklist - Host & VM Checks (Windows 11+)
==============================================================================

VirtualBox Installation Check:
   [X] VirtualBox version 7.2.4 is outdated -> Update to 7.2.6 or later for stability and features
   [X] Extension Pack missing or mismatched (current: None) -> Install matching Extension Pack for USB 3.0, etc.

Host Resources Detected:
  - Physical CPU Cores: 10
  - Logical Processors: 12
  - Total RAM: 32 GB

1. Checking Hyper-V and VBS status...
   [?] A hypervisor or VBS is present (Hyper-V or another) -> VirtualBox may run slowly
       Check: bcdedit /enum | findstr hypervisorlaunchtype
   [X] Memory Integrity (Core Isolation) is ENABLED -> Often conflicts with VirtualBox
       Recommendation: Disable in Windows Security -> Device security -> Core isolation

2. Checking active Power Plan...
   [OK] Active plan looks good: Power Scheme GUID: 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c  (High performance)

3. Checking Hardware Virtualization (VT-x/AMD-V) status...
   [X] Virtualization DISABLED in firmware
       You must enable VT-x / AMD-V / SVM in BIOS/UEFI setup
       (Restart PC -> enter BIOS -> look for Virtualization / CPU features)

4. Scanning VirtualBox VMs for optimization...
   Checking VM: rhel-10-lab-01 (c569df50-1879-4f12-b6b1-dc8b8bd36979)
     [OK] CPU cores: 4 (Suggestion: 2-4 for most desktop guests)
     [OK] RAM: 8 GB (Suggestion: 4-8 GB for most guests)
     [X] Video memory (16 MB) < 128 MB -> Increase for better graphics
     [X] 3D Acceleration is OFF -> Enable for better GUI performance
     [X] Graphics controller ("vmsvga") != VBoxSVGA -> Change to VBoxSVGA for best compatibility
     [X] VT-x/AMD-V or Nested Paging is OFF -> Enable in Acceleration tab
     [?] Paravirtualization Interface ("default") != KVM or Hyper-V -> Consider KVM for better performance
     [?] Chipset ("ich9") not ICH9 or PIIX3 -> Consider ICH9 for modern guests
     [X] I/O APIC is OFF for multi-core guest -> Enable for better SMP performance
     [OK] Host I/O Cache: OFF
     [X] Storage controller ("PIIX4") not AHCI or VirtIO -> Switch to VirtIO for best I/O (install drivers in guest)
     [?] Network adapter ("nat") not NAT or Bridged -> NAT is fastest for simple internet access
     [?] Audio enabled ("default") but may not be needed -> Disable if unused for minor perf gain
     [i] Nested Virtualization: OFF (enable if needed for nested VMs)
     [X] USB enabled but Extension Pack missing -> Install Ext Pack for USB 2.0/3.0 support
     [OK] Guest Additions: Installed and matching ()
     [i] No log found - Start VM and check logs for 'NEM' or 'snail mode' mentions

   Checking VM: rhel-9.4-lab-01 (a8146a18-9603-4786-b96b-5df1d111e26e)
     [?] VM is running -> Some settings can't be changed now; shut down for full fixes
     [OK] CPU cores: 6 (Suggestion: 2-4 for most desktop guests)
     [OK] RAM: 16 GB (Suggestion: 4-8 GB for most guests)
     [OK] Video memory: 128 MB
     [X] 3D Acceleration is OFF -> Enable for better GUI performance
     [X] Graphics controller ("vmsvga") != VBoxSVGA -> Change to VBoxSVGA for best compatibility
     [X] VT-x/AMD-V or Nested Paging is OFF -> Enable in Acceleration tab
     [?] Paravirtualization Interface ("kvm") != KVM or Hyper-V -> Consider KVM for better performance
     [?] Chipset ("piix3") not ICH9 or PIIX3 -> Consider ICH9 for modern guests
     [X] I/O APIC is OFF for multi-core guest -> Enable for better SMP performance
     [OK] Host I/O Cache: OFF
     [X] Storage controller ("PIIX4") not AHCI or VirtIO -> Switch to VirtIO for best I/O (install drivers in guest)
     [?] Network adapter ("natnetwork") not NAT or Bridged -> NAT is fastest for simple internet access
     [?] Audio enabled ("default") but may not be needed -> Disable if unused for minor perf gain
     [i] Nested Virtualization: OFF (enable if needed for nested VMs)
     [X] USB enabled but Extension Pack missing -> Install Ext Pack for USB 2.0/3.0 support
     [OK] Guest Additions: Installed and matching ()
     [i] No log found - Start VM and check logs for 'NEM' or 'snail mode' mentions

   Total Allocated Across All VMs:
     [OK] Total CPU cores: 10
     [OK] Total RAM: 24 GB

5. Guest Additions check (Global)
   [i] Cannot fully detect from host without VM running. For each VM:
       - Check if VBoxTray.exe is running (Task Manager in guest)
       - Or: Look for 'Oracle VM VirtualBox Graphics Adapter' in Device Manager (guest)
       - Best: Run VirtualBox -> VM -> Devices -> Insert Guest Additions CD
         (then install inside guest if not already present)

==============================================================================
Summary & Recommended Next Steps (Found 13 [X] issues):

-> Disable Memory Integrity in Windows Security
-> Enable Virtualization in BIOS/UEFI
-> Update VirtualBox to 7.2.6+
-> Install matching Extension Pack
-> For each VM: Address [X] items in VirtualBox GUI -> Settings
-> After fixes -> reboot host, then test VM performance
  - System -> Acceleration: Enable VT-x/AMD-V + Nested Paging
  - Display: Enable 3D Acceleration, set Video Memory >=128 MB, Controller = VBoxSVGA
  - Install Guest Additions inside every VM
  - Don't over-allocate CPU/RAM (use <=70% cores, <=50% RAM per VM; monitor totals)
  ```
