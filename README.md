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
VirtualBox VM Optimization Checklist - Host & VM Checks (Windows 11)
==============================================================================

Host Resources Detected:
  - Physical CPU Cores: 10
  - Logical Processors: 12
  - Total RAM: 32 GB

1. Checking Hyper-V status...
   [?] A hypervisor is present (Hyper-V or another) -> VirtualBox may run slowly
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
     [OK] CPU cores: 4
     [OK] RAM: 8 GB
     [X] Video memory (16 MB) < 128 MB -> Increase for better graphics
     [X] 3D Acceleration is OFF -> Enable for better GUI performance
     [X] Graphics controller ("vmsvga") != VBoxSVGA -> Change to VBoxSVGA for best compatibility
     [X] VT-x/AMD-V or Nested Paging is OFF -> Enable in Acceleration tab
     [?] Paravirtualization Interface ("default") != KVM or Hyper-V -> Consider KVM for better performance
     [i] Guest Additions: Check inside VM (cannot detect from host)
     [i] Storage: Review in VM Settings -> Use SATA/AHCI or VirtIO for best I/O

   Checking VM: rhel-9.4-lab-01 (a8146a18-9603-4786-b96b-5df1d111e26e)
     [OK] CPU cores: 6
     [OK] RAM: 16 GB
     [OK] Video memory: 128 MB
     [X] 3D Acceleration is OFF -> Enable for better GUI performance
     [X] Graphics controller ("vmsvga") != VBoxSVGA -> Change to VBoxSVGA for best compatibility
     [X] VT-x/AMD-V or Nested Paging is OFF -> Enable in Acceleration tab
     [?] Paravirtualization Interface ("kvm") != KVM or Hyper-V -> Consider KVM for better performance
     [i] Guest Additions: Check inside VM (cannot detect from host)
     [i] Storage: Review in VM Settings -> Use SATA/AHCI or VirtIO for best I/O

5. Guest Additions check (Global)
   [i] Cannot reliably detect from host. For each VM:
       - Check if VBoxTray.exe is running (Task Manager in guest)
       - Or: Look for 'Oracle VM VirtualBox Graphics Adapter' in Device Manager (guest)
       - Best: Run VirtualBox -> VM -> Devices -> Insert Guest Additions CD
         (then install inside guest if not already present)

==============================================================================
Summary & Recommended Next Steps:

-> Disable Memory Integrity in Windows Security
-> Enable Virtualization in BIOS/UEFI
-> For each VM: Address [X] items in VirtualBox GUI -> Settings
-> After fixes -> reboot host, then test VM performance
  - System -> Acceleration: Enable VT-x/AMD-V + Nested Paging
  - Display: Enable 3D Acceleration, set Video Memory >= 128 MB, Controller = VBoxSVGA
  - Install Guest Additions inside every VM
  - Don't over-allocate CPU/RAM (use <=70% cores, <=50% RAM)
  ```
