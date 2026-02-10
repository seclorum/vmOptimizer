# vmOptimizer

A Windows PowerShell script that inspects a local Windows hosts VM-related configuration options as well as VirtualBox VM instances, and provides a detailed report of recommended changes to improve VirtualBox VM performance on the Windows hosts.

## Features

- Detects host-level blockers (Hyper-V, Memory Integrity, power plan, BIOS virtualization)
- Scans all configured VirtualBox VMs
- Checks key VM settings: CPU/RAM allocation, video memory, 3D acceleration, graphics controller, hardware virtualization, paravirtualization
- Provides clear `[OK]`, `[X]`, `[?]`, and `[i]` indicators with actionable recommendations
- Helps eliminate common "turtle mode" (slow NEM fallback) issues

## Example Report

```text
 .\vmInspectorOptimizer.ps1
VirtualBox VM Optimization Checklist - Host & VM Checks (Windows 11+)
==============================================================================

VirtualBox Installation Check:
   [X] VirtualBox version 7.2.4 is outdated -> Update to 7.2.6 or later
   [X] Extension Pack missing or mismatched (None) -> Install matching version

Host Resources Detected:
  - Physical CPU Cores: 10
  - Logical Processors: 12
  - Total RAM: 32 GB

1. Checking Hyper-V and VBS status...
   [?] Hypervisor or VBS present -> Likely causing slow NEM mode
   [X] Memory Integrity (Core Isolation) ENABLED
       Disable via Windows Security -> Device security -> Core isolation

2. Checking active Power Plan...
   [OK] Power Scheme GUID: 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c  (High performance)

3. Checking Hardware Virtualization status...
   [X] Virtualization DISABLED in BIOS/UEFI
       Enable VT-x/AMD-V/SVM in BIOS setup

4. Scanning VirtualBox VMs...
   Checking VM: rhel-10-lab-01 (c569df50-1879-4f12-b6b1-dc8b8bd36979)
     [OK] CPU cores: 4
     [OK] RAM: 8 GB
     [X] Video memory (16 MB) < 128 MB
     [X] 3D Acceleration OFF
     [X] Graphics controller (vmsvga) != vboxsvga
     [OK] VT-x/AMD-V + Nested Paging ON
     [X] Paravirtualization (default) fallback -> Set to kvm
     [OK] Chipset: ich9
     [OK] I/O APIC: on
     [OK] Host I/O Cache:
     [X] Storage controller (PIIX4) -> Prefer VirtioSCSI
     [OK] Network: nat
     [?] Audio enabled (default) -> Disable if unused
     [i] Nested Virtualization OFF
     [X] USB enabled but no Ext Pack
     [X] Guest Additions missing or not running
     [i] Log not found - start VM to generate

   Checking VM: rhel-9.4-lab-01 (a8146a18-9603-4786-b96b-5df1d111e26e)
     [?] VM is running -> Shut down to change some settings
     [OK] CPU cores: 6
     [OK] RAM: 16 GB
     [OK] Video memory: 128 MB
     [OK] 3D Acceleration ON
     [X] Graphics controller (vmsvga) != vboxsvga
     [OK] VT-x/AMD-V + Nested Paging ON
     [OK] Paravirtualization: kvm
     [OK] Chipset: piix3
     [OK] I/O APIC: on
     [OK] Host I/O Cache:
     [X] Storage controller (PIIX4) -> Prefer VirtioSCSI
     [?] Network (natnetwork) -> NAT fastest for basic use
     [?] Audio enabled (default) -> Disable if unused
     [i] Nested Virtualization OFF
     [X] USB enabled but no Ext Pack
     [X] Guest Additions missing or not running
     [i] Log not found - start VM to generate

   Total Allocated:
     [OK] Total CPU: 10
     [OK] Total RAM: 24 GB

5. Guest Additions check (Global)
   [i] Verify inside guest: VBoxTray.exe running, Oracle graphics in Device Manager
   [i] Insert Guest Additions CD via VirtualBox menu if needed

==============================================================================
Summary & Next Steps (Found 11 [X] issues):

-> Disable Memory Integrity
-> Enable BIOS Virtualization
-> Update VirtualBox
-> Install Extension Pack
-> Address [X] items in VM Settings
-> Reboot host after host fixes
-> Test VM performance post-changes

Script finished.
  ```
