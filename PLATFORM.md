# Platform Requirements

## Operating System
- Windows 10 or Windows 11 (x64)
- Test signing mode must be enabled (see Setup)
- Memory Integrity (HVCI) must be disabled

## Architecture
- x86-64 (amd64) only
- 32-bit systems are not supported

## Required Software

### User Mode Application
- Microsoft Visual C++ Redistributable 2022 (x64)
- No additional runtime dependencies (statically linked)

### Kernel Driver
- Windows Driver Kit (WDK) 10.0 or later (build only)
- Test signing mode enabled
- Secure Boot disabled (or configured to allow test signed drivers)

## Setup

### Enable Test Signing
Run `scripts/test_signing.bat` as Administrator and reboot.
Confirm test mode is active — a "Test Mode" watermark should appear in the bottom right corner of the desktop.

 **Important:** The following .bat files look for `anti-cheat.sys` in the same directory as the script. If the `.sys` file is missing or in a different location the scripts will fail.

### Trust the Test Certificate
Run `scripts/sign.bat` as Administrator.

### Load the Driver
Run `scripts/load_driver.bat` as Administrator.

### Run the Application
Run `bin/soft_sec_final.exe` from a terminal.

### Unload the Driver
Run `scripts/unload_driver.bat` as Administrator when finished.

## Tested Environment
- Windows 11 Pro x64
- VMware Workstation 17 (guest VM)
- Test signing enabled, HVCI disabled, Secure Boot disabled

## Known Incompatibilities
- HVCI / Memory Integrity must be off — kernel driver will fail to load with error 577
- Secure Boot must be disabled or test signing will not apply
- 32-bit Windows is not supported
- ARM64 is not supported
