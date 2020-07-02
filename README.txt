________________________________________________

Microsoft Defender ATP Installation Scripts
________________________________________________

This script installs and sets on devices in Workgroup : 
- Microsoft Defender AV
- Microsoft Defender EDR
- Network Protection (Audit mode by default)
- Attack Surface Reduction rules (Audit mode by default)
- Controlled Folder Access (Audit mode by default)

The script will :
- Detect the operating system version
- Install and setup all Defender ATP components
- Download an EICAR file to initiate a test alert
- (optional) Add a machine tag
- (roadmap) Troubleshoot connectivity problems

-------------------------------------------
REQUIREMENTS
-------------------------------------------

Depending on the platform, the script will ask for WorkspaceId/WorkspaceKey or Onboarding package [WindowsDefenderATPOnboardingPackage.zip], both available in your Microsoft Defender ATP tenant (https://securitycenter.microsoft.com/preferences2/onboarding)
Onboarding package should be located at the same path as the script.

Windows 7 SP1 x64
Windows 8.1 x64
Windows 10 1607 and later x64
Windows Server 2008 R2 SP1 x64
Windows Server 2012 R2 x64
Windows Server 2016 x64
Windows Server 2019 x64

-------------------------------------------
EXAMPLES
-------------------------------------------

.\mdatp_poc_setup_windows.ps1
