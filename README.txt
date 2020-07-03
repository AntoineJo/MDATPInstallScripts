*********************************************************************************************************************
*                                                                                                                   *
*           Disclaimer:                                                                                             *
*       These scripts are only made as demonstration to facilitate POC/Pilot of MDATP in a lab environement         *
*       There is no support for these scripts by Microsoft or by any of the authors                                 *
*       Microsoft or authors are not responsible for impact on your environement if you run these scripts           *
*       You should understand and validate these scripts before using them                                          *
*       These scripts include the download and installation of Microsoft binaires:                                  *
*           - Windows Updates                                                                                       *
*           - Framework .NET 4.5                                                                                    *
*           - Microsoft Monitoring Agent                                                                            *
*           - SCEP                                                                                                  *
*                                                                                                                   *
*       You should only use these for test purpose and with the appropriate licence,                                *
*       the script does not provide licence right to use these products                                             *
*                                                                                                                   *
*********************************************************************************************************************
________________________________________________

Microsoft Defender ATP Installation Scripts
________________________________________________

This script installs and sets on devices in Workgroup : 
- Microsoft Defender AV
- Microsoft Defender EDR
- Network Protection (Audit mode by default)
- Attack Surface Reduction rules (Audit mode by default)
- Controlled Folder Access (Audit mode by default)

With this script you can install with automatic download, or download required binaires to prepare for packaging.

Then when installing it will, depending on paramters 
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
Syntax
-------------------------------------------
* Install EPP & EDR
mdatp_poc_setup_windows.ps1 -installEPP -installEDR [-WorkspaceKey <string>] [-WorkspaceID <string>] [-MDATPTag <string>] [-ASRMode <string>] [<CommonParameters>]
* Install EPP only
mdatp_poc_setup_windows.ps1 -installEPP [-ASRMode <string>] [<CommonParameters>]
* Install EDR only
mdatp_poc_setup_windows.ps1 -installEDR [-WorkspaceKey <string>] [-WorkspaceID <string>] [-MDATPTag <string>] [<CommonParameters>]
* Download binaires locally in order to package the installation
mdatp_poc_setup_windows.ps1 -DownloadContent -OS <string> [<CommonParameters>]

* WorkspaceID & WorkspaceKey are required for Windows 7/8.1/Server 2008 R2/2012 R2/2016
* MDATP Tag is optional, it will define a TAG on the computer for MDATP
* ASRMode is optional, it will set ASR, Control Folder Access and Network Protection to Audit mode or enable them in block mode - possible values are AuditMode or EnforcedMode
* OS must be used for DownloadContent, possible values are one of: "All", "Windows7x64", "Windows8.1x64", "Windows10x64", "Windows2008R2", "Windows2012R2", "Windows2016", "Windows2019"

--------------------------------------------
Examples
--------------------------------------------
* Download all binaires
.\mdatp_poc_setup_windows.ps1 -DownloadContent -OS All

* Install EDR only on Windows 7
.\mdatp_poc_setup_windows.ps1 -installEDR -WorkspaceId "...." -WorkspaceKey "...." -MDATPTag Deployment

* Install EPP only on Windows 10
.\mdatp_poc_setup_windows.ps1 -installEPP -ASRMode EnforcedMode
