# DISCLAIMER
# Script provided as-is without any garantee it will work and is not supported by Microsoft
#

Param(
    
    [Parameter(Mandatory = $false)]
    [switch]
    $installEPP,

    [Parameter(Mandatory = $false)]
    [switch]
    $installEDR,

    [Parameter(Mandatory = $false)]
    [switch]
    $uninstallEPP,

    [Parameter(Mandatory = $false)]
    [switch]
    $uninstallEDR,

    [Parameter(Mandatory = $false)]
    [String]
    $WorkspaceKey,

    [Parameter(Mandatory = $false)]
    [String]
    $WorkspaceID,

    [Parameter(Mandatory = $false)]
    [String]
    $MDATPTag,

    [Parameter(Mandatory = $false)]
    [ValidateSet("AuditMode", "EnforcedMode","Disabled")]
    [String]
    $ASRMode = "AuditMode",

    [Parameter(Mandatory = $false)]
    [switch]
    $DownloadContent,

    [Parameter(Mandatory = $false)]
    [ValidateSet("All", "Windows7x64", "Windows8.1x64", "Windows10x64", "Windows2008R2", "Windows2012R2", "Windows2016", "Windows2019")]
    [String]
    $OS

)


################################
#DO NOT CHANGE ANYTHING AFTER THAT POINT
# Initialize global variables

#region GlobalVar
#
# Let me explain a bit the script logic and how we use global:variable here
#
#   WorkspaceID & WorkspaceKey are took from the MDATP Onboarding page and are used for Onboarding and Offboarding Win7/8.1/2008 R2/2012 R2/2016 into MDATP
#
#   ASRMode (default is AuditMode) is the mode for Windows 10/2019 ASR + NetworkProtection + CFA
#
#   MachineTag is a TAG to add to the computer for MDATP
#
#   DownloadOnly is here to allow download of required binairies in order to package and deploy the script to multiple computers
#
#   OSName is the name of the OS to handle, it can be OS to download binairies for, or the OS we are running on
#
#   CurrentPath is the current script execution path
#
#   DownloadLocation is the path to download binaries to, if we are in download only this is the current path, if we are installing, this is the %TEMP% folder
#
#   OutDir is the directory for output & logs => $ENV:TEMP + '\MDATP\'
#
#   EPP, EDR & uninstall are flags, please read this matrix to understand their meaning (that easy :)
#
#   |----------------------------------------------------------|
#   | meaning                    |  EPP  |  EDR  |  Uninstall  |
#   | install EPP only           |   x   |       |             |     
#   | install EDR only           |       |   x   |             |     
#   | install both EPP & EDR     |   x   |   x   |             |     
#   | uninstall EPP              |   x   |       |     x       |     
#   | uninstall EDR              |       |   x   |     x       |     
#   | uninstall EPP & EDR        |   x   |   x   |     x       |     
#   |----------------------------------------------------------|
#
#   Script logic
#   -------------
#   
#   if install or uninstall mode
#       depending on the OS version and on the OS SKU (client/server)
#           if not uninstall order
#               call install function
#           else 
#               call unistall function
#           
#       add MDATP TAG
#       Confirm EDR installation
#   else
#       download binaries for required OSes
#
#################################

$global:WorkspaceID = $WorkspaceID
$global:WorkspaceKey = $WorkspaceKey


switch ($ASRMode) {
    "AuditMode" { $global:ASRValue = "AuditMode" }
    "EnforcedMode" { $global:ASRValue = "Enabled" }
    "Disabled" { $global:ASRValue = "Disabled" }
}

$global:MachineTag = $MDATPTag

if ($installEPP) {
    $global:EPP = $true
} 
else {
    $global:EPP = $false
}
if ($installEDR) {
    $global:EDR = $true
} 
else {
    $global:EDR = $false
}

# Logic to handle uninstallation with the same global variables
if($uninstallEDR -or $uninstallEPP){
    $global:uninstall = $true
    if($uninstallEPP){
        $global:EPP = $true
    }
    if($uninstallEDR){
        $global:EDR = $true
    }
}
else {
    $global:uninstall = $false
}

$global:downloadOnly = $DownloadContent
$global:OSName = $OS
$global:currentpath = split-path $SCRIPT:MyInvocation.MyCommand.Path -parent

if ($global:downloadOnly) {
    $global:downloadLocation = $global:currentpath
}
else {
    $global:downloadLocation = $ENV:TEMP
}

$global:OnboardingPackage = $global:currentpath + '\WindowsDefenderATPOnboardingPackage.zip'
$global:OffboardingPackageName = (Get-ChildItem -Recurse -Force $global:currentpath | Where-Object {!$_.PSIsContainer -and  ($_.Name -like "*WindowsDefenderATPOffboardingPackage*") }).Name

if (!(Test-Path ($ENV:TEMP + '\MDATP\'))) {
    New-Item ($ENV:TEMP + '\MDATP') -ItemType Directory | Out-Null
}
$global:outDir = $ENV:TEMP + '\MDATP\'

$global:resultsDir = $global:outDir
$global:logfile = $ENV:TEMP + '\MDATP\install.log'

$global:logfile = $global:resultsDir + '\install.log'
if (Test-Path $global:logfile) {
    $rand = Get-Random
    $global:logfile = $global:resultsDir + "\install-$rand.log"
}

#endregion GlobalVar

Write-Debug ("log file is " + $global:logfile)

#Import Module
if ((Get-Module -Name "mdatp_poc_setup_windows_lib")) {
    remove-module mdatp_poc_setup_windows_lib
}
Import-Module ($global:currentpath + '\mdatp_poc_setup_windows_lib.psm1')


#If we are not in download only mode, then get the info of the OS we are running on and proceed to installation or uninstallation
if (!$global:downloadOnly) {
    # Get Windows OS Information
    $OSinfo = get-wmiobject win32_operatingsystem
    Write-Log ("OS : " + $OSinfo.Caption + " | Build number: " + $OSinfo.Version + " | SKU: " + $OSinfo.OperatingSystemSKU)

    if ($OSinfo.Version -like "6.1.7601*") {
        #Win7/Server 2008 R2

        if (("4", "6", "27") -contains $OSinfo.OperatingSystemSKU) {
            #Windows 7 Pro, Enterprise or Enterprise N
            Write-Log "Windows 7 Pro, Enterprise or Enterprise N"
            if ($OSinfo.OSArchitecture -ne "64-bit") {
                Write-Log "This script is meant for Windows 7 x64. x86 is not yet possible" "FATAL"
                Write-Error "This script is meant for Windows 7 x64. x86 is not yet possible. Fatal error exiting Windows 7 config"
                return
            }
            $global:OSName = "Windows7x64"

            if(!$global:uninstall) {
                Install-Windows7
            }
            else {
                Uninstall-Windows7
            }

        }
        elseif (("7", "8", "10", "36", "37", "38") -contains $OSinfo.OperatingSystemSKU) {
            #Windows Server 2008 R2
            Write-Log "Windows Server 2008 R2"
            $global:OSName = "Windows2008R2"

            if(!$global:uninstall) {
                Install-Windows2008R2
            }
            else {
                Uninstall-Windows2008R2
            }

        }
        else {
            Write-Log ("Unsupported SKU" + $OSinfo.OperatingSystemSKU + " (" + $OSinfo.Caption + ")") "FATAL"
            Write-Error ("Unsupported System SKU " + $OSinfo.OperatingSystemSKU + " (" + $OSinfo.Caption + ")")
            Exit
        }

    }
    elseif ($OSinfo.Version -like "6.3.9600*") {
        #Win8.1/2012R2
    
        if (("4", "6", "27") -contains $OSinfo.OperatingSystemSKU) {
            Write-Log "Windows 8.1 Pro, Enterprise or Enterprise N"
            if ($OSinfo.OSArchitecture -ne "64-bit") {
                Write-Log "This script is meant for Windows 8.1 x64. x86 is not yet possible" "FATAL"
                Write-Error "This script is meant for Windows 8.1 x64. x86 is not yet possible"
                return
            }
            $global:OSName = "Windows8.1x64"
            
            if(!$global:uninstall) {
                Install-Windows81
            }
            else {
                Uninstall-Windows81
            }

        }
        elseif (("7", "8", "10", "36", "37", "38") -contains $OSinfo.OperatingSystemSKU) {
            #Windows Server 2012 R2
            Write-Log "Windows Server 2012 R2"
            if ($OSinfo.OSArchitecture -ne "64-bit") {
                Write-Log "This script is meant for Windows Server 2012 R2 x64. x86 is not yet possible" "FATAL"
                Write-Error "This script is meant for Windows Server 2012 x64. x86 is not yet possible"
                return
            }
            $global:OSName = "Windows2012R2"
            
            if(!$global:uninstall) {
                Install-Windows2012R2
            }
            else {
                Uninstall-Windows2012R2
            }

        }
        else {
            Write-Log ("Unsupported SKU" + $OSinfo.OperatingSystemSKU + " (" + $OSinfo.Caption + ")") "FATAL"
            Write-Error ("Unsupported System SKU " + $OSinfo.OperatingSystemSKU + " (" + $OSinfo.Caption + ")")
            Exit
        }
    }
    elseif (($OSinfo.Version -like "10.0.*") -and ([Convert]::ToInt32($OSinfo.BuildNumber) -ge 14393)) {
        #Win10/Server 2016/2019 + min 1607
    
        if (("4", "6", "27", "48", "49") -contains $OSinfo.OperatingSystemSKU) {
            #Windows 10 Pro, Pro N, Enterprise or Enterprise N
            Write-Log "Windows 10 Pro, Pro N, Enterprise or Enterprise N"
            $global:OSName = "Windows10x64"
            
            if(!$global:uninstall) {
                Install-Windows10
                if ($global:EPP -or $global:ASRValue) {
                    Set-WindowsSecuritySettings -ProtectionMode $global:ASRValue # can be changed to "Enabled" for ASR, CFA, NP
                }
            }
            else {
                Uninstall-Windows10
                if ($global:EPP) {
                    Set-WindowsSecuritySettings -ProtectionMode Disabled # can be changed to "Enabled" for ASR, CFA, NP
                }
            }

        }
        elseif (("7", "8", "10", "36", "37", "38") -contains $OSinfo.OperatingSystemSKU) {
            if (([Convert]::ToInt32($OSinfo.BuildNumber) -lt 17763)) {
                #Windows Server 2016
                Write-Log "Windows Server 2016"
                $global:OSName = "Windows2016"
                
                if(!$global:uninstall) {
                    Install-Windows2016
                }
                else {
                    Uninstall-Windows2016
                }

            }
            else {
                #Windows Server 2019
                Write-Log "Windows Server 2019"
                $global:OSName = "Windows2019"

                if(!$global:uninstall) {
                    Install-Windows2019
                    if ($global:EPP -or $global:ASRValue) {
                        Set-WindowsSecuritySettings -ProtectionMode $global:ASRValue # can be changed to "Enabled" for ASR, CFA, NP
                    }
                }
                else {
                    Uninstall-Windows2019
                    if ($global:EPP) {
                        Set-WindowsSecuritySettings -ProtectionMode Disabled # can be changed to "Enabled" for ASR, CFA, NP
                    }
                }

            }   

        }
        else {
            Write-Log ("Unsupported SKU" + $OSinfo.OperatingSystemSKU + " (" + $OSinfo.Caption + ")") "FATAL"
            Write-Error ("Unsupported System SKU " + $OSinfo.OperatingSystemSKU + " (" + $OSinfo.Caption + ")")
            Exit
        }
    }
    else {
        Write-Log ("Unsupported OS" + $OSinfo.Version + " " + $OSinfo.OperatingSystemSKU + " (" + $OSinfo.Caption + ")") "FATAL"
        Write-Error ("Unsupported OS " + $OSinfo.Version + " " + $OSinfo.OperatingSystemSKU + " (" + $OSinfo.Caption + ")")
        Exit
    }

    if ($global:EDR) {
        Add-MachineTag
    }
    if(!$global:uninstall){
        Confirm-MDATPInstallation 
    }
}
else {
    
    switch ($global:OSName) {
        "Windows7x64" { Install-Windows7; break }
        "Windows8.1x64" { Install-Windows81 ; break }
        "Windows10x64" { Install-Windows10 ; break }
        "Windows2008R2" { Install-Windows2008R2 ; break }
        "Windows2012R2" { Install-Windows2012R2 ; break }
        "Windows2016" { Install-Windows2016 ; break }
        "Windows2019" { Install-Windows2019 ; break }
        "All" {
            $global:OSName = "Windows7x64"
            Install-Windows7
            $global:OSName = "Windows8.1x64"
            Install-Windows81
            $global:OSName = "Windows10x64"
            Install-Windows10
            $global:OSName = "Windows2008R2"
            Install-Windows2008R2
            $global:OSName = "Windows2012R2"
            Install-Windows2012R2
            $global:OSName = "Windows2016"
            Install-Windows2016
            $global:OSName = "Windows2019"
            Install-Windows2019
        }
        Default {
            Write-Log "Unsupported OS selected" "FATAL"
            Write-Error "Unsupported OS selected"
        }
    }
    Confirm-MDATPInstallation
}
