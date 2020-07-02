# DISCLAIMER
# Script provided as-is without any garantee it will work and is not supported by Microsoft

Param(
    [Parameter(Mandatory = $False)]
    [switch]
    $installEPP,
    [Parameter(Mandatory = $False)]
    [switch]
    $installEDR,
    [Parameter(Mandatory = $False)]
    [String]
    $MDATPTag,
    [Parameter(Mandatory = $true)]
    [ValidateSet("AuditMode", "EnforcedMode")]
    [String]
    $ASRMode
)



# Initialize global variables
$global:WorkspaceID = $null
$global:WorkspaceKey = $null



################################
#DO NOT CHANGE ANYTHING AFTER THAT POINT
switch ($ASRMode) {
    "AuditMode" { $global:ASRValue = "AuditMode" }
    "EnforcedMode" { $global:ASRValue = "Enabled" }
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

$global:currentpath = split-path $SCRIPT:MyInvocation.MyCommand.Path -parent

$global:OnboardingPackage = $global:currentpath + '\WindowsDefenderATPOnboardingPackage.zip'
if (!(Test-Path  $ENV:TEMP+'\MDATP\')) {
    New-Item $ENV:TEMP+'\MDATP' -ItemType Directory | Out-Null
}

$global:outDir = $ENV:TEMP + '\MDATP\'
$global:resultsDir = $global:outDir
$global:logfile = $ENV:TEMP + '\MDATP\install.log'


if (!(Test-Path $global:resultsDir)) {
    $dirName = split-path $global:resultsDir -Leaf
    New-Item -Path $global:currentpath -Name $dirName -ItemType "directory" | Out-Null
}

$global:logfile = $global:resultsDir + '\install.log'
if (Test-Path $global:logfile) {
    $rand = Get-Random
    $global:logfile = $global:resultsDir + "\install-$rand.log"
}
Write-Debug ("log file is " + $global:logfile)

#Import Module
if ((Get-Module -Name "mdatp_poc_setup_windows_lib")) {
    remove-module mdatp_poc_setup_windows_lib
}
Import-Module ($global:currentpath + '\mdatp_poc_setup_windows_lib.psm1')

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
        Install-Windows7
        if ($global:EDR) {
            Add-MachineTag
        }
        Test-MDATPEICAR
    }
    elseif (("7", "8", "10", "36", "37", "38") -contains $OSinfo.OperatingSystemSKU) {
        #Windows Server 2008 R2
        Write-Log "Windows Server 2008 R2"
        Install-Windows2008R2
        if ($global:EDR) {
            Add-MachineTag
        }
        Test-MDATPEICAR
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
        Install-Windows81
        if ($global:EDR) {
            Add-MachineTag
        }
        Test-MDATPEICAR
    }
    elseif (("7", "8", "10", "36", "37", "38") -contains $OSinfo.OperatingSystemSKU) {
        #Windows Server 2012 R2
        Write-Log "Windows Server 2012 R2"
        if ($OSinfo.OSArchitecture -ne "64-bit") {
            Write-Log "This script is meant for Windows Server 2012 R2 x64. x86 is not yet possible" "FATAL"
            Write-Error "This script is meant for Windows Server 2012 x64. x86 is not yet possible"
            return
        }
        Install-Windows2012R2
        if ($global:EDR) {
            Add-MachineTag
        }
        Test-MDATPEICAR
    }
    else {
        Write-Log ("Unsupported SKU" + $OSinfo.OperatingSystemSKU + " (" + $OSinfo.Caption + ")") "FATAL"
        Write-Error ("Unsupported System SKU " + $OSinfo.OperatingSystemSKU + " (" + $OSinfo.Caption + ")")
        Exit
    }
}
elseif (($OSinfo.Version -like "10.0.*") -and ([Convert]::ToInt32($OSinfo.BuildNumber) -ge 14393)) {
    #Win10/Server 2016/2019 + min 1607
    
    if (("4", "6", "27", "49") -contains $OSinfo.OperatingSystemSKU) {
        #Windows 10 Pro, Enterprise or Enterprise N
        Write-Log "Windows 10 Pro, Pro N, Enterprise or Enterprise N"
        Install-Windows10
        if ($global:EPP) {
            Set-WindowsSecuritySettings -ProtectionMode $global:ASRValue # can be changed to "Enabled" for ASR, CFA, NP
        }
        if ($global:EDR) {
            Add-MachineTag
        }
        Test-MDATPEICAR
    }
    elseif (("7", "8", "10", "36", "37", "38") -contains $OSinfo.OperatingSystemSKU) {
        if (([Convert]::ToInt32($OSinfo.BuildNumber) -lt 17763)) {
            #Windows Server 2016
            Write-Log "Windows Server 2016"
            Install-Windows2016
            if ($global:EDR) {
                Add-MachineTag
            }
            Test-MDATPEICAR
        }
        else {
            #Windows Server 2019
            Write-Log "Windows Server 2019"
            Install-Windows2019
            if ($global:EPP) {
                Set-WindowsSecuritySettings -ProtectionMode $global:ASRValue # can be changed to "Enabled" for ASR, CFA, NP
            }
            if ($global:EDR) {
                Add-MachineTag
            }
            Test-MDATPEICAR
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
