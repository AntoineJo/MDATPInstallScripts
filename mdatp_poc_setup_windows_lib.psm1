# DISCLAIMER
# Script provided as-is without any garantee it will work and is not supported by Microsoft
# authors Ajourn & thibou

Function Write-Log {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [string]
        $Message,

        [Parameter(Mandatory = $False)]
        [ValidateSet("INFO", "WARN", "ERROR", "FATAL", "DEBUG", "SUCCESS")]
        [String]
        $Level = "INFO"
    )

    $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
    $Line = "$Stamp $Level $Message"
    If ($global:logfile) {
        Add-Content $global:logfile -Value $Line
        $color = ""
        switch ($Level) {
            INFO { $color = "White"; break }
            WARN { $color = "Yellow"; break }
            ERROR { $color = "Red"; break }
            FATAL { $color = "Red"; break }
            DEBUG { $color = "Gray"; break }
            SUCCESS { $color = "Green"; break }
        }
        if ($Level -eq "FATAL") {
            Write-Host $Line -ForegroundColor $color -BackgroundColor White
        }
        else {
            Write-Host $Line -ForegroundColor $color
        }
    }
    Else {
        Write-Output $Line
    }
}

Function Test-MDATPEICAR {
    Write-Log "Connectivity test with an EICAR alert"
    (New-Object Net.WebClient).DownloadFile("https://aka.ms/ioavtest", ($global:currentpath + "\ioav.exe"))
    #powershell.exe -NoExit -ExecutionPolicy Bypass -WindowStyle Hidden $ErrorActionPreference= 'silentlycontinue';(New-Object System.Net.WebClient).DownloadFile('http://127.0.0.1/1.exe', 'C:\\test-WDATP-test\\invoice.exe');Start-Process 'C:\\test-WDATP-test\\invoice.exe'
}

Function Confirm-MDATPInstallation {
    if ( ($null -eq $global:downloadLocation) -or ($null -eq $global:resultsDir)) {
        Write-Log "Download location path not set. Exiting" "ERROR"
        return 
    }

    if (!(Test-Path ($global:currentpath + "\psexec.exe"))) {
        Write-Log "PSExec.exe not found in script directory. Donwloading it"
        $url = "https://live.sysinternals.com/psexec.exe"

        try {
            (New-Object Net.WebClient).DownloadFile($url, ($global:downloadLocation + '\psexec.exe'))
            if (!(Test-Path ($global:downloadLocation + "\psexec.exe"))) {
                Write-Log "Error downloading psexec.exe. Exiting"
                return
            }
        }
        catch {
            Write-Log "Error downloading psexec.exe. Exiting"
            return
        }
    }
    else {
        Copy-Item ($global:currentpath + "\psexec.exe") ($global:downloadLocation + '\psexec.exe')  -Force
    }

    if (!$global:downloadOnly) {
        try {
            #Does not work on Windows 7
            if ("Windows10", "Windows2019", "Windows2016" -contains $global:OSName) {
                Write-Log "Test connection to WDAV backend as System"
                Start-Process -FilePath ($global:downloadLocation + '\psexec.exe') -ArgumentList ("-accepteula", "-nobanner", "-s", ('"' + $Env:ProgramFiles + '\Windows Defender\MpCmdRun.exe" -ValidateMapsConnection >"' + $global:resultsDir + '\mdav.log"')) -Wait -Verb runas

                Write-Log "Extract WDAV configuration & support info"
                if (Test-Path "C:\ProgramData\Microsoft\Windows Defender\Support\MpSupportFiles.cab") {
                    Remove-Item "C:\ProgramData\Microsoft\Windows Defender\Support\MpSupportFiles.cab"
                }
                Start-Process -FilePath ($Env:ProgramFiles + '\Windows Defender\MpCmdRun.exe') -ArgumentList ("-GetFiles") -Wait -Verb runas
                Copy-Item "C:\ProgramData\Microsoft\Windows Defender\Support\MpSupportFiles.cab" ($global:resultsDir + '\MpSupportFiles.cab') -Force
            }
        }
        catch {
            Write-Log "Error testing MDAV" "ERROR"
            Write-Log $_ "ERROR"
        }
    }

    if ($global:EDR -or $global:downloadOnly) {
        if (!(Test-Path ($global:currentpath + "\MDATPClientAnalyzer.zip"))) {
            Write-Log "MDATPClientAnalyzer.zip not found in script directory. Donwloading it"
            $url = "https://aka.ms/mdatpanalyzer"

            try {
                (New-Object Net.WebClient).DownloadFile($url, ($global:downloadLocation + '\MDATPClientAnalyzer.zip'))
                if (!(Test-Path ($global:downloadLocation + "\MDATPClientAnalyzer.zip"))) {
                    Write-Log "Error downloading \MDATPClientAnalyzer.cmd. Exiting"
                    return
                }

            }
            catch {
                Write-Log "Error downloading \MDATPClientAnalyzer.cmd. Exiting"
                return
            }   
        }
        else {
            Copy-Item ($global:currentpath + "\MDATPClientAnalyzer.zip") ($global:downloadLocation + '\MDATPClientAnalyzer.zip')  -Force
        }

        if (!$global:downloadOnly) {
            if (!(Test-Path ($global:downloadLocation + "\MDATPClientAnalyzer"))) {
                New-Item -Path $global:downloadLocation -Name "MDATPClientAnalyzer" -ItemType "directory"
            }
            $expandBuiltIn = get-command Expand-Archive 2> $null
            if ($null -ne $expandBuiltIn) {
                Expand-Archive -Path ($global:downloadLocation + "\MDATPClientAnalyzer.zip") -DestinationPath ($global:downloadLocation + "\MDATPClientAnalyzer\") -Force
            }
            else {
                Expand-ZIPFile ($global:downloadLocation + "\MDATPClientAnalyzer.zip") ($global:downloadLocation + "\MDATPClientAnalyzer\")
            }

            Write-Log "Test connection to MDATP backend as System"
            if (Test-Path ($global:downloadLocation + '\MDATPClientAnalyzer\MDATPClientAnalyzer.cmd')) {
                Start-Process -FilePath ($global:downloadLocation + '\MDATPClientAnalyzer\MDATPClientAnalyzer.cmd') -ArgumentList (">" + $global:resultsDir + "\mdatp.log") -Wait -Verb runas
                Copy-Item ($global:downloadLocation + '\MDATPClientAnalyzer\MDATPClientAnalyzerResult\') ($global:resultsDir) -Recurse  -Force
            }
        }
    }
}

# Reference from https://www.howtogeek.com/tips/how-to-extract-zip-files-using-powershell/
# Author TAYLOR GIBB
function Expand-ZipFile {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)][string]$SourcePath,
        [Parameter(Mandatory = $true, Position = 1)][string]$DestinationPath
    )

    try {
        $shell = new-object -com shell.application
        $zip = $shell.NameSpace($SourcePath)
        foreach ($item in $zip.items()) {
            $shell.Namespace($DestinationPath).copyhere($item)
        }
    }
        
    catch {
        Write-Log ($_.Exception.Message) "WARNING"
    }
}

Function downloadAndInstallSCEP {
    #SCEP alredy include KB3209361
    $scepWebSource = "http://wsus.ds.download.windowsupdate.com/c/msdownload/update/software/crup/2017/01/scepinstall_2c54f8168cc9d05422cde174e771147d527c92ba.exe"

    #Install SCEP
    try {

        if ($global:EPP) {
            #Test if SCEP is already installed
            $scepProcess = get-process -ProcessName MsMpEng 2> $null
            $needinstall = $false
            if ($null -ne $scepProcess) {
                Write-Log "SCEP is already installed and running. Checking version"
                if ($scepProcess.ProductVersion -ne "4.10.0209.0") {
                    Write-Log ("SCEP is not up to date, installed version is " + $scepProcess.ProductVersion)
                    Write-Log "Need to update SCEP"
                    $needinstall = $true
                }
                else {
                    Write-Log "SCEP is installed and up to date"
                }
            }
            else {
                $needinstall = $true
            }
        }

        if ($needinstall -or $global:downloadOnly) {

            if (!(Test-Path ($global:currentpath + '\scep.exe'))) {
                Write-Log "Download SCEP"
                
                (New-Object Net.WebClient).DownloadFile($scepWebSource, ($global:downloadLocation + '\scep.exe'))
                Write-Log "download of SCEP succeded"
            }
            else {
                if (!$global:downloadOnly) {
                    #This is relevant only if we need to install it
                    Copy-Item ($global:currentpath + '\scep.exe') ($global:downloadLocation + '\scep.exe')  -Force
                }
            }

            if (!$global:downloadOnly) {
                if (Test-Path ($global:downloadLocation + '\scep.exe')) {
                    Write-Log "Installing SCEP"
                    $policyFile = ($global:currentpath + "\SCEPProfile.xml")
                    Start-Process -FilePath ($global:downloadLocation + '\scep.exe') -ArgumentList ("/s", "/policy $policyFile", "/sqmoptin") -Verb runas
                    Write-Log "SCEP install in background. Wait for it to finish"
                    Start-Sleep 30
                    $time = 0
                    $scepProcess = get-process -ProcessName MsMpEng 2> $null
                    while (($null -eq $scepProcess) -and ($time -lt 300)) {
                        $scepProcess = get-process -ProcessName MsMpEng 2> $null
                        $time += 30
                        Start-Sleep 30
                        Write-Log "SCEP install in background. Wait for it to finish T=$time"
                    }
                    Copy-Item "C:\ProgramData\Microsoft\Microsoft Security Client\Support\*" ($global:resultsDir + '\')  -Force
                }
                else {
                    Write-Log "Error downloading SCEP agent"
                }
            }
        }
    }
    catch {
        Write-Log "Error downloading or installing SCEP agent" "ERROR"
        Write-Log $_ "ERROR"
        Copy-Item "C:\ProgramData\Microsoft\Microsoft Security Client\Support\*" ($global:resultsDir + '\')  -Force
    }

    if (!$global:downloadOnly) {
        Start-Sleep 20
        Write-Log "Force AV definition update"
        Start-Process -FilePath 'C:\Program Files\Microsoft Security Client\MpCmdRun.exe' -ArgumentList ("-SignatureUpdate", "-MMPC") -Wait -Verb runas

        Write-Log "Getting Windows Update logs"
        Copy-Item "C:\Windows\WindowsUpdate.log" ($global:resultsDir + '\')  -Force
    }
}

Function getOMSWorkspaceInfo {

    if (($null -eq $global:WorkspaceID -or "" -eq $global:WorkspaceID) -or ($null -eq $global:WorkspaceKey -or "" -eq $global:WorkspaceKey)) {
        Write-Log "Workplace ID or Key are null. Fatal error exiting" "FATAL"
        Write-Error "Workplace ID or Key are null. Fatal error exiting Windows config"
        exit
    }

}

Function downloadAndInstallDOTNET45 {
    $restartneeded = $false
    $dotnetWebSource = "https://download.microsoft.com/download/E/2/1/E21644B5-2DF2-47C2-91BD-63C560427900/NDP452-KB2901907-x86-x64-AllOS-ENU.exe"

    try {

        if ($global:EDR) {
            Write-Log "Check if .NET Framework 4.5 is already installed"
            $needinstall = $false
            if (Test-Path 'HKLM:\Software\microsoft\NET Framework Setup\NDP\v4\Full') {
                $needinstall = !((Get-ItemProperty 'HKLM:\Software\microsoft\NET Framework Setup\NDP\v4\Full' -Name Version).Version -ge "4.5")
                Write-Log (".Net 4 installed version is " + (Get-ItemProperty 'HKLM:\Software\microsoft\NET Framework Setup\NDP\v4\Full' -Name Version).Version)
            }
            else {
                $needinstall = $true
                Write-Log ".Net 4 seems not to be installed"
            }
        }

        if ($needinstall -or $global:downloadOnly) {

            if (!(Test-Path ($global:currentpath + '\dotnet4.5.exe'))) {
                Write-Log "Download .NET Framework 4.5"
                (New-Object Net.WebClient).DownloadFile($dotnetWebSource, ($global:downloadLocation + '\dotnet4.5.exe'))
            }
            else {
                if (!$global:downloadOnly) {
                    Copy-Item ($global:currentpath + '\dotnet4.5.exe') ($global:downloadLocation + '\dotnet4.5.exe')  -Force
                }
            }

            if (!$global:downloadOnly) {
                if (Test-Path ($global:downloadLocation + '\dotnet4.5.exe')) {
                    Write-Log "download of DotNet 4.5 succeded"
                    Write-Log "Installing DotNet 4.5"
                    Start-Process -FilePath ($global:downloadLocation + '\dotnet4.5.exe') -ArgumentList ("/q", "/norestart") -Wait -Verb runas
                    Write-Log "DotNet 4.5 install result $LastExitCode"
                    $restartneeded = $true
                    Copy-Item "$global:downloadLocation\Microsoft .NET Framework 4.5 Setup*.html" ($global:resultsDir + '\')  -Force
                }
                else {
                    Write-Log "Error downloading Dot Net 4.5"
                }
            }
        }
    }
    catch {
        Write-Log "Error downloading or installing Dot Net 4.5" "ERROR"
        Write-Log $_ "ERROR"
        Copy-Item "$global:downloadLocation\Microsoft .NET Framework 4.5 Setup*.html" ($global:resultsDir + '\')  -Force
    }

    return $restartneeded
}

Function downloadAndInstallMMA {
    $mmaWebSource = "https://go.microsoft.com/fwlink/?LinkId=828603"
    $restartneeded = $false

    try {
            
        Write-Log "Check if MMA Agent is already installed"
        $needinstall = $false
        $needinstall = !(Test-Path -Path "HKLM:\Software\Classes\AgentConfigManager.MgmtSvcCfg")

        if ($needinstall -or $global:downloadOnly) {

            Write-Log "MMA not already installed"
            if (!(Test-Path ($global:currentpath + '\mma.exe'))) {
                Write-Log "Download MMA"
                (New-Object Net.WebClient).DownloadFile($mmaWebSource, ($global:downloadLocation + '\mma.exe'))
            }
            else {
                if (!$global:downloadOnly) {
                    Copy-Item ($global:currentpath + '\mma.exe') ($global:downloadLocation + '\mma.exe')  -Force
                }
            }
            
            if (!$global:downloadOnly) {
                if (Test-Path ($global:downloadLocation + '\mma.exe')) {
                    Write-Log "download of MMA succeded"
                    Write-Log "Extracting MMA into %TEMP%\MMA"
                    Start-Process -FilePath ($global:downloadLocation + '\mma.exe') -ArgumentList ("/C", "/T:$global:downloadLocation\MMA\") -Wait -Verb runas
                    Write-Log "Installing MMA"
                    Start-Process -FilePath ($global:downloadLocation + '\MMA\setup.exe') -ArgumentList ("/qn", "NOAPM=1", "ADD_OPINSIGHTS_WORKSPACE=1", "OPINSIGHTS_WORKSPACE_AZURE_CLOUD_TYPE=0", 'OPINSIGHTS_WORKSPACE_ID="' + $global:WorkspaceID + '"', 'OPINSIGHTS_WORKSPACE_KEY="' + $global:WorkspaceKey + '"', 'AcceptEndUserLicenseAgreement=1') -Wait -Verb runas
                
                    Write-Log "MMA install result $LastExitCode"
                }
                else {
                    Write-Log "Error downloading MMA"
                }
            }
        }
        else {
            Write-Log "MMA Agent is already installed, so we add MDATP workspace to the existing MMA agent"
            $AgentCfg = New-Object -ComObject AgentConfigManager.MgmtSvcCfg
            $AgentCfg.AddCloudWorkspace($global:WorkspaceID, $global:WorkspaceKey)
            $AgentCfg.ReloadConfiguration()
        }
    }
    catch {
        Write-Log "Error downloading or installing MMA"
        Write-Log $_ "ERROR"
    }

    return $restartneeded
}

Function downloadAndInstallKB {
    [CmdletBinding()]
    param (
        [hashtable]
        $kburls,
        [string]
        $OSName
    )

    $restartneeded = $false

    if (!$global:downloadOnly) {
        $installedkb = Get-HotFix
    }
    else {
        $installedkb = @{}
    }
    foreach ($kb in $kburl.Keys) {

        $installed = $false
        
        $installed = $installedkb | ForEach-Object { if ($_.HotfixID -eq $kb) { $true } }
        
        if (!$installed -or $global:downloadOnly) {
            try {

                if (!(Test-Path ($global:currentpath + '\' + $kb + $OSName + '.msu'))) {
                    write-log ($kb + " missing from OS. Launching download from " + $kburl[$kb])
                    (New-Object Net.WebClient).DownloadFile($kburl[$kb], ($global:downloadLocation + '\' + $kb + $OSName + '.msu'))
                }
                else {
                    if (!$global:downloadOnly) {
                        Copy-Item ($global:currentpath + '\' + $kb + $OSName + '.msu') ($global:downloadLocation + '\' + $kb + $OSName + '.msu')  -Force
                    }
                }

                if (!$global:downloadOnly) {
                    if (Test-Path ($global:downloadLocation + '\' + $kb + $OSName + '.msu')) {
                        Write-Log "download of $kb succeded"
                        Write-Log "Installing $kb"
                        Start-Process -FilePath "wusa.exe" -ArgumentList (($global:downloadLocation + '\' + $kb + $OSName + '.msu'), "/quiet", "/norestart") -Wait -Verb runas
                        Write-Log "$kb install result $LastExitCode"
                        $restartneeded = $true
                    }
                    else {
                        Write-Log "Error downloading $kb "
                    }
                }
            }
            catch {
                Write-Log "Error downloading or installing $kb" "ERROR"
                Write-Log $_ "ERROR"
            }
        }
    }

    return $restartneeded
}

Function Install-Windows7 {

    Write-Log "Handle Windows 7"

    #KB4074598 Feb2018 monthly rollup replaced by full update of Windows 7, for that we need to install KB4534310 (that have KB4490628, KB4474419 and KB4536952 as prereq) - note that KB4474419 is also a prereq to MMA
    #Update for customer XP & telemetry KB3080149
    $kburl = @{KB4490628 = "http://download.windowsupdate.com/c/msdownload/update/software/secu/2019/03/windows6.1-kb4490628-x64_d3de52d6987f7c8bdc2c015dca69eac96047c76e.msu";
        KB4474419        = "http://download.windowsupdate.com/c/msdownload/update/software/secu/2019/03/windows6.1-kb4474419-x64_6acf139f1eb84f60fcdeef3d4f81285e1edb45f9.msu";
        KB4536952        = "http://download.windowsupdate.com/c/msdownload/update/software/secu/2020/01/windows6.1-kb4536952-x64_87f81056110003107fa0e0ec35a3b600ef300a14.msu";
        KB4534310        = "http://download.windowsupdate.com/c/msdownload/update/software/secu/2020/01/windows6.1-kb4534310-x64_4dc78a6eeb14e2eac1ede7381f4a93658c8e2cdc.msu";
        KB3080149        = "http://download.windowsupdate.com/d/msdownload/update/software/updt/2015/08/windows6.1-kb3080149-x64_f25965cefd63a0188b1b6f4aad476a6bd28b68ce.msu"
    }

    $restartneeded = $false

    if ($global:EDR) {
        getOMSWorkspaceInfo
    }

    if ($global:EPP -or $global:downloadOnly) {
        $restartneeded = downloadAndInstallSCEP
    }


    if ($global:EDR -or $global:downloadOnly) {
        #Install NET4.5
        $restartneeded = downloadAndInstallDOTNET45

        #Install missing KB
        $restartneeded = downloadAndInstallKB $kburl $global:OSName

        #Install MMA Agent
        $restartneeded = downloadAndInstallMMA
    }

    if ($restartneeded) {
        Write-Log "Installation completed. Restart is required" "SUCCESS"
        <# Write-Host "You should now restart your Computer. Do you want to do it now?(Y/N)"
        $answer = Read-Host
        do {
            switch ($answer) {
                "y" { $fin=$true;shutdown.exe -r -t 60; Write-Log "Reboot will occurs in one Minute";break }
                "n" { $fin=$true;Write-Log "User choose not to reboot now"}
                Default {$fin=$false;Write-Host "You should now restart your Computer. Do you want to do it now?(Y/N)"
                $answer = Read-Host}
            }
        } while(!$fin) #>
    }
}
Function Install-Windows81 {
    
    Write-Log "Handle Windows 8.1"

    #Update for customer XP & telemetry KB3080149
    $kburl = @{KB3080149 = "http://download.windowsupdate.com/d/msdownload/update/software/updt/2015/08/windows8.1-kb3080149-x64_4254355747ba7cf6974bcfe27c4c34a042e3b07e.msu" }

    $restartneeded = $false
    if ($global:EDR) {
        getOMSWorkspaceInfo
    }

    if ($global:EPP -or $global:downloadOnly) {
        $restartneeded = downloadAndInstallSCEP
    }


    if ($global:EDR -or $global:downloadOnly) {
        #Install NET4.5 is not needed as already part of Windows 8.1 & Server 2012R2
        #$restartneeded = downloadAndInstallDOTNET45

        #Install missing KB
        $restartneeded = downloadAndInstallKB $kburl $global:OSName

        #Install MMA Agent
        $restartneeded = downloadAndInstallMMA
    }

    if ($restartneeded) {
        Write-Log "Installation completed. Restart is required" "SUCCESS"
        <#Write-Host "You should now restart your Computer. Do you want to do it now?(Y/N)"
        $answer = Read-Host
        do {
            switch ($answer) {
                "y" { $fin = $true; shutdown.exe -r -t 60; Write-Log "Reboot will occurs in one Minute"; break }
                "n" { $fin = $true; Write-Log "User choose not to reboot now" }
                Default {
                    $fin = $false; Write-Host "You should now restart your Computer. Do you want to do it now?(Y/N)"
                    $answer = Read-Host
                }
            }
        } while (!$fin)#>
    }
}

Function Get-AVInformation {
    get-wmiObject AntivirusProduct -Namespace root\SecurityCenter2 > $ENV:TEMP + '\MDATP\WMI_Antivirus.log'
    get-
}

Function Install-Windows10 {
    
    Write-Log "Handle Windows 10"

    if ($global:EPP) {
        # Test if MDAV is already installed and running
        $restartneeded = $false
        Try {
            $WDAVProcess = Get-Process -ProcessName MsMpEng 2> $null
            if ($null -ne $WDAVProcess) {
                Write-Log "Windows Defender is already installed and running"
                Write-Log "Checking security intelligence updates settings"
                $WUSetting = (Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU -Name AUOptions).AUOptions
                if (($WUSetting -eq "3") -or ($WUSetting -eq "4")) {
                    Write-Log "Launching security intelligence updates"
                    Update-MPSignature -UpdateSource MicrosoftUpdateServer
                }
                else {
                    Write-Log "Changing update settings to Windows Update"
                    Set-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU -Name AUOptions -Value "4"
                    Update-MPSignature -UpdateSource MicrosoftUpdateServer
                } 
            }
            else {
                Write-Log "Microsoft Defender AV is not running, check the event viewer"
            }
        }
        catch {
            Write-Log "Error installing or updating MDAV" "ERROR"
            Write-Log $_ "ERROR"
        }
    }

    if ($global:EDR) {
        #Onboard machine
        try {
            if (Test-Path $global:OnboardingPackage) {
                Write-Log "Onboarding package detected, proceed with onboarding"
                Expand-Archive -Path $global:OnboardingPackage -DestinationPath $ENV:TEMP -Force
                #Edit cmd file to transform it to automated
                $file = get-content ($ENV:TEMP+"\WindowsDefenderATPLocalOnboardingScript.cmd")
                $file[1] = "GOTO SCRIPT_START"
                $file.replace("pause","") > ($ENV:TEMP + "\WindowsDefenderATPLocalOnboardingScript_silent.cmd")

                Start-Process -FilePath ($ENV:TEMP + "\WindowsDefenderATPLocalOnboardingScript_silent.cmd") -Wait -Verb RunAs
                Write-Log "Onboarding completed" "SUCCESS"
            }
            else {
                Write-Log "Issue finding the onboarding package, make sure you download the file from https://securitycenter.windows.com/preferences2/onboarding and put it in the same folder as the script"
            }
        }
        catch {
            Write-Log "Error while trying to onboard the machine to MDATP" "ERROR"
            Write-Log $_ "ERROR"
            Exit
        }
    }

    if ($restartneeded) {
        Write-Log "Installation completed. Restart is required" "INFO"
        <#Write-Host "You should now restart your Computer. Do you want to do it now?(Y/N)"
        $answer = Read-Host
        do {
            switch ($answer) {
                "y" { $fin = $true; shutdown.exe -r -t 60; Write-Log "Reboot will occurs in one Minute"; break }
                "n" { $fin = $true; Write-Log "User choose not to reboot now" }
                Default {
                    $fin = $false; Write-Host "You should now restart your Computer. Do you want to do it now?(Y/N)"
                    $answer = Read-Host
                }
            }
        } while (!$fin)#>
    }
}

Function Install-Windows2008R2 {

    Write-Log "Handle Windows Server 2008 R2"

    $restartneeded = $false

    #KB4074598 Feb2018 monthly rollup replaced by full update of Windows 2008 R2, for that we need to install KB410378 (replacement for required KB4074598) and KB3125574 (replacement for required KB3080149)

    $kburl = @{KB4103718 = "http://download.windowsupdate.com/d/msdownload/update/software/secu/2018/05/windows6.1-kb4103718-x64_c051268978faef39e21863a95ea2452ecbc0936d.msu";
               KB3125574 = "http://download.windowsupdate.com/d/msdownload/update/software/updt/2016/05/windows6.1-kb3125574-v4-x64_2dafb1d203c8964239af3048b5dd4b1264cd93b9.msu"
    }

    

    if ($global:EDR) {
        getOMSWorkspaceInfo
    }

    if ($global:EPP -or $global:downloadOnly) {
        $restartneeded = downloadAndInstallSCEP
    }


    if ($global:EDR -or $global:downloadOnly) {
        #Install NET4.5
        $restartneeded = downloadAndInstallDOTNET45

        #Install missing KB
        $restartneeded = downloadAndInstallKB $kburl $global:OSName

        #Install MMA Agent
        $restartneeded = downloadAndInstallMMA
    }

    if ($restartneeded) {
        Write-Log "Installation completed. Restart is required" "SUCCESS"
        <# Write-Host "You should now restart your Computer. Do you want to do it now?(Y/N)"
        $answer = Read-Host
        do {
            switch ($answer) {
                "y" { $fin=$true;shutdown.exe -r -t 60; Write-Log "Reboot will occurs in one Minute";break }
                "n" { $fin=$true;Write-Log "User choose not to reboot now"}
                Default {$fin=$false;Write-Host "You should now restart your Computer. Do you want to do it now?(Y/N)"
                $answer = Read-Host}
            }
        } while(!$fin) #>
    }
}

Function Install-Windows2012R2 {
    
    Write-Log "Handle Windows Server 2012 R2"

    $restartneeded = $false

    #Update for customer XP & telemetry KB3080149
    $kburl = @{KB3080149 = "http://download.windowsupdate.com/d/msdownload/update/software/updt/2015/08/windows8.1-kb3080149-x64_4254355747ba7cf6974bcfe27c4c34a042e3b07e.msu" }

    if ($global:EDR) {
        getOMSWorkspaceInfo
    }

    if ($global:EPP -or $global:downloadOnly) {
        $restartneeded = downloadAndInstallSCEP
    }


    if ($global:EDR -or $global:downloadOnly) {
        #Install NET4.5 is not needed as already part of Windows 8.1 & Server 2012R2
        #$restartneeded = downloadAndInstallDOTNET45

        #Install missing KB
        $restartneeded = downloadAndInstallKB $kburl $global:OSName

        #Install MMA Agent
        $restartneeded = downloadAndInstallMMA
    }
    
    if ($restartneeded) {
        Write-Log "Installation completed. Restart is required" "SUCCESS"
        <#         Write-Host "You should now restart your Computer. Do you want to do it now?(Y/N)"
        $answer = Read-Host
        do {
            switch ($answer) {
                "y" { $fin=$true;shutdown.exe -r -t 60; Write-Log "Reboot will occurs in one Minute";break }
                "n" { $fin=$true;Write-Log "User choose not to reboot now"}
                Default {$fin=$false;Write-Host "You should now restart your Computer. Do you want to do it now?(Y/N)"
                $answer = Read-Host}
            }
        } while(!$fin) #>
    }
}

Function Install-Windows2016 {

    Write-Log "Handle Windows Server 2016"

    $restartneeded = $false

    if ($global:EDR) {
        getOMSWorkspaceInfo
    }

    if ($global:EPP) {
        #Install MDAV Server Feature
        try {

            # Test if WDAV is already installed and running
            $WDAVProcess = Get-Process -ProcessName MsMpEng 2> $null
            if ($null -eq $WDAVProcess) {
                Write-Log "Windows Defender is not running, Checking WDAV feature status"
                $WDAVFeature = Get-WindowsFeature -Name "Windows-Defender-Features"
                if ($WDAVFeature.InstallState -ne "Installed") {
                    Write-Log "WDAV Feature is not installed, Installing now..."
                    $WDAVInstall = Install-WindowsFeature -Name "Windows-Defender-Features"
                    if ($WDAVInstall.RestartNeeded -eq "Yes") { $restartneeded = $true }
                }
                else {
                    Write-Log "WDAV feature is installed, check the event viewer to understand why WDAV is not running"
                }
            }
            else {
                Write-Log "Windows Defender is already installed and running"
                Write-Log "Checking security intelligence updates settings"
                $WUSetting = (Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU -Name AUOptions).AUOptions
                if (($WUSetting -eq "3") -or ($WUSetting -eq "4")) {
                    Write-Log "Launching security intelligence updates"
                    Update-MPSignature -UpdateSource MicrosoftUpdateServer
                }

            }
        }
        catch {
            Write-Log "Error installing or updating MDAV" "ERROR"
            Write-Log $_ "ERROR"
        }
    }

    if ($global:EDR) {
        #Install MMA Agent
        downloadAndInstallMMA
    }

    if ($restartneeded) {
        Write-Log "Installation completed. Restart is required" "SUCCESS"
        <#Write-Host "You should now restart your Computer. Do you want to do it now?(Y/N)"
        $answer = Read-Host
        do {
            switch ($answer) {
                "y" { $fin = $true; shutdown.exe -r -t 60; Write-Log "Reboot will occurs in one Minute"; break }
                "n" { $fin = $true; Write-Log "User choose not to reboot now" }
                Default {
                    $fin = $false; Write-Host "You should now restart your Computer. Do you want to do it now?(Y/N)"
                    $answer = Read-Host
                }
            }
        } while (!$fin)#>
    }
}

Function Install-Windows2019 {

    Write-Log "Handle Windows 2019"

    $restartneeded = $false

    if ($global:EPP) {
        #Install MDAV Server Feature
        try {
            # Test if MDAV is already installed and running
            $WDAVProcess = Get-Process -ProcessName MsMpEng 2> $null
            if ($null -eq $WDAVProcess) {
                Write-Log "Windows Defender is not running, Checking WDAV feature status"
                $WDAVFeature = Get-WindowsFeature -Name "Windows-Defender-Features"
                if ($WDAVFeature.InstallState -ne "Installed") {
                    Write-Log "WDAV Feature is not installed, Installing now..."
                    $WDAVInstall = Install-WindowsFeature -Name "Windows-Defender-Features"
                    if ($WDAVInstall.RestartNeeded -eq "Yes") { $restartneeded = $true }
                }
                else {
                    Write-Log "WDAV feature is installed, check the event viewer to understand why WDAV is not running"
                }
            }
            else {
                Write-Log "Windows Defender is already installed and running"
                Write-Log "Checking security intelligence updates settings"
                $WUSetting = (Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU -Name AUOptions).AUOptions
                if (($WUSetting -eq "3") -or ($WUSetting -eq "4")) {
                    Write-Log "Launching security intelligence updates"
                    Update-MPSignature -UpdateSource MicrosoftUpdateServer
                }
            }
        }
        catch {
            Write-Log "Error installing or updating MDAV" "ERROR"
            Write-Log $_ "ERROR"
        }
    }
    if ($global:EDR) {
        #Onboard machine
        try {
            if (Test-Path $global:OnboardingPackage) {
                Write-Log "Onboarding package detected, proceed with onboarding"
                Expand-Archive -Path $global:OnboardingPackage -DestinationPath $global:currentpath -Force
                Start-Process -FilePath ($global:currentpath + "\WindowsDefenderATPLocalOnboardingScript.cmd") -Wait -Verb RunAs
                Write-Log "Onboarding completed" "SUCCESS"
            }
            else {
                Write-Log "Issue finding the onboarding package, make sure you download the file from https://securitycenter.windows.com/preferences2/onboarding and put it in the same folder as the script"
            }
        }
        catch {
            Write-Log "Error while trying to onboard the machine to MDATP" "ERROR"
            Write-Log $_ "ERROR"
            Exit
        }
    }

    if ($restartneeded) {
        Write-Log "Installation completed. Restart is required" "INFO"
        <#  Write-Host "You should now restart your Computer. Do you want to do it now?(Y/N)"
        $answer = Read-Host
        do {
            switch ($answer) {
                "y" { $fin = $true; shutdown.exe -r -t 60; Write-Log "Reboot will occurs in one Minute"; break }
                "n" { $fin = $true; Write-Log "User choose not to reboot now" }
                Default {
                    $fin = $false; Write-Host "You should now restart your Computer. Do you want to do it now?(Y/N)"
                    $answer = Read-Host
                }
            }
        } while (!$fin)#>
    }
}

Function Set-WindowsSecuritySettings {

    # This parameter handles the Attack Surface Reduction, Controlled Folder Access and Network Protection settings mode (Audit or Enabled)
    Param(
        [Parameter(Mandatory = $false)]
        [String]$ProtectionMode = "AuditMode"
    )

    if (!($ProtectionMode -eq "AuditMode" -or $ProtectionMode -eq "Enabled")) {
        Write-Log "Protection Mode parameter for Set-WindowsSecuritySettings function is not AuditMode or Enabled, exiting"
        return
    }

    $Winver = Get-ComputerInfo
    Write-Log "Setting up security features (Antivirus, Attack Surface Reduction Rules, Network Protection, Controlled Folder Access)"
    try {

        #Enable real time monitoring
        Set-MpPreference -DisableRealtimeMonitoring 0

        #Enable behavior monitoring
        Set-MpPreference -DisableBehaviorMonitoring 0

        #Enable IOAV protection
        Set-MpPreference -DisableIOAVProtection 0

        #Enable script scanning
        Set-MpPreference -DisableScriptScanning 0

        #Enable removable drive scanning
        Set-MpPreference -DisableRemovableDriveScanning 0

        #Enable potentially unwanted apps
        Set-MpPreference -PUAProtection $ProtectionMode

        #Enable Email & Archive scan
        Set-MpPreference -DisableArchiveScanning 0
        Set-MpPreference -DisableEmailScanning 0

        #Enable cloud based protection
        Set-MpPreference -MAPSReporting Advanced

        #this is something to be discused with security
        #Enable sample submission"
        Set-MpPreference -SubmitSamplesConsent SendSafeSamples

        #Set cloud protection level to High"
        Set-MpPreference -CloudBlockLevel Default

        #Set cloud timeout to 1 min"
        Set-MpPreference -CloudExtendedTimeout 50

        #Enable block at first sight"
        Set-MpPreference -DisableBlockAtFirstSeen 0

        #this is something to be discused with security
        #Schedule signature updates every 3 hours
        Set-MpPreference -SignatureUpdateInterval 4

        #Enable checking signatures before scanning
        Set-MpPreference -CheckForSignaturesBeforeRunningScan 1

        #LOB apps should be whitelisted
        #Enable ransomware protection"
        Set-MpPreference -EnableControlledFolderAccess $ProtectionMode

        #this is something to be discused with security - same as smartscreen
        #Enable network protection"
        Set-MpPreference -EnableNetworkProtection $ProtectionMode

        #"Increase default protection level"
        #Set-MpPreference -SevereThreatDefaultAction Quarantine
        #Set-MpPreference -HighThreatDefaultAction Quarantine
        #Set-MpPreference -LowThreatDefaultAction Quarantine
        #Set-MpPreference -ModerateThreatDefaultAction Quarantine
        #Set-MpPreference -UnknownThreatDefaultAction Quarantine

        #Enforce File Access protection
        #Set-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows Defender\Policy Manager\' -Name AllowOnAccessProtection -Value 1
        #Set-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\' -Name AllowOnAccessProtection -Value 1

        #Ensure to have notification for Offline scan if needed"
        Set-MpPreference -UILockdown 0
       
        switch ($Winver.WindowsVersion) {

            { $_ -ge "1709" } {
                #Attack Surface Reduction rules, block mode by default, can be changed to Audit if you don't want to be blocked
                Write-Log 'Block all Office applications from creating child processes' 'INFO'; Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions $ProtectionMode
                Write-Log 'Block executable content from email client and webmail' 'INFO'; Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions $ProtectionMode
                Write-Log 'Block execution of potentially obfuscated scripts' 'INFO'; Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions $ProtectionMode
                Write-Log 'Block JavaScript or VBScript from launching downloaded executable content' 'INFO'; Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions $ProtectionMode
                Write-Log 'Block Office applications from creating executable content' 'INFO'; Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions $ProtectionMode
                Write-Log 'Block Office applications from injecting code into other processes' 'INFO'; Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions $ProtectionMode
                Write-Log 'Block Win32 API calls from Office macro' 'INFO'; Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions $ProtectionMode
                Write-Log 'Block credential stealing from the Windows local security authority subsystem (lsass.exe)' 'INFO'; Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions $ProtectionMode
                Write-Log 'Block executable files from running unless they meet a prevalence, age, or trusted list criterion' 'INFO'; Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-cd74-433a-b99e-2ecdc07bfc25 -AttackSurfaceReductionRules_Actions $ProtectionMode
                Write-Log 'Block process creations originating from PSExec and WMI commands' 'INFO'; Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions $ProtectionMode
                Write-Log 'Block untrusted and unsigned processes that run from USB' 'INFO'; Add-MpPreference -AttackSurfaceReductionRules_Ids b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 -AttackSurfaceReductionRules_Actions $ProtectionMode
                Write-Log 'Use advanced protection against ransomware' 'INFO'; Add-MpPreference -AttackSurfaceReductionRules_Ids c1db55ab-c21a-4637-bb3f-a12568109d35 -AttackSurfaceReductionRules_Actions $ProtectionMode
                Write-Log 'Block Adobe Reader from creating child processes' 'INFO'; Add-MpPreference -AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c -AttackSurfaceReductionRules_Actions $ProtectionMode
                Write-Log 'Block Office communication application from creating child processes' 'INFO'; Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49e8-8b27-eb1d0a1ce869 -AttackSurfaceReductionRules_Actions $ProtectionMode
            }

            { $_ -ge "1903" } {
                #New rules for Windows 10 1903
                Write-Log 'Block persistence through WMI event subscription' 'INFO'; Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions $ProtectionMode   
            }

            Default {
                Write-Log ("This Windows version (" + $Winver.WindowsVersion + ") does not support Attack Surface Reduction Rules") "INFO"
            }

        }

        Write-Log "Extracting Windows Defender settings" "INFO"
        Get-MpPreference | Out-File ($global:resultsDir + '\Get-MpPreference.txt')

        Write-Log "Microsoft Defender ATP settings update completed" "SUCCESS"
    }
    catch {
        Write-Log "Error during Windows security settings setup" "ERROR"
        Write-Log $_ "ERROR"
    }
}

Function Add-MachineTag {


    Try {
        if (($null -eq $global:MachineTag) -or ("" -eq $global:MachineTag)) {
            Write-Log "Machine Tag is null" "INFO"
            return
        }
        else {

            Write-Log "Adding machine tag" "INFO"
            New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" -Name "DeviceTagging" -Force | Out-Null
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DeviceTagging\" -Name "Group" -Value $global:MachineTag -PropertyType "String" -Force | Out-Null
            Write-Log "Machine tag added" "SUCCESS"
        }
    }
    catch {
        Write-Log "Error adding a machine tag" "ERROR"
        Write-Log $_ "ERROR"
    }
    
}

Export-ModuleMember -Function Write-Log
Export-ModuleMember -Function Install-Windows7
Export-ModuleMember -Function Install-Windows81
Export-ModuleMember -Function Install-Windows10
Export-ModuleMember -Function Install-Windows2008R2
Export-ModuleMember -Function Install-Windows2012R2
Export-ModuleMember -Function Install-Windows2016
Export-ModuleMember -Function Install-Windows2019
Export-ModuleMember -Function Test-MDATPEICAR
Export-ModuleMember -Function Confirm-MDATPInstallation
Export-ModuleMember -Function Set-WindowsSecuritySettings
Export-ModuleMember -Function Add-MachineTag