#USAGI TOOLS MISC MODULE
#VERSION 1.1.2
#Various Powershell tools designed to serve as either internal functions (labeled as usaverbNoun) Or otherwise misc functions
#Module Event # 1000-1999

function Get-UsaPublicIP{
    <#
    .SYNOPSIS
        Simple script to pull public IP using IPify for Windows PCs
    .PARAMETER Computer
        Runs cmdlet again a remote Windows PC and returns
    .PARAMETER Credential
        PSCredential object to attempt to use to remote to your Computer defined with Computer
    .EXAMPLE
        PS> Get-UsaPublicIP -Computer Srv-DC1.contoso.loc
    .EXAMPLE
        PS> Get-UsaPublicIP -Computer Srv-DC1.Contoso.loc -Credential $(Get-Credential)
    .NOTES
    Version 1.1.0
#>
Param
(
[string]$Computer,
[System.Management.Automation.PSCredential]
[ValidateNotNull()]
$Credential = [System.Management.Automation.PSCredential]::Empty
)
    #Standard use, check to see if the Compuer and credential flags aren't in use then run from local machine
    if(($null -eq $Computer -or $Computer -eq "") -and ($Credential -eq $([System.Management.Automation.PSCredential]::Empty) -or $Credential -eq "") ){
        #Run as a job to force PoSh to make a new session each time to avoid one layer of caching issues
        $JobBase = ((New-Guid).Guid | Out-String).Replace("-","").Substring(0,10)
        Start-Job -Name $("UsaPubIP_" + $JobBase) -ScriptBlock {(Invoke-RestMethod -Uri 'https://api.ipify.org?format=json' -Headers @{"Cache-Control"="no-cache"}).ip} | Out-Null
        Get-Job -Name $("UsaPubIP_" + $JobBase) | Wait-Job | Out-Null
        Get-Job -Name $("UsaPubIP_" + $JobBase) | Receive-Job
    }
    #Run against a Windows Device with the current user credentials
    elseif($null -ne $Computer -and $Credential -eq $([System.Management.Automation.PSCredential]::Empty) ){
        Invoke-Command -ComputerName $Computer -ScriptBlock{
            #Run as a job to force PoSh to make a new session each time to avoid one layer of caching issues
            $JobBase = ((New-Guid).Guid | Out-String).Replace("-","").Substring(0,10)
            Start-Job -Name $("UsaPubIP_" + $JobBase) -ScriptBlock {(Invoke-RestMethod -Uri 'https://api.ipify.org?format=json' -Headers @{"Cache-Control"="no-cache"}).ip} | Out-Null
            Get-Job -Name $("UsaPubIP_" + $JobBase) | Wait-Job | Out-Null
            Get-Job -Name $("UsaPubIP_" + $JobBase) | Receive-Job
        }
    }

    #Run against a Windows Device with arbitrary credentials
    elseif($null -ne $Computer -and $Credential -ne $([System.Management.Automation.PSCredential]::Empty) -and $null -ne $Credential){
        Invoke-Command -ComputerName $Computer -Credential $Credential -ScriptBlock{
            #Run as a job to force PoSh to make a new session each time to avoid one layer of caching issues
            $JobBase = ((New-Guid).Guid | Out-String).Replace("-","").Substring(0,10)
            Start-Job -Name $("UsaPubIP_" + $JobBase) -ScriptBlock {(Invoke-RestMethod -Uri 'https://api.ipify.org?format=json' -Headers @{"Cache-Control"="no-cache"}).ip} | Out-Null
            Get-Job -Name $("UsaPubIP_" + $JobBase) | Wait-Job | Out-Null
            Get-Job -Name $("UsaPubIP_" + $JobBase) | Receive-Job
        }
    }
}


function Connect-UsaOffice365Service{
    <#
    .SYNOPSIS
        Login to all Office 365 Services
    .PARAMETER Interactive
        Forces an Interactive login to allow for MFA to selected Office 365 Services
    .PARAMETER Credential
        Set of NON-MFA Enabled credentials to log into selected Office 365 Service
    .PARAMETER AzureEnvironmentName
        Select Azure Environment to log into. Default is the normal AzureCloud environment, Alternative options are AzureChinaCloud, AzureGermanyCloud, and AzureUSGovernmentCloud. Options will select the same cloud as would be selected with Connect-AzureAD
    .PARAMETER Service
        Select which services to log in to, default logs into all available, only logs into Sharepoint and Sharepoint PNP Libraries if a library is provided. Options AzureAD, ExchangeOnline, MSonline, Sharepoint, SecAndCompCenter, SharepointPNP, Teams
    .PARAMETER SharepointHostName
        Sharepoint root tenant name (IE if your Sharepoint Admin Portal is https://contoso-admin.sharepoint.com enter "contoso"
    .PARAMETER SharepointPNPLibraryURI
        Sharepoint Library URI to log into

    .EXAMPLE
        PS> Connect-UsaOffice365Service -Interactive
    .EXAMPLE
        PS> Connect-UsaOffice365Service -Credential $(Get-Credential)
    .EXAMPLE
        PS> Connect-UsaOffice365Service -Interactive -AzureEnvironmentName AzureGermanyCloud -SharepointHostName contoso-de
    .EXAMPLE
        PS> Connect-UsaOffice365Service -Interactive -Services -SharepointPNPLibraryURI https://contoso.sharepoint.com/sites/AccountingFiles/default.aspx
    .NOTES
    Version 1.0.2
#>

[CmdletBinding(DefaultParameterSetName='noOptions')]
Param
(
    [ValidateSet("AzureAD","ExchangeOnline","MSOnline","SharePoint","SecAndCompCenter","SharePointPnP","Teams")]
    [string[]]
        $Service=("AzureAD","ExchangeOnline","MSOnline","SharePoint","SecAndCompCenter","SharePointPnP","Teams"),
    [ValidateSet("AzureCloud","AzureChinaCloud","AzureGermanyCloud","AzureUSGovernment")]
    [string[]]
        $AzureEnvironmentName = "AzureCloud",

    [System.Management.Automation.PSCredential]
    [ValidateNotNull()]
    [Parameter(ParameterSetName='PSCredentialLogin')]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

    [Parameter(ParameterSetName='InteractiveLogin')]
    [Switch]
        $Interactive,

    [String]$SharepointHostName,
    [String]$SharepointPNPLibraryURI
)
Begin{
    if($PSCmdlet.ParameterSetName -eq 'noOptions'){
    throw "Please input non MFA credentials via -credential or perform and Interactive/MFA Login with -Interacitve"
    return
    }
}
Process{
#Set TLS 1.2 for login for session
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    #Cycle through services and log in if they're in the Services variable

    #Azure AD
        if($Service -contains "AzureAD"){
            $ModImport = $null

            #Check if the required module is imported and if not install it
            do{
                $ModImport = usamoduleimport -modulerequested "AzureAD" -moduleset O365
            }
            until($ModImport -le 1)

            usawritelog -LogLevel SuccessAudit -EventID 0 -Message "Attempting AzureAD Login"
            if($ModImport -eq 1){
            #If usamoduleimport returns 1 we've successfully imported
                if($Interactive -eq $false -or $null -eq $Interactive){
                    Connect-AzureAD -Credential $Credential -AzureEnvironmentName $AzureEnvironmentName
                    }
                else{
                    Connect-AzureAD -AzureEnvironmentName $AzureEnvironmentName
                }
            }
            if($ModImport -eq 0){
                usawritelog -LogLevel Warning -EventID 1001 -Message "Please try installing the AzureAD Module later."
            }
        }

    #Exchange Online
        if($Service -contains "ExchangeOnline"){
            $ModImport = $null

            #Check if the required module is imported and if not install it
            do{
                $ModImport = usamoduleimport -modulerequested "ExchangeOnlineManagement"  -moduleset O365
            }
            until($ModImport -le 1)

            usawritelog -LogLevel SuccessAudit -EventID 0 -Message "Attempting Exchange Online Login"
            if($ModImport -eq 1){
            #If usamoduleimport returns 1 we've successfully imported
                if($Interactive -eq $false -or $null -eq $Interactive){
                    if($AzureEnvironmentName -eq "AzureCloud"){
                        Connect-ExchangeOnline -Credential $Credential
                        }
                    if($AzureEnvironmentName -eq "AzureChinaCloud"){
                        Connect-ExchangeOnline -Credential $Credential -ExchangeEnvironmentName O365China
                        }
                    if($AzureEnvironmentName -eq "AzureGermanyCloud"){
                        Connect-ExchangeOnline -Credential $Credential -ExchangeEnvironmentName O365GermanyCloud
                        }
                    if($AzureEnvironmentName -eq "AzureUSGovernment"){
                        Connect-ExchangeOnline -Credential $Credential -ExchangeEnvironmentName O365USGovGCCHigh
                        }
                    }
                else{
                    if($AzureEnvironmentName -eq "AzureCloud"){
                        Connect-ExchangeOnline
                        }
                    if($AzureEnvironmentName -eq "AzureChinaCloud"){
                        Connect-ExchangeOnline -ExchangeEnvironmentName O365China
                        }
                    if($AzureEnvironmentName -eq "AzureGermanyCloud"){
                        Connect-ExchangeOnline -ExchangeEnvironmentName O365GermanyCloud
                        }
                    if($AzureEnvironmentName -eq "AzureUSGovernment"){
                        Connect-ExchangeOnline -ExchangeEnvironmentName O365USGovGCCHigh
                    }
                }
            if($ModImport -eq 0){
                usawritelog -LogLevel Warning -EventID 1001 -Message  "Please try installing the ExchangeOnlineManagement Module later."
                }
            }
        }

    #MSOnline
        if($Service -contains "MSOnline"){
            $ModImport = $null

            #Check if the required module is imported and if not install it
            do{
                $ModImport = usamoduleimport -modulerequested "MSOnline" -moduleset O365
            }
            until($ModImport -le 1)

            usawritelog -LogLevel SuccessAudit -EventID 0 -Message "Attempting MSOL Login"
            if($ModImport -eq 1){
            #If usamoduleimport returns 1 we've successfully imported

                if($Interactive -eq $false -or $null -eq $Interactive){
                    Connect-MsolService -Credential $Credential -AzureEnvironment $AzureEnvironmentName
                    }
                else{
                    Connect-MsolService -AzureEnvironment $AzureEnvironmentName
                    }
                }
            if($ModImport -eq 0){
                usawritelog -LogLevel Warning -EventID 1002 -Message "Please try installing the MSOnline Module later."
            }
        }

    #Sharepoint Admin
        if($Service -contains "SharePoint" -and $null -ne $SharepointHostName -and $SharepointHostName -ne ""){
            $ModImport = $null

            #Check if the required module is imported and if not install it
            do{
                $ModImport = usamoduleimport -modulerequested "Microsoft.Online.SharePoint.PowerShell" -moduleset O365
            }
            until($ModImport -le 1)

            usawritelog -LogLevel SuccessAudit -EventID 0 -Message "Attempting Sharepoint Login"

            if($ModImport -eq 1){

            #If usamoduleimport returns 1 we've successfully imported
                if($Interactive -eq $false -or $null -eq $Interactive){
                    if($AzureEnvironmentName -eq "AzureCloud"){
                        Connect-SPOService -Url https://$SharepointHostName-admin.sharepoint.com -Credential $Credential -region default
                        }
                    if($AzureEnvironmentName -eq "AzureChinaCloud"){
                        Connect-SPOService -Url https://$SharepointHostName-admin.sharepoint.com -Credential $Credential -region China
                        }
                    if($AzureEnvironmentName -eq "AzureGermanyCloud"){
                        Connect-SPOService -Url https://$SharepointHostName-admin.sharepoint.com -Credential $Credential -region Germany
                        }
                    if($AzureEnvironmentName -eq "AzureUSGovernment"){
                        Connect-SPOService -Url https://$SharepointHostName-admin.sharepoint.com -Credential $Credential -region ITAR
                        }
                    }
                else{
                    if($AzureEnvironmentName -eq "AzureCloud"){
                        Connect-SPOService -Url https://$SharepointHostName-admin.sharepoint.com -region default
                        }
                    if($AzureEnvironmentName -eq "AzureChinaCloud"){
                        Connect-SPOService -Url https://$SharepointHostName-admin.sharepoint.com -region China
                        }
                    if($AzureEnvironmentName -eq "AzureGermanyCloud"){
                        Connect-SPOService -Url https://$SharepointHostName-admin.sharepoint.com -region Germany
                        }
                    if($AzureEnvironmentName -eq "AzureUSGovernment"){
                        Connect-SPOService -Url https://$SharepointHostName-admin.sharepoint.com -region ITAR
                        }

                }
            if($ModImport -eq 0){
                usawritelog -LogLevel Warning -EventID 1003 -Message "Please try installing the SharePoint Module later."
                }
            }
        }

    #SharepointPNP
        if($Service -contains "SharePointPnP" -and $null -ne $SharepointPNPLibraryURI -and $SharepointPNPLibraryURI -ne ""){
            $ModImport = $null

            #Check if the required module is imported and if not install it
            do{$ModImport = usamoduleimport -modulerequested "PnP.Powershell" -moduleset O365}
            until($ModImport -le 1)

            usawritelog -LogLevel SuccessAudit -EventID 0 -Message "Attempting Sharepoint PNP Login to $SharepointPNPLibraryURI"

            if($ModImport -eq 1){
            #Check if the required module is imported and if not install it
                if($Interactive -eq $false -or $null -eq $Interactive){
                    if($AzureEnvironmentName -eq "AzureCloud"){
                        Connect-PnPOnline -Url $SharepointPNPLibraryURI -Credential $Credential -region Production
                        }
                    if($AzureEnvironmentName -eq "AzureChinaCloud"){
                        Connect-PnPOnline -Url $SharepointPNPLibraryURI -Credential $Credential -region China
                        }
                    if($AzureEnvironmentName -eq "AzureGermanyCloud"){
                        Connect-PnPOnline -Url $SharepointPNPLibraryURI -Credential $Credential -region Germany
                        }
                    if($AzureEnvironmentName -eq "AzureUSGovernment"){
                        Connect-PnPOnline -Url $SharepointPNPLibraryURI -Credential $Credential -region USGovernmentHigh
                        }
                    }
                else{
                    if($AzureEnvironmentName -eq "AzureCloud"){
                        Connect-PnPOnline -Url $SharepointPNPLibraryURI -SPOManagementShell -region Production
                        }
                    if($AzureEnvironmentName -eq "AzureChinaCloud"){
                        Connect-PnPOnline -Url $SharepointPNPLibraryURI -SPOManagementShell -region China
                        }
                    if($AzureEnvironmentName -eq "AzureGermanyCloud"){
                        Connect-PnPOnline -Url $SharepointPNPLibraryURI -SPOManagementShell -region Germany
                        }
                    if($AzureEnvironmentName -eq "AzureUSGovernment"){
                        Connect-PnPOnline -Url $SharepointPNPLibraryURI -SPOManagementShell -region USGovernmentHigh
                        }
                }
            if($ModImport -eq 0){
                usawritelog -LogLevel SuccessAudit -EventID 1004 -Message  "Please try installing the SharePointPnP Module later."
                }
            }
        }
        if($Service -contains "SecAndCompCenter"){
            $ModImport = $null

            #Check if the required module is imported and if not install it
            do{
               $ModImport = usamoduleimport -modulerequested "ExchangeOnlineManagement"  -moduleset O365
            }
            until($ModImport -le 1)

            usawritelog -LogLevel SuccessAudit -EventID 0 -Message "Attempting Security and Compliance Center Login"
            if($ModImport -eq 1){
            #Check if the required module is imported and if not install it
                if($Interactive -eq $false -or $null -eq $Interactive){
                    if($AzureEnvironmentName -eq "AzureCloud"){
                        Connect-IPPSSession -Credential $Credential
                        }
                    if($AzureEnvironmentName -eq "AzureChinaCloud"){
                        Connect-IPPSSession  -Credential $Credential -ConnectionUri "https://ps.compliance.protection.partner.outlook.cn/powershell-liveid"
                        }
                    if($AzureEnvironmentName -eq "AzureGermanyCloud"){
                        Connect-IPPSSession  -Credential $Credential -ConnectionUri "https://ps.compliance.protection.outlook.de/PowerShell-LiveID"
                        }
                    if($AzureEnvironmentName -eq "AzureUSGovernment"){
                        Connect-IPPSSession  -Credential $Credential -ConnectionUri "https://ps.compliance.protection.office365.us/powershell-liveid/"
                        }
                    }
                else{
                    if($AzureEnvironmentName -eq "AzureCloud"){
                        Connect-IPPSSession
                        }
                    if($AzureEnvironmentName -eq "AzureChinaCloud"){
                        Connect-IPPSSession  -ConnectionUri "https://ps.compliance.protection.partner.outlook.cn/powershell-liveid"
                        }
                    if($AzureEnvironmentName -eq "AzureGermanyCloud"){
                        Connect-IPPSSession  -ConnectionUri "https://ps.compliance.protection.outlook.de/PowerShell-LiveID"
                        }
                    if($AzureEnvironmentName -eq "AzureUSGovernment"){
                        Connect-IPPSSession  -ConnectionUri "https://ps.compliance.protection.office365.us/powershell-liveid/"
                    }
                }
            if($ModImport -eq 0){
                usawritelog -LogLevel Warning -EventID 1001 -Message  "Please try installing the ExchangeOnlineManagement Module later."
                }
            }
        }

    #Teams Login
        if($Service -contains "Teams"){
            $ModImport = $null

            #Check if the required module is imported and if not install it
            do{$ModImport = usamoduleimport -modulerequested "MicrosoftTeams" -moduleset O365}
            until($ModImport -le 1)
            usawritelog -LogLevel SuccessAudit -EventID 0 -Message "Attempting Teams Login"
            if($ModImport -eq 1){

            #Check if the required module is imported and if not install it
                if($Interactive -eq $false -or $null -eq $Interactive){

                    if($AzureEnvironmentName -eq "AzureCloud"){
                        Connect-MicrosoftTeams -Credential $Credential
                        }
                    if($AzureEnvironmentName -eq "AzureChinaCloud"){
                        Connect-MicrosoftTeams -Credential $Credential -TeamsEnvironmentName TeamsChina
                        }
                    if($AzureEnvironmentName -eq "AzureGermanyCloud"){
                        usawritelog -LogLevel Warning -EventID 1010 -Message "Cannot connect to Teams in AzureGermanyCloud as no tenant exists, see https://learn.microsoft.com/en-us/powershell/module/teams/connect-microsoftteams?view=teams-ps#-teamsenvironmentname for more info"
                        }
                    if($AzureEnvironmentName -eq "AzureUSGovernment"){
                        Connect-MicrosoftTeams -Credential $Credential -TeamsEnvironmentName TeamsGCCH
                        }
                    }
                else{
                    if($AzureEnvironmentName -eq "AzureCloud"){
                        Connect-MicrosoftTeams
                        }
                    if($AzureEnvironmentName -eq "AzureChinaCloud"){
                        Connect-MicrosoftTeams -TeamsEnvironmentName TeamsChina
                        }
                    if($AzureEnvironmentName -eq "AzureGermanyCloud"){
                        usawritelog -LogLevel Warning -EventID 1010 -Message "Cannot connect to Teams in AzureGermanyCloud as no tenant exists, see https://learn.microsoft.com/en-us/powershell/module/teams/connect-microsoftteams?view=teams-ps#-teamsenvironmentname for more info"
                        }
                    if($AzureEnvironmentName -eq "AzureUSGovernment"){
                        Connect-MicrosoftTeams -TeamsEnvironmentName TeamsGCCH
                        }
                }
            }

            if($ModImport -eq 0){
                usawritelog -LogLevel Warning -EventID 1005 -Message   "Please try installing the MicrosoftTeams Module later."
                }
            }
    }
}



function Install-UsaOffice365Module{
    <#
    .SYNOPSIS
        Installs access to Office 365 Modules
    .PARAMETER Module
        Select which services to install modules for, defaults to AzureAD, ExchangeOnline, MSonline, Sharepoint, SharepointPNP, Teams
    .PARAMETER Update
        Run Updates on selected Modules

    .EXAMPLE
        PS> Install-UsaOffice365Module
    .EXAMPLE
        PS> Install-UsaOffice365Module -Module AzureAD
    .EXAMPLE
        PS> Install-UsaOffice365Module -Module AzureAD -Update
    .NOTES
     Version 1.0.2
#>


Param
(
    [ValidateSet("AzureAD","ExchangeOnline","MSOnline","SharePoint","SharePointPnP","Teams")]
    [string[]]$Module=("AzureAD","ExchangeOnline","MSOnline","SharePoint","SharePointPnP","Teams"),
    [switch]$Update
)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$IsAdmin = Test-UsaAdministrator

if($Module -contains "AzureAD"){
    usainstallModule -modulerequested "AzureAD" -doupdate $Update
}
if($Module -contains "ExchangeOnline"){
    usainstallModule -modulerequested "ExchangeOnlineManagement" -doupdate $Update
}
if($Module -contains "MSOnline"){
    usainstallModule -modulerequested "MSOnline" -doupdate $Update
}

if($Module -contains "SharePoint"){
    usainstallModule -modulerequested "Microsoft.Online.SharePoint.PowerShell" -doupdate $Update
}
if($Module -contains "SharePointPnP"){
    $PNPinstalled = Get-Module "PnP.PowerShell"
    if($null -eq $PNPinstalled -or $PNPinstalled -eq ""){
        if($IsAdmin -eq $True){
            Install-Module -Name "PnP.PowerShell" -RequiredVersion 1.12.0 -Force -AllowClobber
        }
        if($IsAdmin -eq $False){
            Install-Module -Name "PnP.PowerShell" -RequiredVersion 1.12.0 -Force -AllowClobber -Scope CurrentUser
        }
    }
    if($null -ne $PNPinstalled -and $PNPinstalled -ne "" -and $Update -eq $true){
        Update-Module "PnP.PowerShell" -RequiredVersion 1.12.0
    }
    if($null -ne $PNPinstalled -and $PNPinstalled -ne ""){
        usawritelog -LogLevel SuccessAudit -EventID 0 -Message "SharePointPnP Module already installed, Skipping"
    }
}
if($Module -contains "Teams"){
    usainstallModule -modulerequested "MicrosoftTeams" -doupdate $Update
    }
}


function Test-UsaAdministrator  {
    <#
    .SYNOPSIS
        Simple script to test if the current user is Admin, returns $true if the user is an admin
    .EXAMPLE
        PS> Test-UsaAdministrator
    .NOTES
      Version 1.0.1
#>
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Test-UsaNetwork{
    <#
    .SYNOPSIS
        Pings multiple in the environment to path test
    .PARAMETER Count
        How many times to run test, do Unlimited for a continuous ping
    .PARAMETER SourceIP
        Provides a source IP to run tests against
    .PARAMETER Internal
        Internal hosts to ping
    .PARAMETER External
        External targets to ping
    .PARAMETER Gateway
        Internal Gateway to ping, defaults to current interface gateway
    .PARAMETER DNS
        DNS Servers to hit and test
    .EXAMPLE
        PS> Test-UsaNetwork
    .EXAMPLE
        PS> Test-UsaNetwork -Internal 10.0.0.3,10.0.0.4:443,web,web:8080 -External google.com,microsoft.com,lifehacker.com:443,34.34.34.34
    .EXAMPLE
        PS> Test-UsaNetwork -Gateway 10.0.0.1 -DNS 10.0.0.20,10.0.0.21
    .NOTES
     Version 1.0.1
#>

    Param
    (
    [int]$Count,
    $Internal  = @(),
    $External  = @(),
    [ipaddress]$Source,
    $Gateway   = @(),
    $DNS       = @(),
    [Switch]$SecureDNS
    )

    function addtoTable{
        Param
            (
                [string]$Hostname,
                [ipaddress]$IP,
                [string]$Port,
                [int]$Success,
                [int]$Failure,
                [string]$RTT,
                [string]$AddType
            )
            $TableRow =New-Object PSObject
            $TableRow | Add-Member  -Type NoteProperty -Name "Hostname" -Value $Hostname
            $TableRow | Add-Member  -Type NoteProperty -Name "IP" -Value $IP
            $TableRow | Add-Member  -Type NoteProperty -Name "Port" -Value $Port
            $TableRow | Add-Member  -Type NoteProperty -Name "Success" -Value $Success
            $TableRow | Add-Member  -Type NoteProperty -Name "Failure" -Value $Failure
            $TableRow | Add-Member  -Type NoteProperty -Name "RTTinMS" -Value $RTT
            $TableRow | Add-Member  -Type NoteProperty -Name "AddType" -Value $AddType
            $TableRow | Add-Member  -Type NoteProperty -Name "ID" -Value $ID
            return $TableRow
    }

    #Get base info on SourceIP
    if($null -ne $Source -and $Source -notlike ""){
        $SourceAddress = $Source
    }
    else{
            $SourceAddress = (Test-NetConnection).SourceAddress.IPAddress
    }

    if($null -eq $SourceAddress){
            usawritelog -LogLevel Error -EventID 1021 -Category ConnectionError -Message "ERROR: Cannot automatically set Source address, please select a Source Address and rerun" -RecommendedAction "Rerun with a -Source $IP where IP is a valid address for a local network adapter to ping from"
            break
    }
    #Build a default object for internal paths to test against
    $Adapter = Get-NetIPConfiguration | Where-Object {$_.IPv4Address.IPAddress -like $SourceAddress}
    
    if($null -eq $Adapter){
            usawritelog -LogLevel Error -EventID 1022 -Category ConnectionError -Message $("ERROR: Cannot locate Adapter with source address " + $SourceAddress + " Please rerun with valid source address") -RecommendedAction "Rerun with a -Source $IP where IP is a valid address for a local network adapter to ping from"
            break
    }

    #Check Gateway object, if none provided use source object
    if($null -ne $Gateway -and $Gateway -notlike ""){
        $GWIP = $Gateway
    }
    else{
        $GWIP = $Adapter.IPv4DefaultGateway.NextHop
    }
    #Check DNS Objects are provided and use default adapter if not
    if($null -ne $DNS -and $DNS -notlike ""){
        $DNSIP = $DNS
    }
    else{
        $DNSIP = $Adapter.DNSServer.ServerAddresses
    }

    #Clean Internal Addresses
    $Int = $Internal | ForEach-Object {usacheckNetname $_}
    #Clean External Addresses
    $Ext = $External | ForEach-Object {usacheckNetname $_}

    usawritelog -LogLevel SuccessAudit -EventID 0 -Message "Gathering network info, please wait..."
    #Create base table object
    $BaseTable  =  @()
    $Success = 0
    $Failure = 0
    $ID = 0

    #Add Gateway
    $GWIP | ForEach-Object{
        $ID++
        $TRow = addtoTable -Hostname $(Resolve-DnsName $_ -ErrorAction SilentlyContinue).NameHost -IP $_ -Port "ICMP" -Success $Success -Failure $Failure -RTT "Null" -AddType "DefaultGateway" -ID $ID
        $BaseTable += $TRow
    }
    #Add DNS
    $DNSIP | ForEach-Object{
        $ID++
        $TRow = addtoTable -Hostname $(Resolve-DnsName $_ -ErrorAction SilentlyContinue).NameHost -IP $_ -Port "ICMP" -Success $Success -Failure $Failure -RTT "Null" -AddType "DNS" -ID $ID
        $BaseTable += $TRow

        $ID++
        $TRow = addtoTable -Hostname $(Resolve-DnsName $_ -ErrorAction SilentlyContinue).NameHost -IP $_ -Port "53" -Success $Success -Failure $Failure -RTT "Null" -AddType "DNS" -ID $ID
        $BaseTable += $TRow

        if($SecureDNS -eq $true){
            $ID++
            $TRow = addtoTable -Hostname $(Resolve-DnsName $_ -ErrorAction SilentlyContinue).NameHost -IP $_ -Port "853" -Success $Success -Failure $Failure -RTT "Null" -AddType "DNS" -ID $ID
            $BaseTable += $TRow

        }
    }

    #Add Internal Devices
    ForEach ($Device in $Int){
        $ID++
        switch($Device.Type){
            DNSName {
                $TRow = addtoTable -Hostname $Device.Address -IP $((Test-NetConnection $Device.Address -ErrorAction SilentlyContinue).IPV4Address.IPAddressToString |Sort-Object -Unique) -Port $Device.Port -Success $Success -Failure $Failure -RTT "Null" -AddType $("Internal"+$Device.Type) -ID $ID
                $BaseTable += $TRow
            }
            IP {
                $TRow = addtoTable -Hostname $(Resolve-DnsName $Device.Address -DnsOnly -ErrorAction SilentlyContinue).NameHost -IP $Device.Address -Port $Device.Port -Success $Success -Failure $Failure -RTT "Null" -AddType $("Internal"+$Device.Type) -ID $ID
                $BaseTable += $TRow

            }
        }
    }

    #Add External Devices
    ForEach ($Device in $Ext){
        $ID++
        switch($Device.Type){
            DNSName {
                $TRow = addtoTable -Hostname $Device.Address -IP $((Test-NetConnection $Device.Address).IPV4Address.IPAddressToString |Sort-Object -Unique) -Port $Device.Port -Success $Success -Failure $Failure -RTT "Null" -AddType $("External"+$Device.Type) -ID $ID += $BaseTable
                $BaseTable += $TRow
            }
            IP {
                $TRow = addtoTable -Hostname $(Resolve-DnsName $Device.Address -DnsOnly -ErrorAction SilentlyContinue).NameHost -IP $Device.Address -Port $Device.Port -Success $Success -Failure $Failure -RTT "Null" -AddType $("External"+$Device.Type) -ID $ID += $BaseTable
                $BaseTable += $TRow
            }
        }
    }

    #Test all IPs via Jobs
    $Upcount = 0

    Do{
    $Start = "Testing network connections via Interface " + $Adapter.InterfaceAlias + " with Index of " + $Adapter.InterfaceIndex + " And IP(s), of " + $($Adapter.IPv4Address.IpAddress -join " , ")
    $origpos = $host.UI.RawUI.CursorPosition
    $Start
    $BaseTable | Format-Table -AutoSize | Out-String | ForEach-Object {Write-Output $_}
    $JobBase = ((New-Guid).Guid | Out-String).Replace("-","").Substring(0,10)
    ForEach ($Row in $BaseTable){
        if($Row.Port -eq -1){$Row.Port = "ICMP"}
        switch($Row.AddType){
        DefaultGateway {
            if($null -eq $Row.Hostname -or $Row.Hostname -like ""){
                $Row.Hostname = (Resolve-DnsName $Row.IP -ErrorAction SilentlyContinue).NameHost
            }
            Start-Job -Name $("Usa-" + $Row.ID + "_" + $JobBase) -ScriptBlock {
                $function:usaPing = $using:function:usaPing
                $SourceAddress = $using:SourceAddress
                $Row = $using:Row
                usaPing -Source $SourceAddress -Destination $Row.IP -ErrorAction SilentlyContinue
            } | Out-Null
        }
        DNS{
            if($Row.Port -eq "ICMP"){
                Start-Job -Name $("Usa-" + $Row.ID + "_" + $JobBase) -ScriptBlock {
                    $function:usaPing = $using:function:usaPing
                    $SourceAddress = $using:SourceAddress
                    $Row = $using:Row
                    usaPing -Source $SourceAddress -Destination $Row.IP -ErrorAction SilentlyContinue
                } | Out-Null
            }
            if($Row.Port -ne "ICMP" -and $Row.Port -ne -1){
                Start-Job -Name $("Usa-" + $Row.ID + "_" + $JobBase) -ScriptBlock {
                    $function:usaPing = $using:function:usaPing
                    $SourceAddress = $using:SourceAddress
                    $Row = $using:Row
                    usaPing -Source $SourceAddress -Destination $Row.IP -Port $Row.Port -ErrorAction SilentlyContinue
                } | Out-Null
            }
        }
        InternalDNSName{
            if($null -eq $Row.IP -or $Row.IP -like ""){
                [IPAddress]$Row.IP = (Test-NetConnection -ComputerName $Row.HostName -ErrorAction SilentlyContinue).RemoteAddress.IPAddressToString
            }
            if($Row.Port -eq "ICMP"){
                Start-Job -Name $("Usa-" + $Row.ID + "_" + $JobBase) -ScriptBlock {
                    $function:usaPing = $using:function:usaPing
                    $SourceAddress = $using:SourceAddress
                    $Row = $using:Row
                    usaPing -Source $SourceAddress -Destination $Row.IP -ErrorAction SilentlyContinue
                } | Out-Null
            }
            if($Row.Port -ne -1 -and $Row.Port -ne "ICMP"){
                Start-Job -Name $("Usa-" + $Row.ID + "_" + $JobBase) -ScriptBlock {
                    $function:usaPing = $using:function:usaPing
                    $SourceAddress = $using:SourceAddress
                    $Row = $using:Row
                    usaPing -Source $SourceAddress -Destination $Row.IP -Port $Row.Port -ErrorAction SilentlyContinue
                } | Out-Null
            }
        }
        InternalIP{
            if($null -eq $Row.Hostname -or $Row.Hostname -like ""){
                $Row.Hostname = (Resolve-DnsName $Row.IP -DnsOnly -ErrorAction SilentlyContinue).NameHost
            }
            if($Row.Port -eq "ICMP"){
                Start-Job -Name $("Usa-" + $Row.ID + "_" + $JobBase) -ScriptBlock {
                    $function:usaPing = $using:function:usaPing
                    $SourceAddress = $using:SourceAddress
                    $Row = $using:Row
                    usaPing -Source $SourceAddress -Destination $Row.IP -ErrorAction SilentlyContinue
                } | Out-Null
            }
            if($Row.Port -ne -1 -and $Row.Port -ne "ICMP"){
                Start-Job -Name $("Usa-" + $Row.ID + "_" + $JobBase) -ScriptBlock {
                    $function:usaPing = $using:function:usaPing
                    $SourceAddress = $using:SourceAddress
                    $Row = $using:Row
                    usaPing -Source $SourceAddress -Destination $Row.IP -Port $Row.Port -ErrorAction SilentlyContinue
                }| Out-Null
            }
        }
        ExternalDNSName{
            if($null -eq $Row.IP -or $Row.IP -like ""){
                [IPAddress]$Row.IP = (Test-NetConnection -ComputerName $Row.HostName -ErrorAction SilentlyContinue).RemoteAddress.IPAddressToString
            }
            if($Row.Port -eq "ICMP" -and $null -ne $Row.IP){
                Start-Job -Name $("Usa-" + $Row.ID + "_" + $JobBase) -ScriptBlock {
                    $function:usaPing = $using:function:usaPing
                    $SourceAddress = $using:SourceAddress
                    $Row = $using:Row
                    usaPing -Source $SourceAddress -Destination $Row.IP -ErrorAction SilentlyContinue
                } | Out-Null
            }
            if($Row.Port -ne -1 -and $Row.Port -ne "ICMP"){
                Start-Job -Name $("Usa-" + $Row.ID + "_" + $JobBase) -ScriptBlock {
                    $function:usaPing = $using:function:usaPing
                    $SourceAddress = $using:SourceAddress
                    $Row = $using:Row
                    usaPing -Source $SourceAddress -Destination $Row.IP -Port $Row.Port -ErrorAction SilentlyContinue
                } | Out-Null
            }
        }
        ExternalIP{
            if($null -eq $Row.Hostname -or $Row.Hostname -like ""){
                $Row.Hostname = (Resolve-DnsName $Row.IP -DnsOnly -ErrorAction SilentlyContinue).NameHost
            }
            if($Row.Port -eq "ICMP"){
                Start-Job -Name $("Usa-" + $Row.ID + "_" + $JobBase) -ScriptBlock {
                    $function:usaPing = $using:function:usaPing
                    $SourceAddress = $using:SourceAddress
                    $Row = $using:Row
                    usaPing -Source $SourceAddress -Destination $Row.IP -ErrorAction SilentlyContinue
                } | Out-Null
            }
            if($Row.Port -ne -1 -and $Row.Port -ne "ICMP"){
                Start-Job -Name $("Usa-" + $Row.ID + "_" + $JobBase) -ScriptBlock {
                    $function:usaPing = $using:function:usaPing
                    $SourceAddress = $using:SourceAddress
                    $Row = $using:Row
                    usaPing -Source $SourceAddress -Destination $Row.IP -Port $Row.Port -ErrorAction SilentlyContinue
                } | Out-Null
            }
        }


        }
}
    #Wait for jobs to complete
    Start-Sleep -s 5
    #Pull Jobs and update table
    ForEach ($Row in $BaseTable){
        if($null -ne $Row.IP){
            $Job = Get-Job -Name $("Usa-" + $Row.ID + "_" + $JobBase) | Receive-Job
            if($Job.Connected -eq $true){
                $Row.Success ++
                $Row.RTTinMS = $Job.RTT
            }

            if($Job.Connected -eq $false){
                $Row.Failure ++
            }
            Get-Job -Name $("Usa-" + $Row.ID + "_" + $JobBase) | Remove-Job
        }
    }

    $host.UI.RawUI.CursorPosition = $origpos


    $UpCount ++
    }until($Upcount -eq $Count )
    usawritelog -LogLevel Information -EventID 1020 -Message $($Start + "`n" + $BaseTable)
}
