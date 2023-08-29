#USAGI TOOLS MISC MODULE
#VERSION 0.3.0
#Various Powershell tools designed to serve as either internal functions (labeled as usaverbNoun) Or otherwise misc functions

function Get-UsaPublicIP{
    <#
    .SYNOPSIS
        Simple script to pull public IP using IPify for Windows PCs
    .PARAMETER Computer
        Runs cmdlet again a remote Windows PC and returns
    .EXAMPLE
        PS> Get-UsaPublicIP -Computer Srv-DC1.contoso.loc
    .EXAMPLE
        PS> Get-UsaPublicIP -Computer Srv-DC1.Contoso.loc -Credential $(Get-Credential) 
    .VERSION
    1.0.0
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
    (Invoke-WebRequest http://api.ipify.org -UseBasicParsing).content}

#Run against a Windows Device with the current user credentials
elseif($null -ne $Computer -and $Credential -eq $([System.Management.Automation.PSCredential]::Empty) ){
    Invoke-Command -ComputerName $Computer -ScriptBlock{
        (Invoke-WebRequest http://api.ipify.org -UseBasicParsing).content} 
        }

#Run against a Windows Device with arbitrary credentials
elseif($null -ne $Computer -and $Credential -ne $([System.Management.Automation.PSCredential]::Empty) -and $null -ne $Credential){
    Invoke-Command -ComputerName $Computer -Credential $Credential -ScriptBlock{
       (Invoke-WebRequest http://api.ipify.org -UseBasicParsing).content} 
        }

}


function Login-UsaOffice365Services{
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
        PS> Login-UsaOffice365Services -Interactive
    .EXAMPLE
        PS> Login-UsaOffice365Services -Credential $(Get-Credential)
    .EXAMPLE
        PS> Login-UsaOffice365Services -Interactive -AzureEnvironmentName AzureGermanyCloud -SharepointHostName contoso-de
    .EXAMPLE
        PS> Login-UsaOffice365Services -Interactive -Services -SharepointPNPLibraryURI https://contoso.sharepoint.com/sites/AccountingFiles/default.aspx
    .VERSION
    1.0.0
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
            do{$ModImport = usamoduleimport -modulerequested "AzureAD" -moduleset O365}
            until($ModImport -le 1)

            Write-host "Attempting AzureAD Login"
            if($ModImport -eq 1){
            #If usamoduleimport returns 1 we've successfully imported
                if($Interactive -eq $false -or $null -eq $Interactive){
                    Connect-AzureAD -Credential $Credential -AzureEnvironmentName $AzureEnvironmentName
                    }
                else{
                    Connect-AzureAD -AzureEnvironmentName $AzureEnvironmentName
                    }
                }
            elseif($ModImport -eq 0){
                Write-Host "Please try installing the AzureAD Module later."
                }
            }

    #Exchange Online
        if($Service -contains "ExchangeOnline"){        
            $ModImport = $null

            #Check if the required module is imported and if not install it
            do{$ModImport = usamoduleimport -modulerequested "ExchangeOnlineManagement"  -moduleset O365}
            until($ModImport -le 1)

            Write-host "Attempting Exchange Online Login"
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
                Write-Host "Please try installing the ExchangeOnlineManagement Module later."
                }
            }
        }

    #MSOnline
        if($Service -contains "MSOnline"){
            $ModImport = $null

            #Check if the required module is imported and if not install it
            do{$ModImport = usamoduleimport -modulerequested "MSOnline" -moduleset O365}
            until($ModImport -le 1)

            Write-host "Attempting MSOL Login"
            if($ModImport -eq 1){
            #If usamoduleimport returns 1 we've successfully imported

                if($Interactive -eq $false -or $null -eq $Interactive){
                    Connect-MsolService -Credential $Credential -AzureEnvironment $AzureEnvironmentName
                    }
                else{
                    Connect-MsolService -AzureEnvironment $AzureEnvironmentName
                    }
                }
            elseif($ModImport -eq 0){
                Write-Host "Please try installing the MSOnline Module later."
                }
            }

    #Sharepoint Admin
        if($Service -contains "SharePoint" -and $null -ne $SharepointHostName -and $SharepointHostName -ne ""){
            $ModImport = $null

            #Check if the required module is imported and if not install it
            do{$ModImport = usamoduleimport -modulerequested "Microsoft.Online.SharePoint.PowerShell" -moduleset O365}
            until($ModImport -le 1)

            Write-host "Attempting Sharepoint Login"

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
                Write-Host "Please try installing the SharePoint Module later."
                }
            }
        }

    #SharepointPNP
        if($Service -contains "SharePointPnP" -and $null -ne $SharepointPNPLibraryURI -and $SharepointPNPLibraryURI -ne ""){
            $ModImport = $null

            #Check if the required module is imported and if not install it
            do{$ModImport = usamoduleimport -modulerequested "PnP.Powershell" -moduleset O365}
            until($ModImport -le 1)

            Write-host "Attempting Sharepoint PNP Login to $SharepointPNPLibraryURI"

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
                Write-Host "Please try installing the SharePointPnP Module later."
                }
            }
        }
        if($Service -contains "SecAndCompCenter"){        
            $ModImport = $null

            #Check if the required module is imported and if not install it
            do{$ModImport = usamoduleimport -modulerequested "ExchangeOnlineManagement"  -moduleset O365}
            until($ModImport -le 1)

            Write-host "Attempting Security and Compliance Center Login"
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
                Write-Host "Please try installing the ExchangeOnlineManagement Module later."
                }
            }
        }      

    #Teams Login
        if($Service -contains "Teams"){
            $ModImport = $null

            #Check if the required module is imported and if not install it
            do{$ModImport = usamoduleimport -modulerequested "MicrosoftTeams" -moduleset O365}
            until($ModImport -le 1)
            Write-host "Attempting Teams Login"


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
                        Write-Warning "Cannot connect to Teams in AzureGermanyCloud as no tenant exists, see https://learn.microsoft.com/en-us/powershell/module/teams/connect-microsoftteams?view=teams-ps#-teamsenvironmentname for more info"
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
                        Write-Warning "Cannot connect to Teams in AzureGermanyCloud as no tenant exists, see https://learn.microsoft.com/en-us/powershell/module/teams/connect-microsoftteams?view=teams-ps#-teamsenvironmentname for more info"
                        }
                    if($AzureEnvironmentName -eq "AzureUSGovernment"){
                        Connect-MicrosoftTeams -TeamsEnvironmentName TeamsGCCH
                        }            
                } 
            }

            if($ModImport -eq 0){
                Write-Host "Please try installing the MicrosoftTeams Module later."
                }
            }

    
    }

}



function Install-UsaOffice365Modules{
    <#
    .SYNOPSIS
        Installs access to Office 365 Modules
    .PARAMETER Module
        Select which services to install modules for, defaults to AzureAD, ExchangeOnline, MSonline, Sharepoint, SharepointPNP, Teams
    .PARAMETER Update
        Run Updates on selected Modules

    .EXAMPLE
        PS> Install-UsaOffice365Modules
    .EXAMPLE
        PS> Install-UsaOffice365Modules -Module AzureAD
    .EXAMPLE
        PS> Install-UsaOffice365Modules -Module AzureAD -Update
    .VERSION
    1.0.0
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
        if($IsAdmin -eq $True){Install-Module -Name "PnP.PowerShell" -RequiredVersion 1.12.0 -Force -AllowClobber}
        if($IsAdmin -eq $False){Install-Module -Name "PnP.PowerShell" -RequiredVersion 1.12.0 -Force -AllowClobber -Scope CurrentUser}
        }
    if($null -ne $PNPinstalled -and $PNPinstalled -ne "" -and $Update -eq $true){Update-Module "PnP.PowerShell" -RequiredVersion 1.12.0 }
    if($null -ne $PNPinstalled -and $PNPinstalled -ne ""){Write-Host "SharePointPnP Module already installed, Skipping" }
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
    .VERSION
    1.0.0
#>
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  
}