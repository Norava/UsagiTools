﻿#USAGI TOOLS MISC MODULE
#VERSION 0.1.0
#Various Powershell tools designed to serve as either internal functions (labeled as usaverbNoun) Or otherwise misc functions

function Get-UsaPublicIP{
    <#
    .SYNOPSIS
        Simple script to pull public IP using IPify
    .PARAMETER Computer
        Runs cmdlet again a remote PC and returns
    .EXAMPLE
        PS> Invoke-WebRequest
    .EXAMPLE
        PS> Get-PublicIP -Computer Srv-DC1.contoso.loc
    .EXAMPLE
        PS> Get-PublicIP -Computer Srv-DC1.Contoso.loc -Credential $(Get-Credential) 
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
if($null -eq $Computer -and $Credential -eq $([System.Management.Automation.PSCredential]::Empty) ){
    (Invoke-WebRequest http://api.ipify.org -UseBasicParsing).content}

elseif($null -ne $Computer -and $Credential -eq $([System.Management.Automation.PSCredential]::Empty) ){
    Invoke-Command -ComputerName $Computer -ScriptBlock{
        (Invoke-WebRequest http://api.ipify.org -UseBasicParsing).content} 
        }

elseif($null -ne $Computer -and $Credential -ne $([System.Management.Automation.PSCredential]::Empty) -and $null -ne $Credential){
    Invoke-Command -ComputerName $Computer -Credential $Credential -ScriptBlock{
       (Invoke-WebRequest http://api.ipify.org -UseBasicParsing).content} 
        }

}


function Login-UsaOffice365Services{
#SecAndCompCenter is seperate login self FYI SecAndCompCenter
Param
( 
    [ValidateSet('AzureAD','ExchangeOnline','MSOnline','SharePoint','SharePointPnP','SecAndCompCenter','Teams')]
    [string[]]
        $Service=("AzureAD","ExchangeOnline","MSOnline",'SharePoint','SecAndCompCenter','SharePointPnP','Teams'),
    [ValidateSet('AzureCloud','AzureChinaCloud','AzureGermanyCloud','AzureUSGovernment')]
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
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12  


        
#Login without MFA
    if($Module -contains "AzureAD"){
        $ModImport = $null
        do{$ModImport = usamoduleimport -modulerequested "AzureAD" -moduleset O365}
        until($ModImport -le 1)
        if($ModImport -eq 1){
            if($Interactive -eq $false -or $null -eq $Interactive){
                Connect-AzureAD -Credential $Credential -AzureEnvironmentName $AzureEnvironmentName
                }
            else{
                Connect-AzureAD -AzureEnvironmentName $AzureEnvironmentName -
                }
            }
        elseif($ModImport -eq 0){
            Write-Host "Please try installing the AzureAD Module later."
            }
        }
    if($Module -contains "ExchangeOnline"){        
        $ModImport = $null
        do{$ModImport = usamoduleimport -modulerequested "ExchangeOnlineManagement"  -moduleset O365}
        until($ModImport -le 1)
        if($ModImport -eq 1){
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
        elseif($ModImport -eq 0){
            Write-Host "Please try installing the ExchangeOnlineManagement Module later."
            }
        }
    }


    if($Module -contains "MSOnline"){
        $ModImport = $null
        do{$ModImport = usamoduleimport -modulerequested "MSOnline" -moduleset O365}
        until($ModImport -le 1)
        if($ModImport -eq 1){
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

    if($Module -contains "SharePoint" -and $null -ne $SharepointHostName -and $SharepointHostName -ne ""){
        $ModImport = $null
        do{$ModImport = usamoduleimport -modulerequested "Microsoft.Online.SharePoint.PowerShell" -moduleset O365}
        until($ModImport -le 1)
        if($ModImport -eq 1){
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
        elseif($ModImport -eq 0){
            Write-Host "Please try installing the SharePoint Module later."
            }
        }
    }
    if($Module -contains "SharePointPnP" -and $null -ne $SharepointPNPLibraryURI -and $SharepointPNPLibraryURI -ne ""){
        $ModImport = $null
        do{$ModImport = usamoduleimport -modulerequested "PnP.Powershell" -moduleset O365}
        until($ModImport -le 1)
        if($ModImport -eq 1){
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
                    Connect-PnPOnline -Url $SharepointPNPLibraryURI -Interactive -region Production
                    }
                if($AzureEnvironmentName -eq "AzureChinaCloud"){
                    Connect-PnPOnline -Url $SharepointPNPLibraryURI -Interactive -region China
                    }
                if($AzureEnvironmentName -eq "AzureGermanyCloud"){
                    Connect-PnPOnline -Url $SharepointPNPLibraryURI -Interactive -region Germany
                    }
                if($AzureEnvironmentName -eq "AzureUSGovernment"){
                    Connect-PnPOnline -Url $SharepointPNPLibraryURI -Interactive -region USGovernmentHigh
                    }            
            }
        elseif($ModImport -eq 0){
            Write-Host "Please try installing the SharePointPnP Module later."
            }
        }
    }
    if($Module -contains "SecAndCompCenter"){        
        $ModImport = $null
        do{$ModImport = usamoduleimport -modulerequested "ExchangeOnlineManagement"  -moduleset O365}
        until($ModImport -le 1)
        if($ModImport -eq 1){
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
        elseif($ModImport -eq 0){
            Write-Host "Please try installing the ExchangeOnlineManagement Module later."
            }
        }
    }      
    if($Module -contains "Teams"){
        $ModImport = $null
        do{$ModImport = usamoduleimport -modulerequested "MicrosoftTeams" -moduleset O365}
        until($ModImport -le 1)
        if($ModImport -eq 1){
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
                }            }
        elseif($ModImport -eq 0){
            Write-Host "Please try installing the MicrosoftTeams Module later."
            }
        }

    
}





function Install-UsaOffice365Modules{

Param
( 
    [ValidateSet('AzureAD','ExchangeOnline',"MSOnline",'SharePoint','SharePointPnP','Teams')]
    [string[]]$Module=("AzureAD","ExchangeOnline","MSOnline",'SharePoint','SharePointPnP','Teams'),
    [switch]$Update

)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12  

    function usacheckModule{
        Param
        ([string]$modulerequested)
        $modinstalled = Get-InstalledModule $modulerequested
        if($null -eq $modinstalled -or $modinstalled -eq ""){
            if($IsAdmin -eq $true){Install-Module $modulerequested}
            else{Install-Module $modulerequested -Scope CurrentUser}
            }
        elseif($null -ne $modinstalled -and $modinstalled -ne "" -and $Update -eq $true){
            Update-Module $modulerequested 
            }
        elseif($null -ne $modinstalled -and $modinstalled -ne ""){
            Write-Host "$modulerequested Module already installed, Skipping" 
            }
        }
$IsAdmin = Test-UsaAdministrator

if($Module -contains "AzureAD"){
    usainstallModule -modulerequested "AzureAD" -doupdate $Update
    }
if($Module -contains "ExchangeOnline"){
    usainstallkModule -modulerequested "ExchangeOnlineManagement" -doupdate $Update
    }
if($Module -contains "MSOnline"){
    usainstallModule -modulerequested "MSOnline" -doupdate $Update
    }

if($Module -contains "SharePoint"){
    usaisntallModule -modulerequested "Microsoft.Online.SharePoint.PowerShell" -doupdate $Update
    }
if($Module -contains "SharePointPnP"){
    $PNPinstalled = Get-Module "PnP.PowerShell"
    if($null -eq $PNPinstalled -or $PNPinstalled -eq ""){
        if($IsAdmin -eq $True){Install-Module -Name "PnP.PowerShell" -RequiredVersion 1.12.0 -Force -AllowClobber}
        if($IsAdmin -eq $False){Install-Module -Name "PnP.PowerShell" -RequiredVersion 1.12.0 -Force -AllowClobber -Scope CurrentUser}
        }
    elseif($null -ne $PNPinstalled -and $PNPinstalled -ne "" -and $Update -eq $true){Update-Module "PnP.PowerShell" -RequiredVersion 1.12.0 }
    elseif($null -ne $PNPinstalled -and $PNPinstalled -ne ""){Write-Host "SharePointPnP Module already installed, Skipping" }
    }
if($Module -contains "Teams"){
    usainstatllModule -modulerequested "MicrosoftTeams" -doupdate $Update
    }
}


function Test-UsaAdministrator  
{  
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  
}