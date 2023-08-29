<#USAGITOOLS MODULE
CTRL-F to find base info, modules included:
Internal Module
Identity Module
Misc Module
#>

#USAGI TOOLS INTERNAL MODULE
#VERSION 1.0.0
#Various Powershell tools designed to serve as either internal functions (labeled as usaverbNoun) (Expect slightly less professional comments in this section here be monsters)
function usamoduleimport{
    <#
    .SYNOPSIS
        Imports Modules and asks to install if it's missing, public module sets to be added as needed or until I somehow can have a required module magically be installed LOL
    .PARAMETER modulerequested
        what we want to import
    .PARAMETER moduleset
        If something special needs to be done to install, reroute to the appropriate function here
    .EXAMPLE
        PS> usamoduleimport -modulerequested ExchangeOnline -moduleset O365
    .NOTES
    Version 1.0.0
#>
        Param
        (
        [string]$modulerequested,
        [ValidateSet('O365')]
        [string[]]
        $moduleset
)
        Write-Output "Attempting import of $modulerequested"
        $modinstalled = Get-InstalledModule $modulerequested
        if($null -eq $modinstalled -or $modinstalled -eq ""){
            $Choices = @("Yes","No")
            $installmod = $Host.UI.PromptForChoice("Install Module?","Module $modulerequested not found, proceed with installation?",$Choices,1)
            if($installmod -eq 0){
            #If we want to install the module install based off the ModuleSet
                if($moduleset -eq "O365"){
                    Install-UsaOffice365Module -Module $modulerequested
                }
            #Attempt to import the newly Downloaded Module
                try{
                    Import-Module $modulerequested
                }
                catch{
                    Write-Error $_.Exception.Message
                    return 2
                }
            #Provided it works return sucess
                return 1
            }

            #If we're cancelling the install when not found
            else{
                Write-Warning "Module $modulerequested not found, and user elected to not install Skipping"
                return 0
            }
        }
        if($null -ne $modinstalled -and $modinstalled -ne ""){
            Import-Module $modulerequested
            return 1
        }
}

    function usainstallModule{
    <#
    .SYNOPSIS
        Attempts to install a module as admin and installs locally if we don't have perms
    .PARAMETER modulerequested
        What we want to import
    .PARAMETER doupdate
        Do update-module rather than install-module
    .EXAMPLE
        PS> usainstallModule -modulerequested ExchangeOnline
    .EXAMPLE
        PS> usainstallModule -modulerequested ExchangeOnline -doupdate
    .NOTES
    Version 1.0.0
#>
        Param
        (
        [string]$modulerequested,
        [bool]$doupdate = $false
        )
        $IsAdmin = Test-UsaAdministrator
        $modinstalled = Get-InstalledModule $modulerequested
        if($null -eq $modinstalled -or $modinstalled -eq ""){
            if($IsAdmin -eq $true){Install-Module $modulerequested}
            else{Install-Module $modulerequested -Scope CurrentUser}
            }
        if($null -ne $modinstalled -and $modinstalled -ne "" -and $doupdate -eq $true){
            Update-Module $modulerequested
            }
        if($null -ne $modinstalled -and $modinstalled -ne ""){
            Write-Warning "$modulerequested Module already installed, Skipping"
            }
        }
#USAGI TOOLS IDENTITY MODULE
#VERSION 1.0.1
#Various Powershell tools designed around Identity Provisioning / Management systems (Active Directory, Azure AD, Etc)

function Set-UsaDynamicGroupMember{
    <#
    .SYNOPSIS
        Sets the members of a group based off various attributes, designed to be piped into a scheduled task with a foreach-object loop and WILL PROCEED WITH EMPTY VARIABLES

    .PARAMETER Identity
        Identity of group to set

    .PARAMETER Computers
        List of computers to manually add to group

    .PARAMETER ComputerOU
        OU to take all Commputer AD Objects from in DN format

    .PARAMETER Debug
        Enables errors and pauses script before applying changes to allow review of users before application

    .PARAMETER Group
        List of Distribution Lists or Security Groups to nest in said group

     .PARAMETER OutputPath
        Path to output list of users exported, will not export if no path is provided

    .PARAMETER SearchString
        Manual search string for ADObejcts to add

    .PARAMETER Users
        List of users to directly add to group

     .PARAMETER UserOU
        OU to take all AD User Objects from in DN format

    .EXAMPLE
        PS> Set-UsaDynamicGroupMember -Identity TexasUsers -UserOU "OU=Users,OU=TX,OU=Org,DC=Contoso,DC=internal" -UsersManual "JDoeCEO@Contoso.internal"

    .EXAMPLE
        PS> Set-UsaDynamicGroupMember -Identity TexasUsers -UserOU "OU=Users,OU=TX,OU=Org,DC=Contoso,DC=internal" -UsersManual "JDoeCEO@Contoso.internal"

    .EXAMPLE
        PS> Set-UsaDynamicGroupMember -Identity TexasUsers -UserOU "OU=Users,OU=TX,OU=Org,DC=Contoso,DC=internal" -UsersManual "JDoeCEO@Contoso.internal"

    .EXAMPLE
        PS> Set-UsaDynamicGroupMember -Identity TexasUsers -UserOU "OU=Users,OU=TX,OU=Org,DC=Contoso,DC=internal" -UsersManual "JDoeCEO@Contoso.internal"

    .EXAMPLE
        PS> Set-UsaDynamicGroupMember -Identity TexasUsers -UserOU "OU=Users,OU=TX,OU=Org,DC=Contoso,DC=internal" -UsersManual "JDoeCEO@Contoso.internal"

    .NOTES
       Version 1.0.1
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param
    (
        [Parameter(Mandatory = $true)]$Identity,
        $Computers,
        $ComputersOU,
        $PauseAtEnd,
        $Group,
        [string]$OutputPath,
        [string]$SearchString,
        $Users,
        $UsersOU
    )
    #Specific table function for ease of coding
    function addtoTable{
        Param
            (
                [string]$AddType
            )
            $TableRow =New-Object PSObject
            $TableRow | Add-Member  -Type NoteProperty -Name "DisplayName" -Value $_.Name
            $TableRow | Add-Member  -Type NoteProperty -Name "DistinguishedName" -Value $_.DistinguishedName
            $TableRow | Add-Member  -Type NoteProperty -Name "ObjectGUID" -Value $_.ObjectGUID
            $TableRow | Add-Member  -Type NoteProperty -Name "OrgUnit" -Value $($_.DistinguishedName -replace '^.*?,(?=[A-Z]{2}=)')
            $TableRow | Add-Member  -Type NoteProperty -Name "AddType" -Value $AddType
            return $TableRow
    }
    #Validate Params are correct

    #Check that Identity group exists, if not terminate
    $IdentityObject = get-adgroup $Identity
    if($null -eq $IdentityObject -or $IdentityObject -eq ""){
        Write-Error "NO GROUP NAMED $Identity FOUND, ENDING SCRIPT" -TargetObject $Identity -RecommendedAction "Check your target AD Group and try again" -Category InvalidArgument
        break
    }

    #Are the OUs OUs?
        #Users
    if($null -ne $UsersOU -and $UsersOU -ne ""){
        $UsersOU  | ForEach-Object{
            try {
                Get-ADOrganizationalUnit $_ | Out-Null
            }
            catch{
                Write-Warning "An error occured validating a User OU:"
                Write-Error $_
                break
            }
        }
    }
        #Computers
    if($null -ne $ComputersOU -and $ComputersOU -ne ""){
        $ComputersOU  | ForEach-Object{
            try {
                Get-ADOrganizationalUnit $_ | out-null
            }
            catch{
                Write-Warning "An error occured validating a Computer OU:"
                Write-Error $_
                break
            }
        }
    }

    #Create base object to define list of who we're inputing
    $Table = @()

    #If UserOU is null skip
    if($null -eq $UsersOU -or $UsersOU -eq ""){
        Write-Output "No User OU selected, Skipping"
    }
    #Else look up all User Objects in OU and add to baseobject
    else{
        $UsersOU | ForEach-Object{
            Get-ADUser -SearchBase $_ -Filter *  | ForEach-Object{
                $Table += addtoTable -AddType "UserOU"
            }
        }
    }
    #If ComputerOU is null skip
    if($null -eq $ComputersOU -or $ComputersOU -eq ""){
        Write-Output "No Computer OU selected, Skipping"
    }

    #Else look up all Computer objects in OU and add to baseobject
    else{
        $ComputersOU | ForEach-Object{
            Get-ADComputer -SearchBase $_ -Filter * | ForEach-Object{
                $Table += addtoTable -AddType "ComputerOU"
            }
        }
    }
    #Add any manual Users and Computers
    if($null -eq $Users -or $Users -eq ""){
        Write-Output "No Extra Users selected, Skipping"
    }
    #Else look up all User Objects and add to baseobject
    else{
        $Users | ForEach-Object{
                    Get-ADUser -Identity $_ |ForEach-Object{ #I cannot conceivably think of any reason the identity field would somehow even LET more than 1 user exist for this and if it does your AD is cursed but it makes it easier to put it here LOL
                            $Table += addtoTable -AddType "ExtraUsers"
                    }
                }
    }
    if($null -eq $Computers -or $Computers -eq ""){
        Write-Output "No Extra Computers selected, Skipping"
    }
    #Else look up all User Objects and add to baseobject
    else{
        $Computers | ForEach-Object{
                    Get-ADComputers -Identity $_ |ForEach-Object{ #I cannot conceivably think of any reason the identity field would somehow even LET more than 1 VALID computer exist for this and if it does your AD is cursed but it makes it easier to put it here LOL
                            $Table += addtoTable -AddType "ExtraComputers"
                    }
                }
    }

    #Add any manual groups to add
    if($null -eq $Group -or $Group -eq ""){Write-Output "No Extra Groups selected, Skipping"}
    #Else look up all User Objects and add to baseobject
    else{
        $Group | ForEach-Object{
                    Get-ADGroup -Identity $_ |ForEach-Object{ #I cannot conceivably think of any reason the identity field would somehow even LET more than 1 user exist for this and if it does your AD is cursed but it makes it easier to put it here LOL
                        if($IdentityObject.GroupScope.value__ -ge $_.GroupScope.value__){
                            $Table += addtoTable -AddType "ExtraGroup"
                        }
                        if($IdentityObject.GroupScope.value__ -lt $_.GroupScope.value__){
                            Write-Warning "Group $_.Name with GUID $_.ObjectGUID cannot be nested in Group $Identity.name with GUID of $Identity.Object GUID as it's Group Scope is $_.GroupScope while target group is $Identity.GroupScope . Skipping."
                        }
                    }
                }
    }

    #Add all objects from a custom Searchstring
    if($null -eq $SearchString -or $SearchString -eq ""){
        Write-Output "No Search String added, Skipping"
    }

    #Else look up all objects matching your filter string and add to baseobject
    else{
        Get-ADObject -Filter $SearchString | Where-Object{$_.objectclass -eq 'user' -or $_.objectclass -eq 'computer' -or $_.objectclass -eq 'group'} | ForEach-Object{
            if($_.objectclass -eq 'group'){
                $SSValidateGroup = Get-ADGroup $_.ObjectGUID
                if($IdentityObject.GroupScope.value__ -ge $SSValidateGroup.GroupScope.value__){
                    $Table += addtoTable -AddType "SearchString"
                }
                if($IdentityObject.GroupScope.value__ -lt $SSValidateGroup.GroupScope.value__){
                    Write-Warning $("Group " + $SSValidateGroup.Name + " with GUID " + $SSValidateGroup.ObjectGUID + " cannot be nested in Group " + $IdentityObject.Name + " with GUID of " + $IdentityObject.ObjectGUID + " as it's Group Scope is " + $SSValidateGroup.GroupScope + " while target group is " + $IdentityObject.GroupScope + ". Skipping.")
                }
            }
                else{
                    $Table += addtoTable -AddType "SearchString"
                }
        }
    }

    #Output baseobject if OutputPath is provided with timestamp on the files
    if($null -ne $OutputPath -and $OutputPath -ne ""){
        $Table | Export-Csv -Path $OutputPath
        Write-Output $("Exported list of users added to " + $IdentityObject.Name + " to $OutputPath")
    }
    #Pause script for review if Debug is enabled
    if($PauseAtEnd -eq $true){
        Write-Output "Displaying Object for review"
        $Table | Format-Table
        timeout /t -1
    }
    #Add all users in baseobject to group defined by identity
    Get-ADGroup -Identity $IdentityObject | Set-ADGroup -Clear member
    Add-ADGroupMember -Identity $IdentityObject -Members $Table.ObjectGUID
}

function Add-UsaUserSendasGlobally{
<#
    .SYNOPSIS
        Grants a User in Office 365 permission to send as ALL Licensed users. Good for global service accounts

    .PARAMETER Trustee
        Identity of user to gain full SendAs Rights

    .PARAMETER Credentials
        PSCredential Object of a NON MFA Admin to log into Office 365 with. If no credentials are provided will log in by default in interactive mode for MFA Login

    .PARAMETER AzureEnvironmentName
        Select Azure Environment to log into. Default is the normal AzureCloud environment, Alternative options are AzureChinaCloud, AzureGermanyCloud, and AzureUSGovernmentCloud. Options will select the same cloud as would be selected with Connect-AzureAD

    .EXAMPLE
        PS> Add-UsaUserSendasGlobally -Trustee CRM@contoso.net

    .EXAMPLE
        PS> Add-UsaUserSendasGlobally -Trustee CRM@contoso.net -Credentials $(Get-Credential)

    .EXAMPLE
        PS> Add-UsaUserSendasGlobally -Trustee CRMDE@contoso.net -Credentials $(Get-Credential) -AzureEnvironmentName AzureGermanyCloud

    .NOTES
        VERSION 1.0.1
    #>

    param(
    [string]$Trustee,

    [System.Management.Automation.PSCredential]
    [ValidateNotNull()]
    [Parameter(ParameterSetName='PSCredentialLogin')]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

    [ValidateSet('AzureCloud','AzureChinaCloud','AzureGermanyCloud','AzureUSGovernment')]
    [string[]]
    $AzureEnvironmentName = "AzureCloud"

    )

    #Non MFA Credential Login
    if($Credential -ne $([System.Management.Automation.PSCredential]::Empty) -and $null -ne $Credential){
        Connect-UsaOffice365Service -Credential $Credential -Service ExchangeOnline,MSOnline -AzureEnvironmentName $AzureEnvironmentName
    }
    #MFA Login
    else{
        Connect-UsaOffice365Service -Interactive -Service ExchangeOnline,MSOnline -AzureEnvironmentName $AzureEnvironmentName
    }
    [System.Collections.ArrayList]$Users = Get-MsolUser -All | Where-Object{$_.IsLicensed -eq $True}
    $CurrentPerms = Get-RecipientPermission -Trustee $Trustee
    #Take all users in CurrentPerms
    $CurrentPerms | ForEach-Object{
        #For each user check if it's in the Users Object locally and save that as a value
        $usertoremove = $_.Identity
        $remove = $Users | Where-Object{$_.DisplayName -like "$usertoremove" -OR $_.ObjectID -eq "$usertoremove"}
        #Check if it's 1 object, if -batch is on and we get 2 just skip the user and log it
        if($null -eq $remove){
            Write-Warning "$usertoremove NOT FOUND"
            #Put it on a log list if that's on
        }
        elseif($remove.count -eq 1){
            $Users.Remove($remove) #Remove object from list
        }
        else{
            Write-Warning "The following users were found but will not be removed from existing adds, expect errors"
            $remove
        }
    }
    $Users | ForEach-Object{
        Add-RecipientPermission -Identity $_.ObjectID -Trustee $Trustee -AccessRights SendAs  -Confirm:$false
    }
}

#USAGI TOOLS MISC MODULE
#VERSION 1.0.1
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
    .NOTES
    Version 1.0.1
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
    Version 1.0.1
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

            Write-Output "Attempting AzureAD Login"
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
                Write-Error "Please try installing the AzureAD Module later."
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

            Write-Output "Attempting Exchange Online Login"
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
                Write-Warning "Please try installing the ExchangeOnlineManagement Module later."
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

            Write-Output "Attempting MSOL Login"
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
                Write-Output "Please try installing the MSOnline Module later."
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

            Write-Output "Attempting Sharepoint Login"

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
                Write-Warning "Please try installing the SharePoint Module later."
                }
            }
        }

    #SharepointPNP
        if($Service -contains "SharePointPnP" -and $null -ne $SharepointPNPLibraryURI -and $SharepointPNPLibraryURI -ne ""){
            $ModImport = $null

            #Check if the required module is imported and if not install it
            do{$ModImport = usamoduleimport -modulerequested "PnP.Powershell" -moduleset O365}
            until($ModImport -le 1)

            Write-Output "Attempting Sharepoint PNP Login to $SharepointPNPLibraryURI"

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
                Write-Output "Please try installing the SharePointPnP Module later."
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

            Write-Output "Attempting Security and Compliance Center Login"
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
                Write-Warning "Please try installing the ExchangeOnlineManagement Module later."
                }
            }
        }

    #Teams Login
        if($Service -contains "Teams"){
            $ModImport = $null

            #Check if the required module is imported and if not install it
            do{$ModImport = usamoduleimport -modulerequested "MicrosoftTeams" -moduleset O365}
            until($ModImport -le 1)
            Write-Output "Attempting Teams Login"
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
                Write-Warning "Please try installing the MicrosoftTeams Module later."
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
     Version 1.0.1
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
        Write-Output "SharePointPnP Module already installed, Skipping"
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
