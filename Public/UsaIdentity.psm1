#USAGI TOOLS IDENTITY MODULE
#VERSION 1.0.2
#Various Powershell tools designed around Identity Provisioning / Management systems (Active Directory, Azure AD, Etc)
#Module Event # 2000-2999


function Add-UsaUserSendasGlobally{
<#
    .SYNOPSIS
        Grants a User in Office 365 permission to send as ALL Licensed users. Good for global service accounts as a workaround for Applications that require it

    .PARAMETER Trustee
        Identity of user to gain full SendAs Rights

    .PARAMETER Credentials
        PSCredential Object of a NON MFA Admin to log into Office 365 with. If no credentials are provided will log in by default in interactive mode for MFA Login

    .PARAMETER AzureEnvironmentName
        Select Azure Environment to log into. Default is the normal AzureCloud environment, Alternative options are AzureChinaCloud, AzureGermanyCloud, and AzureUSGovernmentCloud. Options will select the same cloud as would be selected with Connect-AzureAD

    .PARAMETER AddDistributionGroups
        Add permissions to all Distribution groups as well

    .PARAMETER AddSharedMailboxes
        Adds permissions to all Shared Mailboxes

    .PARAMETER RemoveStaleEntries
        Removes any users from the current set of permissions who aren't found in the existing pulled list of permissions, useful for when these entry lookups don't match with curent data (Like when a User changes their name)
    .EXAMPLE
        PS> Add-UsaUserSendasGlobally -Trustee CRM@contoso.net

    .EXAMPLE
        PS> Add-UsaUserSendasGlobally -Trustee CRM@contoso.net -Credentials $(Get-Credential)

    .EXAMPLE
        PS> Add-UsaUserSendasGlobally -Trustee CRMDE@contoso.net -Credentials $(Get-Credential) -AzureEnvironmentName AzureGermanyCloud

    .NOTES
        VERSION 1.0.2
    #>

    param(
    [string]$Trustee,

    [System.Management.Automation.PSCredential]
    [ValidateNotNull()]
    [Parameter(ParameterSetName='PSCredentialLogin')]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

    [ValidateSet('AzureCloud','AzureChinaCloud','AzureGermanyCloud','AzureUSGovernment')]
    [string[]]
    $AzureEnvironmentName = "AzureCloud",
    [switch]$AddDistributionGroups,
    [switch]$AddSharedMailboxes,
    [switch]$RemoveStaleEntries

    )

    #Non MFA Credential Login
    if($Credential -ne $([System.Management.Automation.PSCredential]::Empty) -and $null -ne $Credential){
        Connect-UsaOffice365Service -Credential $Credential -Service ExchangeOnline,MSOnline -AzureEnvironmentName $AzureEnvironmentName
    }
    #MFA Login
    else{
        Connect-UsaOffice365Service -Interactive -Service ExchangeOnline,MSOnline -AzureEnvironmentName $AzureEnvironmentName
    }

    usawritelog  -Message "Gathering Users list, please wait" -LogLevel SuccessAudit -EventID 1000

    usawritelog  -Message "Gathering Users list, please wait" -LogLevel SuccessAudit -EventID 1000

    [System.Collections.ArrayList]$Users = Get-MsolUser -All  | Where-Object{$_.IsLicensed -eq $True}
    if($AddDistributionGroups -or $AddSharedMailboxes){
        [System.Collections.ArrayList]$Extras = @()
    }
    if($AddDistributionGroups){Get-DistributionGroup -Filter * | ForEach-Object { 
        $Extras.Add($_.PrimarySMTPAddress)} | Out-Null
    }
    if($AddSharedMailboxes){
        Get-Mailbox -GroupMailbox -Filter * | ForEach-Object { $Extras.Add($_.PrimarySMTPAddress)} | Out-Null
    }
    
    $CurrentPerms = Get-RecipientPermission -Trustee $Trustee -ResultSize Unlimited
    #Take all users in CurrentPerms and remove them from the Users Object so we don't push duplicate permissions
    usawritelog -LogLevel SuccessAudit -EventID 0 -Message "Cleaning Permission Object"
    $CurrentPerms | ForEach-Object{
        #For each user check if it's in the Users Object locally and save that as a value
        #Get the object from our $Users MSOnline based object if it exists, due to varying Identity vales checks  DisplayName, ObjectID, SamAccountName,  UserPrincipalName
        $usertoremove = $_.Identity
    
        $UserRemove = $Users | Where-Object{$_.DisplayName -like "$usertoremove" -OR $_.ObjectID -eq "$usertoremove" -OR  $_.UserPrincipalName.Split('@')[0] -like $usertoremove -OR  $_.UserPrincipalName -like $usertoremove}
    $ExtrasRemove = $Extras |Where-Object    -like $usertoremove
        #Check both objects and verify only 1 object exists then remove from the add list so it's not readded
        if(($null -eq $UserRemove -or $UserRemove -eq "")  -and $RemoveStaleEntries){ #Check if Users list exists and remove the old entry for readd later
            usawritelog -LogLevel Warning -EventID 2003 -Message "$usertoremove not found, removing permission"
            Get-RecipientPermission -Trustee $Trustee -ResultSize Unlimited -Identity $usertoremove | Remove-RecipientPermission -Confirm:$False
        }
        elseif($null -eq $UserRemove -or $UserRemove -eq ""){
            usawritelog -LogLevel Warning -EventID 2001 -Message "$usertoremove not found in active recipients, please run with the -RemoveStaleEntries flag to attempt to remove if invalid and rebuild if stale"
            #Put it on a log list if that's on
        }
        elseif($UserRemove.count -eq 1){ #Remove object from list
            $Users.Remove($UserRemove)
        }
        elseif(($null -eq $ExtrasRemove -or $ExtrasRemove -like "") -and $RemoveStaleEntries){
            usawritelog -LogLevel Warning -EventID 2003 -Message "$usertoremove not found, removing permission"
            Get-RecipientPermission -Trustee $Trustee -ResultSize Unlimited -Identity $usertoremove | Remove-RecipientPermission -Confirm:$False
        }
        elseif($null -eq $ExtrasRemove){
            usawritelog -LogLevel Warning -EventID 2001 -Message "$usertoremove not found in active recipients, please run with the -RemoveStaleEntries flag to attempt to remove if invalid and rebuild if stale"
        }
        elseif($ExtrasRemove.count -eq 1){ #Remove object from list
            $Users.Remove($ExtrasRemove)
        }
        else{
            usawritelog -LogLevel Warning -EventID 2002 -Message $("The following users were found but will not be removed from existing adds, expect errors
            "+ $remove)
        }
    }

    usawritelog -LogLevel SuccessAudit -EventID 0 -Message $("Adding permissions for " + $Trustee)
    $Users | ForEach-Object{
        Add-RecipientPermission -Identity $_.ObjectID -Trustee $Trustee -AccessRights SendAs  -Confirm:$false
    }
}

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
       Version 1.0.2
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

    #Import AD Module
    $ModImport = $null

    #Check if the AD module is imported and if not install it
    do{
        $ModImport = usamoduleimport -modulerequested "ActiveDirectory" -moduleset ActiveDirectory
    }
    until($ModImport -le 1)

    usawritelog -LogLevel SuccessAudit -EventID 0 -Message "Attempting AzureAD Login"
    if($ModImport -eq 0){
        usawritelog -LogLevel Error -EventID 2014 -Category NotInstalled -Message "Could not import ActiveDirectory Module please install and try again"
        Break
    }
        #Module imported lets go
    else{
        #Validate Params are correct
        
        #Check that Identity group exists, if not terminate
        $IdentityObject = get-adgroup $Identity
        if($null -eq $IdentityObject -or $IdentityObject -eq ""){
            usawritelog -LogLevel Error -EventID 2010 -Message "NO GROUP NAMED $Identity FOUND, ENDING SCRIPT" -RecommendedAction "Check your target AD Group and try again" -Category InvalidArgument
            break
        }
        else{
            usawritelog -LogLevel Information -EventID 2009 -Message "Starting Group Rebuild for $Identity"
        }
        #Are the OUs OUs?
            #Users
        if($null -ne $UsersOU -and $UsersOU -ne ""){
            $UsersOU  | ForEach-Object{
                try {
                    Get-ADOrganizationalUnit $_ | Out-Null
                }
                catch{
                    usawritelog -LogLevel Warning -EventID 2011 -Message "An error occured validating a User OU:"
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
                    usawritelog -LogLevel Warning -EventID 2012 -Message "An error occured validating a Computer OU:"
                    Write-Error $_
                    break
                }
            }
        }

        #Create base object to define list of who we're inputing
        $Table = @()

        #If UserOU is null skip
        if($null -eq $UsersOU -or $UsersOU -eq ""){
            usawritelog -LogLevel SuccessAudit -EventID 0 -Message "No User OU selected, Skipping"
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
            usawritelog -LogLevel SuccessAudit -EventID 0 -Message "No Computer OU selected, Skipping"
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
            usawritelog -LogLevel SuccessAudit -EventID 0 -Message "No Extra Users selected, Skipping"
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
            usawritelog -LogLevel SuccessAudit -EventID 0 -Message "No Extra Computers selected, Skipping"
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
                                usawritelog -LogLevel SuccessAudit -EventID 0 -Message $("Group " + $_.Name + " with GUID " + $_.ObjectGUID + " cannot be nested in Group " + $Identity.name + " with GUID of " + $Identity.Object + " GUID as it's Group Scope is " + $_.GroupScope + " while target group is $Identity.GroupScope . Skipping.")
                            }
                        }
                    }
        }

        #Add all objects from a custom Searchstring
        if($null -eq $SearchString -or $SearchString -eq ""){
            usawritelog -LogLevel SuccessAudit -EventID 0 -Message "No Search String added, Skipping"
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
                        usawritelog -LogLevel Warning -EventID 2013 -Message $("Group " + $SSValidateGroup.Name + " with GUID " + $SSValidateGroup.ObjectGUID + " cannot be nested in Group " + $IdentityObject.Name + " with GUID of " + $IdentityObject.ObjectGUID + " as it's Group Scope is " + $SSValidateGroup.GroupScope + " while target group is " + $IdentityObject.GroupScope + ". Skipping.")
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
            usawritelog -LogLevel SuccessAudit -EventID 0 -Message $("Exported list of users added to " + $IdentityObject.Name + " to $OutputPath")
        }
        #Pause script for review if Debug is enabled
        if($PauseAtEnd -eq $true){
            usawritelog -LogLevel SuccessAudit -EventID 0 -Message "Displaying Object for review"
            $Table | Format-Table
            timeout /t -1
        }
        #Add all users in baseobject to group defined by identity
        Get-ADGroup -Identity $IdentityObject | Set-ADGroup -Clear member
        Add-ADGroupMember -Identity $IdentityObject -Members $Table.ObjectGUID
    }
}
