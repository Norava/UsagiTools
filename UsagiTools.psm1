<#USAGITOOLS MODULE
CTRL-F to find base info, modules included:
Internal Module
Identity Module
Misc Module
#>

#USAGI TOOLS INTERNAL MODULE
#VERSION 1.1.0
#Various Powershell tools designed to serve as either internal functions (labeled as usaverbNoun) (Expect slightly less professional comments in this section here be monsters)
function usawritelog{
    <#
    .SYNOPSIS
        Writes log to both console and Event Viewer under "UsagiTools"
    .PARAMETER Message
        What we want to write out
    .PARAMETER LogLevel
        Log Level to select Error message output and Event Viewer EntryType. Valid values: 'Error','Warning','Information', 'SuccessAudit','FailureAudit'
    .PARAMETER EventID
        EventID to log under, see NOTES for list of IDs
    .PARAMETER Category
        Category to use for Write-Error. Matches all Write-Error Categories
    .PARAMETER RecommendedAction
        Adds Write-Error's Recommened action as needed
    .EXAMPLE
        PS> usawritelog Message "This is a message" -LogLevel -Information -EventID 0
    .NOTES
    Version 1.0.0
    EventID
    0   : Verbose audit message
    1   : New UsagiTools Version Available
    1001: Azure AD Module was unable to install and import, manual import or reinstall module
    1002: Exchange Online Module was unable to install and import, manual import or reinstall module
    1003: Sharepoint Online Module was unable to install and import, manual import or reinstall module
    1004: Sharepoint PNP Module was unable to install and import, manual import or reinstall module
    1005: Teams Module was unable to install and import, manual import or reinstall module
    1010: No German Servers for this cmdlet exist per documentation as of writing
    1020: Output of Test-UsaNetwork
    1021: Invalid Source Address IP or automatic detection failed and manual -source flag needed
    1022: Could not find Adapter with Source Address IP given, verify an existing adapter has the IP provided
    2001: User couldn't be added via Add-UsaUserSendasGlobally 's Get-ReciepientPermission -trustee $Trustee. User possibly is manually set without a license or entry is stale information to validate on (A User Rename can cause this), consider cleaning from group
    2002: Somehow 2 users were found when checking object. Validate users
    2003: User sendas perms from Trustee removed, if user is in the valid list of objects it will be readded with updated values
    2004: User sendas perms from Trustee Added
    2005: Error updating Table of known permissions due to a failure to validate an object. Please report this errorr!
    2009: Output for Set-UsaDynamic group citing group worked on
    2010: Invalid group for Set-UsaDynamicGroupMember, validate group via get-adgroup
    2011: Could not validate User OU to add for Set-UsaDynamicGroupMember, validate via Get-ADOrganizationUnit
    2012: Could not validate Computer OU to add for Set-UsaDynamicGroupMember, validate via Get-ADOrganizationUnit
    2013: Set-UsaDynamicGroupMember group validation error stating you're unable to nest a parent level group in a child
    2014: Could not import Active Directory Module
#>
    Param(
    [Parameter(Mandatory = $true)]
    [string]
        $Message,
    [ValidateSet('Error','Warning','Information', 'SuccessAudit','FailureAudit')]
    [Parameter(Mandatory = $true)]
    [string]
        $LogLevel,
    [Parameter(Mandatory = $true)]
    [int]
        $EventID,
    [ValidateSet('AuthenticationError',
                'CloseError',
                'ConnectionError',
                'DeadlockDetected',
                'DeviceError',
                'FromStdError',
                'InvalidArguement',
                'InvalidData',
                'InvalidOperation',
                'InvalidResult',
                'InvalidType',
                'LimitsExceeded',
                'MetadataError',
                'NotEnabled',
                'NotImplemented',
                'NotInstalled',
                'NotSpecified',
                'ObjectNotFound',
                'OpenError',
                'OperationStopped',
                'OperationTimeout',
                'ParserError',
                'PermissionDenied',
                'ProtocalError',
                'QuotaExceeded',
                'ReadError',
                'ResourceBusy',
                'ResourceExists',
                'ResourceUnavailable',
                'SecurityError',
                'SyntaxError',
                'WriteError')]
    [string]
        $Category,
    [string]$RecommendedAction
    )
    #Attempt to write to the log and throw no error if it fails (-ErrorAction for some reason still errors, research seems to point to it being a bug at the time of writing)
    try{
        Write-EventLog -LogName UsagiTools -Source UsagiTools -EntryType $LogLevel -EventId $EventID -Message $Message
    }
    catch{$_ | out-null}
    switch($LogLevel){
        "Error"{Write-Error -ErrorId $EventID -Category $Category -RecommendedAction $RecommendedAction -Message $Message}
        "Warning"{Write-Warning -Message $Message}
        "Information"{Write-Output $Message}
        "SuccessAudit"{Write-Output $Message}
        "FailureAudit"{Write-Output $Message}

    }
}

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
        Param(
        [string]$modulerequested,
        [ValidateSet('O365','ActiveDirectory')]
        [string[]]
        $moduleset
        )
        Write-Output "Attempting import of $modulerequested"
        $modinstalled = Get-Module $modulerequested -ListAvailable
        if($null -eq $modinstalled -or $modinstalled -eq ""){
            $Choices = @("Yes","No")
            $installmod = $Host.UI.PromptForChoice("Install Module?","Module $modulerequested not found, proceed with installation?",$Choices,1)
            if($installmod -eq 0){
            #If we want to install the module install based off the ModuleSet
                switch ($moduleset) {
                    O365 { Install-UsaOffice365Module -Module $modulerequested }
                    ActiveDirectory {Install-WindowsFeature -Name "RSAT-AD-PowerShell" -IncludeAllSubFeature }
                    Default {}
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
        Param(
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
function usacheckNetname{
        <#
.SYNOPSIS
    Checks a string provided with Address to determine if it's an IP or DNS name and if it includes a port then cleans it up and provides an object
.PARAMETER Address
    What we want to import
.EXAMPLE
    PS> usacheckNetname -Address 10.245.23.1
.NOTES
Version 1.0.0
#>
param(
[Parameter(Mandatory, Position=0)]
[string]$Address
)

#Cast our Address as a URI to pull the DNSSafeHost and Port from it
$Base = ([URI]$("cast:\\"+$Address))
$SafeHost = $Base.DNSSafeHost.TrimEnd('.')
$Port    = $Base.Port

#Check if the Address is a valid IP, if not it's a host and will be marked as such
try{
    [ipaddress]$SafeHost | Out-Null
    $Type = "IP"}
catch{
    $Type = "DNSName"
    }
#Build our object
$Device = New-Object PSObject
$Device | Add-Member  -Type NoteProperty -Name "Address" -Value $SafeHost
$Device | Add-Member  -Type NoteProperty -Name "Port" -Value $Port
$Device | Add-Member  -Type NoteProperty -Name "Type" -Value $Type
return $Device

}

function usaPing{
<#
.SYNOPSIS
    Faster ping for continous loops that accepts ports
.PARAMETER Source
    IP of interface to bind to
.PARAMETER Destination
    Remote host to ping to
.PARAMETER MTU
    Packet MTU for normal pings, defaults to 32
.PARAMETER Port
    Port to query
.EXAMPLE
    PS> usaPing -source $SourceIP -Destination $Dest
.EXAMPLE
    PS> usaPing -source $SourceIP -Destination $Dest -port 8080
.NOTES
Version 1.0.0
#>

param(
[Parameter(Mandatory, Position=0)]
[ipaddress]
    $Source,
[Parameter(Mandatory, Position=1)]
[ipaddress]
    $Destination,
[int]$MTU =32,
[int]$Port
)
try{$null -ne [UsaIcmpPing] | Out-Null}
catch{
    Add-Type @"
    using System;
    using System.Net;
    using System.Text;
    using System.Runtime.InteropServices;

    public class UsaIcmpPing
    {
        [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Ansi)]
        private struct ICMP_OPTIONS
        {
            public byte Ttl;
            public byte Tos;
            public byte Flags;
            public byte OptionsSize;
            public IntPtr OptionsData;
        }

        [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Ansi)]
        private struct ICMP_ECHO_REPLY
        {
            public int Address;
            public int Status;
            public int RoundTripTime;
            public short DataSize;
            public short Reserved;
            public IntPtr DataPtr;
            public ICMP_OPTIONS Options;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst=9900)]
            public string Data;
        }

        [DllImport("Iphlpapi.dll", SetLastError = true)]
        private static extern IntPtr IcmpCreateFile();
        [DllImport("Iphlpapi.dll", SetLastError = true)]
        private static extern bool IcmpCloseHandle(IntPtr handle);
        [DllImport("Iphlpapi.dll", SetLastError = true)]
        private static extern int IcmpSendEcho2Ex(IntPtr icmpHandle, IntPtr hEvent, IntPtr apcRoutine, IntPtr apcContext, int sourceAddress, int destinationAddress, string requestData, short requestSize, ref ICMP_OPTIONS requestOptions, ref ICMP_ECHO_REPLY replyBuffer, int replySize, int timeout);

        public int PingRTT(IPAddress sourceIp, IPAddress destIp, int dataSize)
        {
            IntPtr icmpHandle = IcmpCreateFile();
            ICMP_OPTIONS icmpOptions = new ICMP_OPTIONS();
            icmpOptions.Ttl = 255;
            icmpOptions.Flags = 0x02;
            ICMP_ECHO_REPLY icmpReply = new ICMP_ECHO_REPLY();
            string sData = CreateSendData(dataSize);

            int replies = IcmpSendEcho2Ex(icmpHandle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, BitConverter.ToInt32(sourceIp.GetAddressBytes(), 0), BitConverter.ToInt32(destIp.GetAddressBytes(), 0), sData, (short)sData.Length, ref icmpOptions, ref icmpReply, Marshal.SizeOf(icmpReply), 30);
            IcmpCloseHandle(icmpHandle);

            if (replies > 0)
            {
                return icmpReply.RoundTripTime;
            }

            return -1;
        }

        private string CreateSendData(int length)
        {
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            var random = new Random();
            StringBuilder builder = new StringBuilder();
            for(int index = 0; index < length; index++)
            {
                builder.Append(chars[random.Next(chars.Length)]);
            }
            return builder.ToString();
        }
    }
"@
}
if($null -eq $Port -or $Port -eq ""){
        $RTT = $([UsaIcmpPing]::new()).PingRTT($Source, $Destination, $MTU)

        #Check if reply was received, on -1 this is a no (Warning, code not written to account for FTL ping times)
        if($RTT -eq -1){$Connected = $false}
        else{$Connected = $true}
    }
if($null -ne $Port -and $Port -is [int] -and $Port -ne 0){
    $tcpClient = $null
    $connect = $null
    $Success = $null
    $localport = 0
    [ipaddress]$Source = $Source
    $localEP = New-Object System.Net.IPEndPoint($Source, $localPort)
    $tcpClient = New-Object System.Net.Sockets.TcpClient($localEP)
    $stopwatch = New-Object System.Diagnostics.Stopwatch
    $stopwatch.Start()
    $connect = $tcpClient.BeginConnect($Destination, $Port, $null, $null)
    $success = $connect.AsyncWaitHandle.WaitOne(3000)
    $stopwatch.Stop()
    if($success) {
        if($tcpClient.Connected) {
            $Connected = $true
        } else {
            $Connected = $false
        }

        $tcpClient.EndConnect($connect)
        $tcpClient.Close()
    } else {
        $Connected = $false
    }
    $RTT = $stopwatch.Elapsed.TotalMilliseconds
}


#Build our object
$TestResult = New-Object PSObject
$TestResult | Add-Member  -Type NoteProperty -Name "SRC" -Value $Source
$TestResult | Add-Member  -Type NoteProperty -Name "DST" -Value $Destination
$TestResult | Add-Member  -Type NoteProperty -Name "RTT" -Value $([Math]::Round($RTT))
$TestResult | Add-Member  -Type NoteProperty -Name "MTU" -Value $MTU
$TestResult | Add-Member  -Type NoteProperty -Name "Port" -Value $Port
$TestResult | Add-Member  -Type NoteProperty -Name "Connected" -Value $Connected
return $TestResult

}
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

    .EXAMPLE
        PS> Add-UsaUserSendasGlobally -Trustee CRM@contoso.net

    .EXAMPLE
        PS> Add-UsaUserSendasGlobally -Trustee CRM@contoso.net -Credentials $(Get-Credential)

    .EXAMPLE
        PS> Add-UsaUserSendasGlobally -Trustee CRMDE@contoso.net -Credentials $(Get-Credential) -AzureEnvironmentName AzureGermanyCloud

    .NOTES
        VERSION 1.1.0
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
    [switch]$AddSharedMailboxes

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

    #Create our base object of recipients using get-msoluser for a 100x or more speed increase, this will be slightly less accurate during the cleanup phase of this object but will ultimately take the whole cmdlet down to a few minutes with 1000 users after initial run provided recipient objects in your environment MOSTLY match the "Name" property with the "Display Name" Property
    [System.Collections.ArrayList]$Recipients = Get-MsolUser -All | Where-Object{$_.IsLicensed -eq $true -and $($_.Licenses.ServiceStatus | Where-Object{$_.ServicePlan.ServiceName -match "EXCHANGE"}).ProvisioningStatus -match "success"}

    #Add any Distribution Groups that are active if flagged to the same Recipients table above with modified Key names for select variables to have a single consistent object for easy looping
    if($AddDistributionGroups){
        Get-DistributionGroup -Filter * | ForEach-Object {
            $Recipients.Add([PSCustomObject]@{'DisplayName'=$_.Name; 'UserPrincipalName' = $_.PrimarySMTPAddress; 'ObjectID'=$_.ExternalDirectoryObjectId})
        } | Out-Null
    }

    #Add any Shared Mailboxes that are active if flagged to the same Recipients table above with modified Key names for select Variables to have a single consistent object for easy looping
    if($AddSharedMailboxes){
        Get-Mailbox -GroupMailbox -RecipientTypeDetails GroupMailbox,RoomMailbox,SchedulingMailbox,SharedMailbox  -Filter * | ForEach-Object {
            $Recipients.Add([PSCustomObject]@{'DisplayName'=$_.Name; 'UserPrincipalName' = $_.PrimarySMTPAddress; 'ObjectID'=$_.ExternalDirectoryObjectId})
        } | Out-Null
    }

    usawritelog -LogLevel SuccessAudit -EventID 0 -Message "Gathering current Trustee $Trustee permissions, this may take awhile"
    #Get all current perms for users
    $CurrentPerms = Get-RecipientPermission -Trustee $Trustee -ResultSize Unlimited | Sort-Object Identity

    #Take all users in CurrentPerms and remove them from the Users Object so we don't push duplicate permissions
    usawritelog -LogLevel SuccessAudit -EventID 0 -Message "Cleaning Permission Object"
    $CurrentPerms | ForEach-Object{
        #For each user check if it's in the Users Object locally and save that as a value

        #Get the object from our $Users MSOnline based object if it exists, due to varying Identity vales checks  DisplayName, ObjectID, SamAccountName,  UserPrincipalName
        $usertoremove = $_.Identity

        #Search through our recipients list to find any users who are already validly permissed objects. Clean up and research twice on Displayname as some objects in the $CurrentPerms object on Add will have two spaces in the DisplayName that cmdlets used for $Recipients lacks
        $Remove = $Recipients | Where-Object{$_.DisplayName -like "$usertoremove" -OR `
                                            $_.ObjectID -eq "$usertoremove" -OR  `
                                            $_.UserPrincipalName.Split('@')[0] -like $usertoremove -OR `
                                            $_.UserPrincipalName -like $usertoremove -OR `
                                            $_.DisplayName.replace("  "," ") -like $usertoremove
                                }

        #If Remove object contains our user to remove remove them from their respective tables
        if($($Remove | Measure-Object).Count -eq 1){ #Remove object from list
            $Recipients.Remove($Remove)
        }
        #If Remove Object contains nothing perform the (MUCH) slower ExchangeOnline based check for the valid permission's user so we can get it's relevant ObjectID
        elseif(($null -eq $Remove -or $Remove -eq "") -and ($RemoveStaleEntries -eq $false -or $null -eq $RemoveStaleEntries)){
            $SecondStageRemove = $null
            $SecondStageRemove = Get-Recipient $_
            #Which if it exists remove it (As it should)
            if($null -ne $SecondStageRemove){
                $Remove = $Recipients | Where-Object{$_.ObjectID -like $SecondStageRemove.ExternalDirectoryObjectId}
                $Recipients.Remove($Remove)
            }
            #Otherwise we can assume there may be issue with the obect permission and can alert the user to rerun with -RemoveStaleEntries to remove it, this MAY fix the issue but
            else{
                usawritelog -LogLevel Warning -EventID 2001 -Message "$usertoremove not found in active recipients, please run with the -RemoveStaleEntries flag to attempt to remove if invalid and rebuild if stale"
            }
        }
        #If Remove is null AND we're removing stale users simply remove the existing permission, if a valid recipient for it exists it will be recreated on add
        elseif(($null -eq $Remove -or $Remove -eq "") -and $RemoveStaleEntries){
            usawritelog -LogLevel Warning -EventID 2003 -Message "$usertoremove not found, removing permission"
            Get-RecipientPermission -Trustee $Trustee -ResultSize Unlimited -Identity $usertoremove | Remove-RecipientPermission -Confirm:$False
        }
        #If for some reason multiple objects come back note them to disregard
        elseif($($Remove | Measure-Object).Count -ge 2){
            usawritelog -LogLevel Warning -EventID 2002 -Message $("Multiple potential Receipients are listed in existing permissions for $Trustee. Will attempt to readd to gurantee all objects have permissions. Consider manually removing permissions from the following and rerunning script to have permissions be added as GUIDS
            "+ $Remove)
        }
        #Standard "Stuff broke please tell me" message
        else{
            usawritelog -LogLevel Error -EventID 2005 -Category InvalidData -Message $("Error when removing known permission from list, expect errors and please report this via https://github.com/Norava/UsagiTools/ . Object Details:
            " + $($Remove | Select-Object *))
        }
    }
    #Then add all the new perms
    usawritelog -LogLevel SuccessAudit -EventID 0 -Message $("Adding permissions for " + $Trustee)
    $Recipients | Sort-Object UserPrincipalName | ForEach-Object{
        usawritelog -LogLevel SuccessAudit -EventID 2004 -Message $("Adding Permission for $Trustee to SendAs " + $_.DisplayName + " with ObjectID of " + $_.ObjectID )
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
    [ValidateSet("AzureAD","ExchangeOnline","MSOnline","SharePoint","SharePointPnP","MicrosoftTeams")]
    [string[]]$Module=("AzureAD","ExchangeOnline","MSOnline","SharePoint","SharePointPnP","MicrosoftTeams"),
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
if($Module -contains "MicrosoftTeams"){
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
     Version 1.0.2
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
            Get-Job -Name $("Usa-" + $Row.ID + "_" + $JobBase) | Remove-Job -Force
        }
    }

    $host.UI.RawUI.CursorPosition = $origpos


    $UpCount ++
    }until($Upcount -eq $Count )
    usawritelog -LogLevel Information -EventID 1020 -Message $($Start + "`n" + $BaseTable)
}

function Get-UsaVMReport{
    <#
    .SYNOPSIS
        Gets VMs from a list of hosts or Hyper-V Clusters along with their Name,Host,CPU Count, RAM (And Dynamic Sizes), Disk Sizes, and attempts to get the IPs of VMs if possible
    .PARAMETER Computer
        Comma Seperated List of all hosts to run this against (REQUIRED)
    .PARAMETER Credentials
        PSCredential Object to use to perform tests
    .PARAMETER LiveStats
        Checks current in use statistics
    .EXAMPLE
        PS> Get-UsaVMReport -Hosts s-cluster
    .EXAMPLE
        PS> Get-UsaVMReport -Hosts HST-01,HST-02,HST-03 -LiveStats
    .NOTES
     Version 1.0.0
#>
Param
(
$Computer,
[System.Management.Automation.PSCredential]
[ValidateNotNull()]
    $Credential = [System.Management.Automation.PSCredential]::Empty,
[switch]$LiveStats
)
function addtoTable{
    Param
        (
            [string]$VMHost,
            [string]$Name,
            [ipaddress]$IP,
            [string]$CPUCount,
            [string]$CPUUsage,
            [string]$RAM,
            [string]$RAMUsage,
            [string]$MemoryPressure,
            [string]$MinimumRAM,
            [string]$MaximumRAM,
            $DiskProv,
            [switch]$LiveStats
        )
        $TableRow =New-Object PSObject
        $TableRow | Add-Member  -Type NoteProperty -Name "VMHost" -Value $VMHost
        $TableRow | Add-Member  -Type NoteProperty -Name "Name" -Value $Name
        $TableRow | Add-Member  -Type NoteProperty -Name "CPU" -Value $CPUCount
        $TableRow | Add-Member  -Type NoteProperty -Name "RAM(GB)" -Value $RAM
        switch ($LiveStats){
            true {
                $TableRow | Add-Member  -Type NoteProperty -Name "CPU Usage" -Value $CPUUsage
                $TableRow | Add-Member  -Type NoteProperty -Name "RAM(GB Used)" -Value $RAMUsage
                $TableRow | Add-Member  -Type NoteProperty -Name "MemPres(%)" -Value $MemoryPressure
                $TableRow | Add-Member  -Type NoteProperty -Name "DiskProv" -Value $DiskProv
            }
            Default {
                $TableRow | Add-Member  -Type NoteProperty -Name "MinimumRAM(GB)" -Value $MinimumRAM
                $TableRow | Add-Member  -Type NoteProperty -Name "MaximumRAM(GB)" -Value $MaximumRAM
                $TableRow | Add-Member  -Type NoteProperty -Name "DiskProv" -Value $DiskProv
            }
        }
        $TableRow | Add-Member  -Type NoteProperty -Name "IP" -Value $IP
        return $TableRow
}
#Create Base Table
$BaseTable  =  @()

usawritelog -EventID 0 -LogLevel Information -Message "Gathering VMs from hosts, Please Wait"
#Loop through $Computer object
$Computer | ForEach-Object{
    usawritelog -EventID 0 -LogLevel Information -Message "Gathering $_"
#Determine if we're pulling livve stats
        if($LiveStats) {
            if($Credential -ne [System.Management.Automation.PSCredential]::Empty -and $Credential -ne ""){
                    $VMs = Invoke-Command -ComputerName $_ -Credential $Credential -ScriptBlock {Get-VM | Select-Object *}
            }
            else{
                    $VMs = Invoke-Command -ComputerName $_ -ScriptBlock {Get-VM | Select-Object *}
            }
            $VMs | ForEach-Object{
                    $TRow = addtoTable `
                        -LiveStats `
                        -VMHost $_.ComputerName `
                        -Name $_.Name `
                        -IP $(($_ | Select-Object -ExpandProperty NetworkAdapters).IPAddresses | Where-Object{$_ -notlike "fe80*" -and $null -ne $_ -and $_ -ne "127.0.0.1"}) `
                        -CPUCount $_.ProcessorCount `
                        -RAM $([math]::Round($($_.MemoryStartup / 1GB),2)) `
                        -CPUUsage $_.CPUUsage `
                        -RAMUsage $([math]::Round($($_.MemoryAssigned / 1GB),2)) `
                        -MemoryPressure $((get-counter  $("\\"+$_.ComputerName+"\hyper-v dynamic memory vm("+$_.VMName+")\average pressure")).CounterSamples.CookedValue) `
                        -DiskProv $(($_  | Select-Object -ExpandProperty HardDrives |Select-Object ComputerName,Path | ForEach-Object{$Path = $_.Path
                            Invoke-Command -ComputerName $_.ComputerName -ScriptBlock {get-vhd $using:Path}}) | Select-Object @{l="Disk";e={$_.Path.split('\')[-1]}},@{l="CurrentSize";e={$([math]::Round($($_.FileSize / 1GB),2))}},@{label="MaxSize";expression={$([math]::Round($($_.Size / 1GB),2))}})
                    $BaseTable += $TRow
                }
        }
            else {
                if($Credential -ne [System.Management.Automation.PSCredential]::Empty -and $Credential -ne ""){
                        $VMs = Invoke-Command -ComputerName $_ -Credential $Credential -ScriptBlock {Get-VM | Select-Object *}
                }
                else {
                        $VMs = Invoke-Command -ComputerName $_ -ScriptBlock {Get-VM | Select-Object *}
                }
            $VMs | ForEach-Object{
                $TRow = addtoTable `
                        -VMHost $_.ComputerName`
                        -Name $_.Name`
                        -IP $(($_ | Select-Object -ExpandProperty NetworkAdapters).IPAddresses | Where-Object{$_ -notlike "fe80*" -and $null -ne $_ -and $_ -ne "127.0.0.1"}) `
                        -CPUCount $_.ProcessorCount `
                        -RAM $([math]::Round($($_.MemoryStartup / 1GB),2)) `
                        -MinimumRAM $([math]::Round($($_.MemoryMinimum / 1GB),2))`
                        -MaximumRAM $([math]::Round($($_.MemoryMaximum / 1GB),2)) `
                        -DiskProv $(($_  | Select-Object -ExpandProperty HardDrives |Select-Object ComputerName,Path | ForEach-Object{$Path = $_.Path
                            Invoke-Command -ComputerName $_.ComputerName -ScriptBlock {get-vhd $using:Path}}) | Select-Object @{l="Disk";e={$_.Path.split('\')[-1]}},@{label="MaxSize";expression={$([math]::Round($($_.Size / 1GB),2))}})
                    $BaseTable += $TRow
                }
        }





    }
 return $BaseTable
}

try{
    $LogCheck = [System.Diagnostics.EventLog]::SourceExists("UsagiTools")
}
catch{
    usawritelog -Message "UsagiTools EventViewer source not found, this normally can be fixed by reimporting once as Admin to enable this otherwise logging will only happen locally in console. Error encountered:" -LogLevel Warning -EventID 1
    usawritelog -Message $_ -LogLevel Error -EventID 0001 -Category WriteError -RecommendedAction "Re import once as Admin"
}
finally{
    If(($LogCheck -eq $false -or $null -eq $LogCheck) -and $(Test-UsaAdministrator) -eq $true ){
        try{
            [System.Diagnostics.EventLog]::CreateEventSource("UsagiTools", "UsagiTools")
            usawritelog -LogLevel Information -EventID 0 -Message "UsagiTools source added to Event Viewer, Event Viewer Service restart or device reboot may be required before writes properly show in log"
        }
        catch{
        usawritelog -Message "Could not create UsagiTools Event source in Event Viewer, potential errors with logging to the Event Viewer may occur" -LogLevel Warning -EventID 0001
        }
    }
$LatestVer = Find-Module UsagiTools -ErrorAction SilentlyContinue
$CurrentVer = Get-Module -ListAvailable UsagiTools | Sort-Object Version
if($Currentver[-1].Version -lt $LatestVer.Version){
    usawritelog -LogLevel Warning -EventID 1 -Message $("New Version of UsagiTools is available, please run Update-Module UsagiTools as an admin  to update your version " + $CurrentVer[-1].Version + " to " + $LatestVer.Version)
}
}
