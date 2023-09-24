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
        PS> usamoduleimport -modulerequested ExchangeOnline -moduleset O365
    .NOTES
    Version 1.0.0
    EventID
    0   : Verbose audit message
    1001: Azure AD Module was unable to install and import, manual import or reinstall module
    1002: Exchange Online Module was unable to install and import, manual import or reinstall module
    1003: Sharepoint Online Module was unable to install and import, manual import or reinstall module
    1004: Sharepoint PNP Module was unable to install and import, manual import or reinstall module
    1005: Teams Module was unable to install and import, manual import or reinstall module
    1010: No German Servers for this cmdlet exist per documentation as of writing
    1020: Output of Test-UsaNetwork
    2001: User couldn't be added via Add-UsaUserSendasGlobally 's Get-ReciepientPermission -trustee $Trustee. User possibly is manually set without a license, consider cleaning from group
    2002: No German Servers for this cmdlet exist per documentation as of writing
    2010: Invalid group for Set-UsaDynamicGroupMember, validate group via get-adgroup
    2011: Could not validate User OU to add for Set-UsaDynamicGroupMember, validate via Get-ADOrganizationUnit
    2012: Could not validate Computer OU to add for Set-UsaDynamicGroupMember, validate via Get-ADOrganizationUnit
    2013: Set-UsaDynamicGroupMember group validation error stating you're unable to nest a parent level group in a child

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