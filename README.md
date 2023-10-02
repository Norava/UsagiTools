# UsagiTools
Simple Scripts to get random things done. Most if not all cmdlets are documented through Get-Help

Script for many modules logs information an UsagiTools log source for automation against log. 

Current EventIDs:
	EventID
	0   : Verbose audit message
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
	2009: Output for Set-UsaDynamic group citing group worked on
	2010: Invalid group for Set-UsaDynamicGroupMember, validate group via get-adgroup
	2011: Could not validate User OU to add for Set-UsaDynamicGroupMember, validate via Get-ADOrganizationUnit
	2012: Could not validate Computer OU to add for Set-UsaDynamicGroupMember, validate via Get-ADOrganizationUnit
	2013: Set-UsaDynamicGroupMember group validation error stating you're unable to nest a parent level group in a child
	2014: Could not import Active Directory Module

Identity
	Module for scripts related to identity systems (Active Directory, Azure Active Directory, Local Users etc) and the management of such systems (AAD Connect for example)
	
	Add-UsaUserSendasGlobally
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


	Set-UsaDynamicGroupMember

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

  
Misc
	Random bits and baubles that don't have a proper category yet
	Has Event IDs 1000-1999 assigned as follows
	
	Connect-UsaOffice365Service
		.SYNOPSIS
			Logs into  Office 365 Services
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

	Get-UsaPublicIP
		.SYNOPSIS
			Simple script to pull public IP using IPify for Windows PCs. Also supports remote PC IP Lookup (In the instance you want to check a NAT rule or something)
		.PARAMETER Computer
			Runs cmdlet again a remote Windows PC and returns
		.EXAMPLE
			PS> Get-UsaPublicIP -Computer Srv-DC1.contoso.loc
		.EXAMPLE
			PS> Get-UsaPublicIP -Computer Srv-DC1.Contoso.loc -Credential $(Get-Credential)

	Install-UsaOffice365Module
    
		.SYNOPSIS
			Installs Office 365 Modules
		.PARAMETER Module
			Select which services to install modules for, defaults to AzureAD, ExchangeOnline, MSonline, Sharepoint, SharepointPNP, Teams (Or all available options)
		.PARAMETER Update
			Run Updates on selected Modules

		.EXAMPLE
			PS> Install-UsaOffice365Module
		.EXAMPLE
			PS> Install-UsaOffice365Module -Module AzureAD
		.EXAMPLE
			PS> Install-UsaOffice365Module -Module AzureAD -Update

	Test-UsaAdministrator
    .SYNOPSIS
        Simple script to test if the current user is Admin, returns $true if the user is an admin
    .EXAMPLE
        PS> Test-UsaAdministrator

	Test-UsaNetwork{
    .SYNOPSIS
        Pings multiple in the environment to path test
    .PARAMETER Computer
        Remote Computer to run against
    .PARAMETER Credential
        Credentials to use with Computer Flag
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
