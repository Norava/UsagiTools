# UsagiTools
Simple Scripts to get random things done. Most if not all cmdlets are documented through Get-Help

Identity
	Module for scripts related to identity systems (Active Directory, Azure Active Directory, Local Users etc) and the management of such systems (AAD Connect for example)
	
	Add-UsaUserSendasGlobally
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




  
Misc
	Random bits and baubles that don't have a proper category yet
	
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
