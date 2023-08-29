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
