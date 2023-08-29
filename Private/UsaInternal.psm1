#USAGI TOOLS INT MODULE
#VERSION 0.3.0
#Various Powershell tools designed to serve as either internal functions (labeled as usaverbNoun) (Expect slightly less professional comments here be monsters)
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
    .VERSION
    1.0.0
#>
        Param
        (
        [string]$modulerequested,
        [ValidateSet('O365')]
        [string[]]
        $moduleset
)
        Write-Host "Attempting import of $modulerequested"
        $modinstalled = Get-InstalledModule $modulerequested
        if($null -eq $modinstalled -or $modinstalled -eq ""){
            $Choices = @("Yes","No")
            $installmod = $Host.UI.PromptForChoice("Install Module?","Module $modulerequested not found, proceed with installation?",$Choices,1)
            if($installmod -eq 0){
                if($moduleset -eq "O365"){Install-UsaOffice365Modules -Module $modulerequested}
                try{
                    Import-Module $modulerequested
                }
                catch{
                Write-Host $_.Exception.Message -ForegroundColor Red
                return 2
                }
                return 1}
            else{
                write-host "Module $modulerequested not found, Skipping"
                return 0}
            }
        elseif($null -ne $modinstalled -and $modinstalled -ne ""){
            Import-Module $modulerequested
            return 1 }
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
    .VERSION
    1.0.0
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
        elseif($null -ne $modinstalled -and $modinstalled -ne "" -and $doupdate -eq $true){
            Update-Module $modulerequested 
            }
        elseif($null -ne $modinstalled -and $modinstalled -ne ""){
            Write-Host "$modulerequested Module already installed, Skipping" 
            }
        }
