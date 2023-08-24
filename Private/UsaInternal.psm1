#USAGI TOOLS INT MODULE
#VERSION 0.1.0
#Various Powershell tools designed to serve as either internal functions (labeled as usaverbNoun)
    function usamoduleimport{
        Param
        (
        [string]$modulerequested,
        [ValidateSet('O365')]
        [string[]]
        $moduleset
)
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
