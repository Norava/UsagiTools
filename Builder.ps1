#Builder cause NestedModules documentation BLATANTLY LIES
$Base = "<#USAGITOOLS MODULE
CTRL-F to find base info, modules included:
Internal Module
Identity Module
Misc Module
#>
"

$End = '
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
}'
Remove-Item .\UsagiTools.psm1
New-Item UsagiTools.psm1
$Base | Add-Content .\UsagiTools.psm1
Get-ChildItem .\Private -filter *.psm1 | Get-Content | Add-Content .\UsagiTools.psm1
Get-ChildItem .\Public -filter *.psm1 | Sort-Object Name | Get-Content | Add-Content .\UsagiTools.psm1
$End | Add-Content .\UsagiTools.psm1