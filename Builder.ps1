#Builder cause NestedModules documentation BLATANTLY LIES
$Base = "<#USAGITOOLS MODULE
CTRL-F to find base info, modules included:
Internal Module
Identity Module
Misc Module
#>
"

Remove-Item .\UsagiTools.psm1
New-Item UsagiTools.psm1
$Base | Add-Content .\UsagiTools.psm1
gci .\Private -filter *.psm1 | Get-Content | Add-Content .\UsagiTools.psm1
gci .\Public -filter *.psm1 | sort Name | Get-Content | Add-Content .\UsagiTools.psm1
