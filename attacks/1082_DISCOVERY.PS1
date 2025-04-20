# T1082_discovery.ps1
Write-Output "Running system discovery technique (T1082)"
Get-ComputerInfo | Out-Null
