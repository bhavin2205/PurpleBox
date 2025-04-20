# T1059_powershell.ps1
# Simulates basic PowerShell execution (MITRE ATT&CK T1059.001)

Write-Output "Running simulated PowerShell technique (T1059)"
Get-Process | Out-Null
Start-Sleep -Seconds 1
