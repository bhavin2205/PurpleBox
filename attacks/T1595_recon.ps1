# T1595 - Reconnaissance Simulation Script
Write-Output "Running recon techniques..."

Resolve-DnsName example.com
Invoke-RestMethod -Uri http://example.com -Method Get
Test-Connection google.com -Count 1
