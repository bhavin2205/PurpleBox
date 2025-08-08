# T1046 - Scanning & Enumeration Simulation Script
Write-Output "Running scanning/enumeration simulation..."

# Network and port discovery
Get-NetTCPConnection
netstat -an
Get-NetRoute
ipconfig /all

# Process and service enumeration
Get-Service
Get-Process
tasklist

# User and group information
whoami
net user
net localgroup
Get-LocalUser
Get-LocalGroup
Get-LocalGroupMember -Group "Administrators"

# System info
systeminfo
hostname

# Share and session enumeration
net view
net use
net session
