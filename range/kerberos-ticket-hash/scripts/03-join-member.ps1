# Run ON mbr01, elevated. Joins mbr01 to corp.local and reboots.
# The NIC already points DNS at the DC (Terraform set dns_servers = dc_ip), so
# the domain resolves. After reboot, log in as CORP\labadmin.

$ErrorActionPreference = "Stop"
$Domain = "corp.local"

Write-Host "[*] DNS check — must resolve the DC:" -ForegroundColor Cyan
Resolve-DnsName $Domain -Type SRV -ErrorAction SilentlyContinue | Select-Object -First 3 Name, IP4Address

$cred = Get-Credential -Message "CORP\labadmin (domain admin)"
Write-Host "[*] Joining $Domain ..." -ForegroundColor Cyan
Add-Computer -DomainName $Domain -Credential $cred -Restart -Force
# (reboots)
