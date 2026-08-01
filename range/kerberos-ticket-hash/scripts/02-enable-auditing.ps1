# Run ON dc01 (after promotion + reboot), elevated, as CORP\labadmin.
# 1) Force the DC fully patched so the 4768/4769 "Ticket Information" hash
#    fields are present (they ship in the Jan-2025 CU and later).
# 2) Turn on Kerberos success+failure auditing so 4768/4769 are actually logged.
# 3) Create a test user and the CIFS service principal we'll forge against.

$ErrorActionPreference = "Stop"

Write-Host "[*] Current build / patch level:" -ForegroundColor Cyan
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5 HotFixID, InstalledOn
[System.Environment]::OSVersion.Version

Write-Host "[*] Forcing Windows Update (guarantees the ticket-hash CU)..." -ForegroundColor Cyan
try {
    Install-PackageProvider -Name NuGet -Force -Scope CurrentUser | Out-Null
    Install-Module PSWindowsUpdate -Force -Scope CurrentUser -AllowClobber
    Import-Module PSWindowsUpdate
    Get-WindowsUpdate -AcceptAll -Install -IgnoreReboot
    Write-Host "    (reboot with Restart-Computer if updates were installed, then re-run from here)" -ForegroundColor Yellow
} catch {
    Write-Host "    PSWindowsUpdate unavailable; run 'sconfig' -> option 6 to patch manually." -ForegroundColor Yellow
}

Write-Host "[*] Enabling Kerberos auditing (4768 AS-REQ, 4769 TGS-REQ)..." -ForegroundColor Cyan
auditpol /set /subcategory:"Kerberos Authentication Service"   /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Logon"                             /success:enable /failure:enable
Write-Host "[*] Verify:" -ForegroundColor Cyan
auditpol /get /category:"Account Logon","Logon/Logoff"

Write-Host "[*] Creating lab principals..." -ForegroundColor Cyan
Import-Module ActiveDirectory
$pw = Read-Host "password for the test user 'alice' and svc account" -AsSecureString
if (-not (Get-ADUser -Filter "SamAccountName -eq 'alice'")) {
    New-ADUser -Name "alice" -SamAccountName "alice" -AccountPassword $pw -Enabled $true -PasswordNeverExpires $true
}
# A service account to carry the CIFS SPN we'll silver-ticket against.
if (-not (Get-ADUser -Filter "SamAccountName -eq 'svc_cifs'")) {
    New-ADUser -Name "svc_cifs" -SamAccountName "svc_cifs" -AccountPassword $pw -Enabled $true -PasswordNeverExpires $true
    setspn -S CIFS/dc01.corp.local svc_cifs
}
Write-Host "[+] DC ready. Next: RDP to mbr01 and run 03-join-member.ps1" -ForegroundColor Green
