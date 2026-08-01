# Run ON mbr01 as CORP\alice (or run the loop after 'runas /user:CORP\alice').
# Generates BENIGN Kerberos traffic: real AS-REQ (4768), TGS-REQ (4769), and
# interactive/network logons (4624). This is the clean baseline the detector
# must NOT flag — every 4769 here has a matching 4768 from the same host.

$ErrorActionPreference = "Continue"

Write-Host "[*] Purging any cached tickets, then forcing fresh AS/TGS exchanges..." -ForegroundColor Cyan
for ($i = 0; $i -lt 5; $i++) {
    klist purge | Out-Null
    # Touch the DC's SYSVOL share -> TGS-REQ for CIFS/dc01 -> 4769 + 4624
    Get-ChildItem "\\dc01.corp.local\SYSVOL" -ErrorAction SilentlyContinue | Out-Null
    # An LDAP bind -> TGS for LDAP/dc01
    Get-ADUser -Filter * -Server dc01.corp.local -ErrorAction SilentlyContinue | Out-Null
    klist | Select-String "Server:" | Select-Object -First 3
    Start-Sleep -Seconds 2
}
Write-Host "[+] Baseline traffic done. All 4769s here have a legit 4768 from this host." -ForegroundColor Green
