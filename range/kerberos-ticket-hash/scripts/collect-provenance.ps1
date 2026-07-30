# Run ON dc01 AND mbr01 BEFORE the capture. Records the experiment's independent
# variable — the exact patch level — plus audit/time state, so "patched DC" is
# evidence, not an assumption. Writes one JSON per host into C:\capture\run-<id>.

param([string]$RunId = (Get-Date -Format "yyyyMMdd-HHmmss"))
$ErrorActionPreference = "Continue"
$dir = "C:\capture\run-$RunId"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$host_tag = $env:COMPUTERNAME.ToLower()

$os = Get-CimInstance Win32_OperatingSystem
$prov = [ordered]@{
    host            = $env:COMPUTERNAME
    collected_at    = (Get-Date).ToString("o")
    os_caption      = $os.Caption
    os_version      = $os.Version                      # build number — the patch-level proof
    ubr             = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").UBR
    hotfixes        = @(Get-HotFix | Sort-Object InstalledOn -Descending |
                        Select-Object HotFixID, @{n='InstalledOn';e={$_.InstalledOn.ToString('o')}})
    audit_kerberos  = @{
                        as_service  = (auditpol /get /subcategory:"Kerberos Authentication Service" /r | ConvertFrom-Csv)
                        tgs_ops     = (auditpol /get /subcategory:"Kerberos Service Ticket Operations" /r | ConvertFrom-Csv)
                       }
    time_sync       = (w32tm /query /status 2>&1 | Out-String)
    is_dc           = [bool](Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4
}
$prov | ConvertTo-Json -Depth 6 | Set-Content "$dir\$host_tag-provenance.json" -Encoding utf8
Write-Host "[+] $dir\$host_tag-provenance.json" -ForegroundColor Green
Write-Host "    build=$($os.Version).$($prov.ubr)  hotfixes=$($prov.hotfixes.Count)" -ForegroundColor Cyan
Write-Host "    Run 06 with -RunId $RunId so the capture lands in the same run dir." -ForegroundColor Yellow
