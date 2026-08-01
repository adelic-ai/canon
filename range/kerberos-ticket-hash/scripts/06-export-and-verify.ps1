# Run ON dc01 (and repeat on mbr01 for the silver-ticket 4624s), elevated.
# Exports the Security log and — the whole point of the range — prints the RAW
# <Data Name=...> element names inside 4768/4769 so we can confirm what the
# ticket-hash fields are actually called and kill the PROVISIONAL guess in
# detection/kerberos_tickets.py.
#
# Pass the SAME -RunId used for collect-provenance.ps1 so capture + provenance +
# action markers land in one immutable run dir (not overwriting C:\capture).

param([string]$RunId)
$ErrorActionPreference = "Stop"
if (-not $RunId) { $RunId = (Get-Date -Format "yyyyMMdd-HHmmss") }
$Out = "C:\capture\run-$RunId"
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$host_tag = $env:COMPUTERNAME.ToLower()

# 1. Raw EVTX (archival) --------------------------------------------------
wevtutil epl Security "$Out\$host_tag-security.evtx" "/q:*[System[(EventID=4768 or EventID=4769 or EventID=4624)]]"

# 2. THE CONFIRMATION: dump every distinct EventData field name on 4768/4769
Write-Host "`n===== distinct <Data Name=...> fields on 4768/4769 =====" -ForegroundColor Green
$names = @{}
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4768,4769} -MaxEvents 200 | ForEach-Object {
    ([xml]$_.ToXml()).Event.EventData.Data | ForEach-Object { $names[$_.Name] = $true }
}
$names.Keys | Sort-Object | ForEach-Object { Write-Host "  $_" }
Write-Host "  ^ look for the hash fields — likely 'TicketHash' / 'RequestTicketHash' /" -ForegroundColor Yellow
Write-Host "    'ResponseTicketHash' or similar. Whatever they are, that's the truth." -ForegroundColor Yellow

# 3. Flatten to JSONL the Python bridge consumes (evtx_to_events.py) -------
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4768,4769,4624} | ForEach-Object {
    $x = [xml]$_.ToXml()
    $h = @{ EventID = "$($_.Id)"; TimeCreated = $_.TimeCreated.ToString("o") }
    foreach ($d in $x.Event.EventData.Data) { $h[$d.Name] = $d.'#text' }
    $h | ConvertTo-Json -Compress
} | Set-Content "$Out\$host_tag-events.jsonl" -Encoding utf8

Write-Host "`n[+] Wrote $Out\$host_tag-security.evtx and $host_tag-events.jsonl" -ForegroundColor Green
Write-Host "    Copy both back to the Mac (scp / RDP drive redirection) for the detector." -ForegroundColor Green
