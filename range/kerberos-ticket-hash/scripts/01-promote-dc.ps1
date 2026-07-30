# Run ON dc01, in an elevated PowerShell, over RDP.
# Installs AD DS and promotes dc01 to the first DC of a new forest: corp.local.
# The VM REBOOTS at the end. After it comes back, log in as CORP\labadmin and
# run 02-enable-auditing.ps1.

$ErrorActionPreference = "Stop"
$DomainName    = "corp.local"
$NetbiosName   = "CORP"
# DSRM (Directory Services Restore Mode) password — lab-only, reuse the admin pass.
$SafeModePass  = Read-Host "DSRM password (can match the admin password)" -AsSecureString

Write-Host "[*] Installing AD DS role..." -ForegroundColor Cyan
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools

Write-Host "[*] Promoting to a new forest: $DomainName ..." -ForegroundColor Cyan
Import-Module ADDSDeployment
Install-ADDSForest `
    -DomainName $DomainName `
    -DomainNetbiosName $NetbiosName `
    -ForestMode "WinThreshold" `
    -DomainMode "WinThreshold" `
    -InstallDns `
    -SafeModeAdministratorPassword $SafeModePass `
    -NoRebootOnCompletion:$false `
    -Force

# (control does not return here — the box reboots)
