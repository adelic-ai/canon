output "dc_public_ip" {
  value       = azurerm_public_ip.dc.ip_address
  description = "Public IP of dc01."
}

output "member_public_ip" {
  value       = azurerm_public_ip.mbr.ip_address
  description = "Public IP of mbr01."
}

output "dc_private_ip" {
  value       = local.dc_ip
  description = "Private IP of dc01 (the member's DNS server)."
}

output "rdp_dc" {
  value       = "open 'rdp://full address=s:${azurerm_public_ip.dc.ip_address}:3389&username=s:${var.admin_username}'"
  description = "macOS: paste into Terminal to launch Microsoft Remote Desktop against dc01."
}

output "rdp_member" {
  value       = "open 'rdp://full address=s:${azurerm_public_ip.mbr.ip_address}:3389&username=s:${var.admin_username}'"
  description = "macOS: RDP to mbr01."
}
