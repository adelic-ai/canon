variable "location" {
  type        = string
  default     = "eastus"
  description = "Azure region. Pick one close to you; any region with the Server 2025 Gen2 image works."
}

variable "operator_ip" {
  type        = string
  description = "Your current public IPv4, as a CIDR (e.g. 203.0.113.7/32). Get it with: curl -s ifconfig.me. RDP/WinRM are open ONLY to this. Re-run apply if your IP changes."
}

variable "admin_username" {
  type        = string
  default     = "labadmin"
  description = "Local admin for both VMs (becomes the domain Administrator context after promotion)."
}

variable "admin_password" {
  type        = string
  sensitive   = true
  description = "Local admin password. Azure requires 12-123 chars with 3 of {upper,lower,digit,symbol}. Set in terraform.tfvars (gitignored), never commit."
}

variable "vm_size" {
  type        = string
  default     = "Standard_B2s"
  description = "2 vCPU / 4 GB — enough for a lab DC and a member. Bump to Standard_B2ms (8 GB) if promotion feels tight."
}

variable "image_sku" {
  type        = string
  default     = "2025-datacenter-g2"
  description = "Windows Server marketplace SKU (Gen2). 2025 gives the freshest patch baseline, so the ticket-hash CU is already in the image; script 02 still forces Windows Update to be sure."
}
