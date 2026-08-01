# Kerberos ticket-hash test range — Azure infra.
# Two Windows Server 2025 VMs on an isolated /24: dc01 (promoted to a DC in
# script 01) and mbr01 (domain-joined member + attacker host). RDP/WinRM are
# reachable ONLY from your current public IP (var.operator_ip). Everything the
# range does to Windows/AD happens in scripts/*.ps1 run over RDP — Terraform
# only stands up the boxes.

terraform {
  required_version = ">= 1.5"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

provider "azurerm" {
  features {}
  # Fresh subscriptions: don't let the provider silently block on auto-registering
  # resource providers during plan. We register the two we need by hand (see README).
  resource_provider_registrations = "none"
}

locals {
  prefix   = "krbhash"
  dc_ip    = "10.42.1.10" # static, out of the low range Azure hands to dynamic NICs (.4+) — avoids a create-order IP collision with the dynamic member NIC
  tags     = { project = "canon", range = "kerberos-ticket-hash", disposable = "true" }
}

resource "azurerm_resource_group" "rg" {
  name     = "${local.prefix}-rg"
  location = var.location
  tags     = local.tags
}

resource "azurerm_virtual_network" "vnet" {
  name                = "${local.prefix}-vnet"
  address_space       = ["10.42.0.0/16"]
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  tags                = local.tags
}

resource "azurerm_subnet" "lab" {
  name                 = "lab"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.42.1.0/24"]
}

# --- NSG: RDP + WinRM only from the operator; intra-subnet is open (default) ---
resource "azurerm_network_security_group" "nsg" {
  name                = "${local.prefix}-nsg"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  tags                = local.tags

  security_rule {
    name                       = "allow-rdp-operator"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = var.operator_ip
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "allow-winrm-operator"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "5986"
    source_address_prefix      = var.operator_ip
    destination_address_prefix = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "assoc" {
  subnet_id                 = azurerm_subnet.lab.id
  network_security_group_id = azurerm_network_security_group.nsg.id
}

# --- Public IPs (Standard/static) ---
resource "azurerm_public_ip" "dc" {
  name                = "${local.prefix}-dc-pip"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.tags
}

resource "azurerm_public_ip" "mbr" {
  name                = "${local.prefix}-mbr-pip"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.tags
}

# --- NICs. The member's DNS points at the DC so it can find the domain. ---
resource "azurerm_network_interface" "dc" {
  name                = "${local.prefix}-dc-nic"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  tags                = local.tags

  ip_configuration {
    name                          = "ipcfg"
    subnet_id                     = azurerm_subnet.lab.id
    private_ip_address_allocation = "Static"
    private_ip_address            = local.dc_ip
    public_ip_address_id          = azurerm_public_ip.dc.id
  }
}

resource "azurerm_network_interface" "mbr" {
  name                = "${local.prefix}-mbr-nic"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  dns_servers         = [local.dc_ip] # resolve corp.local via the DC
  tags                = local.tags

  ip_configuration {
    name                          = "ipcfg"
    subnet_id                     = azurerm_subnet.lab.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.mbr.id
  }
}

# --- VMs. Server 2025 Datacenter (Gen2). Confirm the SKU is offered in your
#     region with:  az vm image list --publisher MicrosoftWindowsServer \
#     --offer WindowsServer --sku 2025-datacenter-g2 --all -o table ---
resource "azurerm_windows_virtual_machine" "dc" {
  name                = "dc01"
  computer_name       = "dc01"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  size                = var.vm_size
  admin_username      = var.admin_username
  admin_password      = var.admin_password
  network_interface_ids = [azurerm_network_interface.dc.id]
  tags                = local.tags

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
  }
  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = var.image_sku
    version   = "latest"
  }
}

resource "azurerm_windows_virtual_machine" "mbr" {
  name                = "mbr01"
  computer_name       = "mbr01"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  size                = var.vm_size
  admin_username      = var.admin_username
  admin_password      = var.admin_password
  network_interface_ids = [azurerm_network_interface.mbr.id]
  tags                = local.tags

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
  }
  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = var.image_sku
    version   = "latest"
  }
}
