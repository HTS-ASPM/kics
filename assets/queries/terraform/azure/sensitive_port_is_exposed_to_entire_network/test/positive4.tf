resource "azurerm_network_security_rule" "positive4" {
  name                        = "positive4"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "5432"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = "example"
  network_security_group_name = "example"
}

resource "azurerm_network_security_rule" "positive5" {
  name                        = "positive5"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "6379"
  source_address_prefix       = "Internet"
  destination_address_prefix  = "*"
  resource_group_name         = "example"
  network_security_group_name = "example"
}
