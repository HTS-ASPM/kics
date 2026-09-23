resource "azurerm_network_security_group" "positive2" {
  name                = "single-inline-rule"
  location            = "West Europe"
  resource_group_name = "example"

  security_rule {
    name                       = "only-rule"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}
