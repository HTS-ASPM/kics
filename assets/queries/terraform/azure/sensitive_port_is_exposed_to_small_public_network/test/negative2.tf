resource "azurerm_network_security_group" "negative2" {
  name                = "negative2"
  location            = "West Europe"
  resource_group_name = "example"

  security_rule {
    name                       = "negative2-rule"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "1433"
    source_address_prefix      = "203.0.113.5/32"
    destination_address_prefix = "*"
  }
}
