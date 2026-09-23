resource "azurerm_network_security_group" "positive2" {
  name                = "positive2"
  location            = "West Europe"
  resource_group_name = "example"

  security_rule {
    name                       = "positive2-rule"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "1433"
    source_address_prefix      = "10.0.0.0/8"
    destination_address_prefix = "*"
  }
}
