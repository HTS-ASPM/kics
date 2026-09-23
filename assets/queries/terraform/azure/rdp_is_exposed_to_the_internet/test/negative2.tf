resource "azurerm_network_security_group" "negative2" {
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
    destination_port_range     = "3389"
    source_address_prefix      = "10.0.0.0/16"
    destination_address_prefix = "*"
  }
}
