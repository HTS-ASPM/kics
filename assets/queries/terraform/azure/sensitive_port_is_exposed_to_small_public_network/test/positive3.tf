resource "azurerm_network_security_group" "positive3" {
  name                = "positive3"
  location            = "West Europe"
  resource_group_name = "example"

  security_rule {
    name                       = "positive3-app"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "8443"
    source_address_prefix      = "198.51.100.0/28"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "positive3-db"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3306"
    source_address_prefix      = "198.51.100.0/28"
    destination_address_prefix = "*"
  }
}
