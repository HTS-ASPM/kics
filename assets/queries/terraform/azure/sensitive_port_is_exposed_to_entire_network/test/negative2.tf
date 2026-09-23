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
    source_address_prefix      = "10.1.0.0/16"
    destination_address_prefix = "*"
  }
}

resource "azurerm_network_security_rule" "negative3" {
  name                        = "negative3"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "1433"
  source_address_prefix       = "AzureLoadBalancer"
  destination_address_prefix  = "*"
  resource_group_name         = "example"
  network_security_group_name = "example"
}
