package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
	resource := input.document[i].resource.azurerm_network_security_rule[name]

	portContent := common_lib.tcpPortsMap[port]
	portNumber = port
	portName = portContent
	protocol := tf_lib.getProtocolList(resource.protocol)[_]

	upper(resource.access) == "ALLOW"
	upper(resource.direction) == "INBOUND"

	common_lib.isPrivateIP(resource.source_address_prefix)
	tf_lib.containsPort(resource, portNumber)
	isTCPorUDP(protocol)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "azurerm_network_security_rule",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("azurerm_network_security_rule[%s].destination_port_range", [name]),
		"searchValue": sprintf("%s:%d", [protocol, portNumber]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("%s (%s:%d) should not be allowed", [portName, protocol, portNumber]),
		"keyActualValue": sprintf("%s (%s:%d) is allowed", [portName, protocol, portNumber]),
		"searchLine": common_lib.build_search_line(["resource", "azurerm_network_security_rule", name, "destination_port_range"], []),
	}
}

# Same check for rules declared inline in the NSG (azurerm_network_security_group.security_rule).
CxPolicy[result] {
	group := input.document[i].resource.azurerm_network_security_group[groupName]
	resource := security_rules(group)[idx]

	portContent := common_lib.tcpPortsMap[port]
	portNumber = port
	portName = portContent
	protocol := tf_lib.getProtocolList(resource.protocol)[_]

	upper(resource.access) == "ALLOW"
	upper(resource.direction) == "INBOUND"

	common_lib.isPrivateIP(resource.source_address_prefix)
	tf_lib.containsPort(resource, portNumber)
	isTCPorUDP(protocol)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "azurerm_network_security_group",
		"resourceName": tf_lib.get_resource_name(resource, [groupName, "security_rule", idx]),
		"searchKey": sprintf("azurerm_network_security_group[%s].security_rule.name={{%s}}.destination_port_range", [groupName, resource.name]),
		"searchValue": sprintf("%s:%d", [protocol, portNumber]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("%s (%s:%d) should not be allowed", [portName, protocol, portNumber]),
		"keyActualValue": sprintf("%s (%s:%d) is allowed", [portName, protocol, portNumber]),
	}
}

isTCPorUDP("TCP") = true

isTCPorUDP("UDP") = true

# HCL gives a list for several inline security_rule blocks and a single object for one.
security_rules(group) = rules {
	is_array(group.security_rule)
	rules := group.security_rule
} else = rules {
	is_object(group.security_rule)
	rules := [group.security_rule]
}
