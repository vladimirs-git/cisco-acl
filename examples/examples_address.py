"""**Address(line)**
The following example demonstrates Address object.
"""

from ipaddress import ip_network

from cisco_acl import Address

addr = Address("10.0.0.0 0.0.0.3", platform="ios")
assert addr.line == "10.0.0.0 0.0.0.3"
assert addr.platform == "ios"
assert addr.addrgroup == ""
assert addr.prefix == "10.0.0.0/30"
assert addr.subnet == "10.0.0.0 255.255.255.252"
assert addr.wildcard == "10.0.0.0 0.0.0.3"
assert addr.ipnet == ip_network("10.0.0.0/30")

# Change syntax from Cisco IOS platform to Cisco Nexus NX-OS.
addr = Address("10.0.0.0 0.0.0.3", platform="ios")
assert addr.line == "10.0.0.0 0.0.0.3"
addr.platform = "nxos"
assert addr.line == "10.0.0.0/30"

addr = Address("host 10.0.0.1", platform="ios")
assert addr.line == "host 10.0.0.1"
addr.platform = "nxos"
assert addr.line == "10.0.0.1/32"

addr = Address("object-group NAME", platform="ios")
assert addr.line == "object-group NAME"
addr.platform = "nxos"
assert addr.line == "addrgroup NAME"
