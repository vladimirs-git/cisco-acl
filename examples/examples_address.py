"""**Address(line)**
The following example demonstrates Address object.
"""

from ipaddress import IPv4Network

from cisco_acl import Address, address

addr = Address("10.0.0.0 0.0.0.3", platform="ios")
assert addr.line == "10.0.0.0 0.0.0.3"
assert addr.platform == "ios"
assert addr.addrgroup == ""
assert addr.prefix == "10.0.0.0/30"
assert addr.subnet == "10.0.0.0 255.255.255.252"
assert addr.wildcard == "10.0.0.0 0.0.0.3"
assert addr.ipnet == IPv4Network("10.0.0.0/30")

# Change syntax from Cisco IOS platform to Cisco Nexus NX-OS.
addr = Address("10.0.0.0 0.0.0.3", platform="ios")
assert addr.line == "10.0.0.0 0.0.0.3"
addr.platform = "nxos"
assert addr.line == "10.0.0.0/30"

addr = Address("object-group NAME", platform="ios")
assert addr.line == "object-group NAME"
addr.platform = "nxos"
assert addr.line == "addrgroup NAME"

# Address.ipnets() Address.prefixes() Address.subnets() Address.wildcards()
addr = Address("addrgroup NAME", platform="nxos", items=["10.0.0.0/30", "10.0.0.4/30"])
print("ipnets", addr.ipnets())
print("prefixes", addr.prefixes())
print("subnets", addr.subnets())
print("wildcards", addr.wildcards())
print()
# ipnets [IPv4Network("10.0.0.0/30"), IPv4Network("10.0.0.4/30")]
# prefixes ["10.0.0.0/30", "10.0.0.4/30"]
# subnets ["10.0.0.0 255.255.255.252", "10.0.0.4 255.255.255.252"]
# wildcards ["10.0.0.0 0.0.0.3", "10.0.0.4 0.0.0.3"]


# Address.is_subnet()
addr = Address("10.0.0.0/24", platform="nxos")
subnet = Address("10.0.0.0/30", platform="nxos")
result = addr.subnet_of(subnet)
assert subnet.subnet_of(addr) is True
assert addr.subnet_of(subnet) is False

# address.collapse()
wildcard = Address("10.0.0.0 0.0.0.1")
host2 = Address("host 10.0.0.2")
host3 = Address("host 10.0.0.3")
collapsed = address.collapse([wildcard, host2, host3])
print("collapsed", collapsed)  # collapsed [Address("10.0.0.0 0.0.0.3")]
print()
