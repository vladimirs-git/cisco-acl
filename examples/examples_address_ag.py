"""**AddressAg(line)**
The following example demonstrates Address object.
"""

from ipaddress import IPv4Network

from cisco_acl import AddressAg, address_ag

addr = AddressAg("10.0.0.0 255.255.255.252", platform="ios")
assert addr.line == "10.0.0.0 255.255.255.252"
assert addr.platform == "ios"
assert addr.addrgroup == ""
assert addr.prefix == "10.0.0.0/30"
assert addr.subnet == "10.0.0.0 255.255.255.252"
assert addr.wildcard == "10.0.0.0 0.0.0.3"
assert addr.ipnet == IPv4Network("10.0.0.0/30")

# Change syntax from Cisco IOS platform to Cisco Nexus NX-OS.
addr = AddressAg("10.0.0.0 255.255.255.252", platform="ios")
assert addr.line == "10.0.0.0 255.255.255.252"
addr.platform = "nxos"
assert addr.line == "10.0.0.0/30"

addr = AddressAg("host 10.0.0.1", platform="ios")
assert addr.line == "host 10.0.0.1"
addr.platform = "nxos"
assert addr.line == "10.0.0.1/32"

# AddressAg with items
addr = AddressAg("group-object NAME", items=["host 10.0.0.1", "host 10.0.0.2"])
print("line", addr.line)
print("platform", addr.platform)
print("addrgroup", addr.addrgroup)
print("prefixes", addr.prefixes())
print("wildcards", addr.wildcards())
print("ipnets", addr.ipnets())
print()
# line group-object NAME
# platform ios
# addrgroup NAME
# prefixes ["10.0.0.1/32", "10.0.0.2/32"]
# wildcards ["10.0.0.1 0.0.0.0", "10.0.0.2 0.0.0.0"]
# ipnets [IPv4Network("10.0.0.1/32"), IPv4Network("10.0.0.2/32")]


# AddressAg.is_subnet()
addr = AddressAg("10.0.0.0/24", platform="nxos")
subnet = AddressAg("10.0.0.0/30", platform="nxos")
result = addr.subnet_of(subnet)
assert subnet.subnet_of(addr) is True
assert addr.subnet_of(subnet) is False

# address_ag.collapse()
wildcard = AddressAg("10.0.0.0 255.255.255.254")
host2 = AddressAg("host 10.0.0.2")
host3 = AddressAg("host 10.0.0.3")
collapsed = address_ag.collapse([wildcard, host2, host3])
print("collapsed", collapsed)  # collapsed [AddressAg("10.0.0.0 255.255.255.252")]
print()
