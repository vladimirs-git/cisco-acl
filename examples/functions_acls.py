"""Create Acl objects based on the "show running-config" output.

Each ACE line is treated as an independent Ace element.
"""
from pprint import pprint

import cisco_acl

config = """
hostname HOSTNAME
 
ip access-list extended ACL_NAME
  permit tcp 10.0.0.0 0.0.0.255 any eq 21 22 23
  permit tcp host 10.0.0.1 any eq 21
  deny tcp object-group ADDR_GROUP any eq 53
  permit icmp any any
  
object-group network ADDR_GROUP 
 10.1.1.0 255.255.255.252
 host 10.1.1.4
 
interface Ethernet1
  ip access-group ACL_NAME in
  ip access-group ACL_NAME out
"""

# Create ACL, TCP/UDP ports and IP protocols as well-known names
acls = cisco_acl.acls(config=config, platform="ios", )
acl = acls[0]
print(acl.line, "\n")
# ip access-list extended ACL_NAME
#   permit tcp 10.0.0.0 0.0.0.255 any eq ftp 22 telnet
#   permit tcp host 10.0.0.1 any eq ftp
#   deny tcp object-group ADDR_GROUP any eq domain
#   permit icmp any any


# Acl some attributes demonstration
# Note, "object-group ADDR_GROUP" includes addresses from "object-group network ADDR_GROUP"
print(f"{acl.line=}")
print(f"{acl.platform=}")
print(f"{acl.type=}")
print(f"{acl.indent=}")
print(f"{acl.input=}")
print(f"{acl.output=}")
print(f"{acl.items=}")
print(f"{acl.items[2].srcaddr.items=}")
print()
# acl.line="ip access-list extended ACL_NAME\n  permit tcp 10.0.0.0 0.0.0.255 any ...
# acl.platform="ios"
# acl.type="extended"
# acl.indent="  "
# acl.input=["interface Ethernet1"]
# acl.output=["interface Ethernet1"]
# acl.items=[Ace("permit tcp 10.0.0.0 0.0.0.255 any eq ftp 22 telnet"), Ace("perm ...
# acl.items[2].srcaddr.items=[Address("10.1.1.0 255.255.255.252"), Address("host 10.1.1.4")]


# Convert well-known TCP/UDP ports and IP protocols to numbers
# Note, ftp -> 21, telnet -> 23, icmp -> 1
acl.protocol_nr = True
acl.port_nr = True
print(acl.line, "\n")
# ip access-list extended ACL_NAME
#   permit tcp 10.0.0.0 0.0.0.255 any eq 21 22 23
#   permit tcp host 10.0.0.1 any eq 21
#   deny tcp object-group ADDR_GROUP any eq 53
#   permit 1 any any


# Add sequence numbers
acl.resequence(start=5, step=5)
print(acl.line, "\n")
# ip access-list extended ACL_NAME
#   5 permit tcp 10.0.0.0 0.0.0.255 any eq 21 22 23
#   10 permit tcp host 10.0.0.1 any eq 21
#   15 deny tcp object-group ADDR_GROUP any eq 53
#   20 permit 1 any any


# Delete sequence numbers
acl.resequence(start=0)
print(acl.line, "\n")
# ip access-list extended ACL_NAME
#   permit tcp 10.0.0.0 0.0.0.255 any eq 21 22 23
#   permit tcp host 10.0.0.1 any eq 21
#   deny tcp object-group ADDR_GROUP any eq 53
#   permit 1 any any


# Change syntax from IOS to NX-OS
# Note, "extended" removed from output, range of ports split to multiple lines
acl.platform = "nxos"
print(acl.line, "\n")
# ip access-list ACL_NAME
#   permit tcp 10.0.0.0 0.0.0.255 any eq 21
#   permit tcp 10.0.0.0 0.0.0.255 any eq 22
#   permit tcp 10.0.0.0 0.0.0.255 any eq 23
#   permit tcp host 10.0.0.1 any eq 21
#   deny tcp addrgroup ADDR_GROUP any eq 53
#   permit 1 any any


# Get shadow ACEs (in the bottom, without hits)
shadow = acl.shadow_of()
print(shadow, "\n")
# ["permit tcp host 10.0.0.1 any eq 21"]


# Get shading ACEs (in the top)
shading = acl.shading()
print(shading, "\n")
# {"permit tcp 10.0.0.0 0.0.0.255 any eq 21": ["permit tcp host 10.0.0.1 any eq 21"]}


# Delete shadow ACEs (in the bottom)
shading = acl.delete_shadow()
print(shading)
print(acl.line, "\n")
# {"permit tcp 10.0.0.0/24 any eq 21": ["permit tcp 10.0.0.1/32 any eq 21"]}
# ip access-list ACL_NAME
#   permit tcp 10.0.0.0/24 any eq 21
#   permit tcp 10.0.0.0/24 any eq 22
#   permit tcp 10.0.0.0/24 any eq 23
#   deny tcp addrgroup ADDR_GROUP any eq 53
#   permit 1 any any


# Convert object to dictionary
data = acl.data()
pprint(data)
print()
# "line": "ip access-list ACL_NAME\n"
#          "  permit tcp 10.0.0.0 0.0.0.255 any eq 21\n"
#          "  permit tcp 10.0.0.0 0.0.0.255 any eq 22\n"
#          "  permit tcp 10.0.0.0 0.0.0.255 any eq 23\n"
#          "  permit tcp host 10.0.0.1 any eq 21\n"
#          "  deny tcp addrgroup ADDR_GROUP any eq 53\n"
#          "  permit 1 any any",
#  "name": "ACL_NAME",
#  "input": ["interface Ethernet1"],
#  "output": ["interface Ethernet1"],
# "items": [{"action": "permit",
#             "dstaddr": {"addrgroup": "",
#                         "ipnet": IPv4Network("0.0.0.0/0"),
#                         "line": "any",
#                         "prefix": "0.0.0.0/0",
#                         "subnet": "0.0.0.0 0.0.0.0",
#                         "type": "any",
#                         "wildcard": "0.0.0.0 255.255.255.255"},
# ...


# Crate Acl object based on dict data
acl = cisco_acl.Acl(**data)
print(acl.line, "\n")
# ip access-list ACL_NAME
#   permit tcp 10.0.0.0/24 any eq 21
#   permit tcp 10.0.0.0/24 any eq 22
#   permit tcp 10.0.0.0/24 any eq 23
#   permit tcp 10.0.0.1/32 any eq 21
#   deny tcp addrgroup ADDR_GROUP any eq 53
#   permit 1 any any


# Copy Acl object
acl2 = acl.copy()
print(acl2.line, "\n")
# ip access-list ACL_NAME
#   permit tcp 10.0.0.0/24 any eq 21
#   permit tcp 10.0.0.0/24 any eq 22
#   permit tcp 10.0.0.0/24 any eq 23
#   deny tcp addrgroup ADDR_GROUP any eq 53
#   permit 1 any any


# Update some data in Ace objects
# Note, when iterating acl2 object, you are iterating list of Ace objects in acl2.items
acl2.items = [o for o in acl2 if o.srcaddr.line == "10.0.0.0/24"]
for port, ace in enumerate(acl2, start=53):
    ace.protocol.line = "udp"
    ace.dstport.line = f"eq {port}"
acl2.items[1].srcaddr.line = "10.0.1.0/24"
acl2.items[2].srcaddr.line = "10.0.2.0/24"
print(acl2.line, "\n")
# ip access-list ACL_NAME
#   permit udp 10.0.0.0/24 any eq 53
#   permit udp 10.0.1.0/24 any eq 54
#   permit udp 10.0.2.0/24 any eq 55


# Convert from NX-OS extended ACL syntax to IOS standard ACL syntax
acl2.protocol_nr = False
acl2.platform = "ios"
acl2.type = "standard"
print(acl2.line, "\n")
# ip access-list standard ACL_NAME
#   permit 10.0.0.0 0.0.0.255
#   permit 10.0.1.0 0.0.0.255
#   permit 10.0.2.0 0.0.0.255
