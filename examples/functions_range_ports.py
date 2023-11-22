"""Generate ACEs in required range of TCP/UDP source/destination ports."""
from pprint import pprint

import cisco_acl

# Generate range of source TCP ports
aces = cisco_acl.range_ports(srcports="21-23,80")
pprint(aces)
print()
# ["permit tcp any eq ftp any",
#  "permit tcp any eq 22 any",
#  "permit tcp any eq telnet any",
#  "permit tcp any eq www any"]


# Generate range of destination TCP ports
aces = cisco_acl.range_ports(dstports="21-23,80")
pprint(aces)
print()
# ["permit tcp any any eq ftp",
#  "permit tcp any any eq 22",
#  "permit tcp any any eq telnet",
#  "permit tcp any any eq www"]


# Generate range where well-known TCP ports represented as numbers
aces = cisco_acl.range_ports(dstports="21-23,80", port_nr=True)
pprint(aces)
print()
# ["permit tcp any any eq 21",
#  "permit tcp any any eq 22",
#  "permit tcp any any eq 23",
#  "permit tcp any any eq 80"]


# Generate range of UDP ports based on the template with specified address
aces = cisco_acl.range_ports(dstports="53,67-68,123", line="deny udp host 10.0.0.1 any eq 1")
pprint(aces)
print()
# ["deny udp host 10.0.0.1 any eq domain",
#  "deny udp host 10.0.0.1 any eq bootps",
#  "deny udp host 10.0.0.1 any eq bootpc",
#  "deny udp host 10.0.0.1 any eq ntp"]
