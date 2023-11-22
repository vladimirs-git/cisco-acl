"""Generate ACEs in required range of IP protocols."""
from pprint import pprint

import cisco_acl

# Generate range of IP protocols
aces = cisco_acl.range_protocols(protocols="1-3,6,17")
pprint(aces)
print()
# ["permit icmp any any",
#  "permit igmp any any",
#  "permit 3 any any",
#  "permit tcp any any",
#  "permit udp any any"]


# Generate range where well-known IP protocols represented as numbers
aces = cisco_acl.range_protocols(protocols="1-3,6,17", protocol_nr=True)
pprint(aces)
print()
# ["permit 1 any any",
#  "permit 2 any any",
#  "permit 3 any any",
#  "permit 6 any any",
#  "permit 17 any any"]
