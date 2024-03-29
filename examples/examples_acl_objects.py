"""AceGroup.data().

The following example creates ACL from objects, with groups.
"""

from cisco_acl import Acl, Ace, AceGroup, Remark

name1 = "ACL1"
items1 = [
    Remark("remark text"),
    Ace("permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 range 3 4"),
    Ace("deny ip any any"),
    AceGroup(items=[Remark("remark ===== web ====="),
                    Ace("permit tcp any any eq 80")]),
    AceGroup(items=[Remark("remark ===== dns ====="),
                    Ace("permit udp any any eq 53"),
                    Ace("permit tcp any any eq 53")]),
]

# Create ACL from objects.
# Note that the items type is <object>.
acl1 = Acl(name=name1, items=items1)
print(acl1)
print()
# ip access-list extended ACL1
#   remark text
#   permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 range 3 4
#   deny ip any any
#   remark ===== web =====
#   permit tcp any any eq www
#   remark ===== dns =====
#   permit udp any any eq domain
#   permit tcp any any eq domain

for item in acl1:
    print(repr(item))
print()
# Remark("remark text")
# Ace("permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 range 3 4")
# Ace("deny ip any any")
# AceGroup("remark ===== web =====\npermit tcp any any eq www")
# AceGroup("remark ===== dns =====\npermit udp any any eq domain\npermit tcp any any eq domain")
