"""Examples"""
from cisco_acl import Acl, Ace, AceGroup, Remark

# ============================= Example1 =============================
# Create simplest ACL. Note that the items type is <str>.
items = ["permit icmp any any", "deny ip any any"]
acl1 = Acl(name="acl1", items=items)

# print ACEs objects.
for item in acl1:
    print(repr(item))
print()
# Ace('permit icmp any any')
# Ace('deny ip any any')

# print ACL lines
print(str(acl1))
print()
# ip access-list extended acl1
#   permit icmp any any
#   deny ip any any

# ============================= Example2 =============================
# Create ACL with groups. Note that the type of items is <object>.
rule0 = Remark("remark ===== acl2 =====")
rule1 = Ace("permit icmp any any")
rule2 = AceGroup(["remark ===== web =====", "permit tcp any any eq 80"])
rule3 = AceGroup(["remark ===== dns =====", "permit udp any any eq 53", "permit tcp any any eq 53"])
rule4 = Ace("deny ip any any")
acl2 = Acl(name="acl2", items=[rule0, rule1, rule2, rule3, rule4])

# print ACEs objects.
for item in acl2:
    print(repr(item))
print()
# Remark('remark ===== acl2 =====')
# Ace('permit icmp any any')
# AceGroup('remark ===== web =====\npermit tcp any any eq 80')
# AceGroup('remark ===== dns =====\npermit udp any any eq 53\npermit tcp any any eq 53')
# Ace('deny ip any any')

# print ACL lines.
print(str(acl2))
print()
# ip access-list extended acl2
#   remark ===== acl2 =====
#   permit icmp any any
#   remark ===== web =====
#   permit tcp any any eq 80
#   remark ===== dns =====
#   permit udp any any eq 53
#   permit tcp any any eq 53
#   deny ip any any

# Generate sequences to ACEs.
acl2.resequence()
print(str(acl2))
print()
# ip access-list extended acl2
#   10 remark ===== acl2 =====
#   20 permit icmp any any
#   30 remark ===== web =====
#   40 permit tcp any any eq 80
#   50 remark ===== dns =====
#   60 permit udp any any eq 53
#   70 permit tcp any any eq 53
#   80 deny ip any any

# Change places of rule1 and rule3. Note that all DNS related rules have been moved with sequences.
acl2.items[1], acl2.items[3] = acl2.items[3], acl2.items[1]
print(str(acl2))
print()
# ip access-list extended acl2
#   10 remark ===== acl2 =====
#   50 remark ===== dns =====
#   60 permit udp any any eq 53
#   70 permit tcp any any eq 53
#   30 remark ===== web =====
#   40 permit tcp any any eq 80
#   20 permit icmp any any
#   80 deny ip any any

# Resequence lines by custom start and step sequence numbers.
acl2.resequence(start=100, step=1)
print(str(acl2))
print()
# ip access-list extended acl2
#   100 remark ===== acl2 =====
#   101 remark ===== dns =====
#   102 permit udp any any eq 53
#   103 permit tcp any any eq 53
#   104 remark ===== web =====
#   105 permit tcp any any eq 80
#   106 permit icmp any any
#   107 deny ip any any
