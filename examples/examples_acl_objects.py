"""Examples ACL objects"""

from cisco_acl import Acl, Ace, AceGroup, Remark

print("""
============================= Example1 =============================
- Create ACL from strings. 
""")
name1 = "ACL1"
items1 = [
    "remark text",
    "permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 range 3 4",
    "deny tcp any any eq 53",
]

# Create ACL from strings.
# Note that the items type is <str>.
acl1 = Acl(name=name1, items=items1)
print(acl1)
print()
# ip access-list extended ACL1
#   remark text
#   permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 range 3 4
#   deny tcp any any eq 53

print(acl1.name)
print(acl1.ip_acl_name)
for item in acl1:
    print(repr(item))
print()
# ACL1
# ip access-list extended ACL1
# Remark('remark text')
# Ace('permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 range 3 4')
# Ace('deny tcp any any eq 53')


print("""
============================= Example2 =============================
- Create ACL from objects. 
""")

name2 = "ACL2"
items2 = [
    Remark("remark text"),
    Ace("permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 range 3 4"),
    Ace("deny ip any any"),
]

# Create ACL from objects.
# Note that the items type is <object>.
acl2 = Acl(name=name2, items=items2)
print(acl2)
print()
# ip access-list extended ACL2
#   remark text
#   permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 range 3 4
#   deny ip any any

for item in acl2:
    print(repr(item))
print()
# Remark('remark text')
# Ace('permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 range 3 4')
# Ace('deny ip any any')

print("""
============================= Example3 =============================
- Create ACL with groups (rules). 
- Generate sequences for ACEs.
- Move group and resequence ACEs.
- Resequence numbers.
""")
rule0 = Remark("remark ===== acl3 =====")
rule1 = Ace("permit icmp any any")
rule2 = AceGroup(["remark ===== web =====", "permit tcp any any eq 80"])
rule3 = AceGroup(["remark ===== dns =====", "permit udp any any eq 53", "permit tcp any any eq 53"])
rule4 = Ace("deny ip any any")
acl3 = Acl(name="ACL3", items=[rule0, rule1, rule2, rule3, rule4])

print(acl3)
print()
# ip access-list extended ACL3
#   remark ===== acl3 =====
#   permit icmp any any
#   remark ===== web =====
#   permit tcp any any eq 80
#   remark ===== dns =====
#   permit udp any any eq 53
#   permit tcp any any eq 53
#   deny ip any any

for item in acl3:
    print(repr(item))
print()
# Remark('remark ===== acl3 =====')
# Ace('permit icmp any any')
# AceGroup('remark ===== web =====\npermit tcp any any eq 80')
# AceGroup('remark ===== dns =====\npermit udp any any eq 53\npermit tcp any any eq 53')
# Ace('deny ip any any')

# Generate sequences for ACEs.
acl3.resequence()
print(str(acl3))
print()
# ip access-list extended ACL3
#   10 remark ===== acl3 =====
#   20 permit icmp any any
#   30 remark ===== web =====
#   40 permit tcp any any eq 80
#   50 remark ===== dns =====
#   60 permit udp any any eq 53
#   70 permit tcp any any eq 53
#   80 deny ip any any

# Move group and resequence ACEs.
# Note that grouped DNS rules have been moved up with the same sequence numbers.
acl3.items[1], acl3.items[3] = acl3.items[3], acl3.items[1]
print(str(acl3))
print()
# ip access-list extended ACL3
#   10 remark ===== acl3 =====
#   50 remark ===== dns =====
#   60 permit udp any any eq 53
#   70 permit tcp any any eq 53
#   30 remark ===== web =====
#   40 permit tcp any any eq 80
#   20 permit icmp any any
#   80 deny ip any any


# Resequence numbers with custom start and step.
acl3.resequence(start=100, step=1)
print(str(acl3))
print()
# ip access-list extended ACL3
#   100 remark ===== acl3 =====
#   101 remark ===== dns =====
#   102 permit udp any any eq 53
#   103 permit tcp any any eq 53
#   104 remark ===== web =====
#   105 permit tcp any any eq 80
#   106 permit icmp any any
#   107 deny ip any any
