"""Examples ACL objects"""

from cisco_acl import Acl, Ace, AceGroup, Remark

print("""
============================= Example1 =============================
Create ACL from strings. 
Note that the items type is <str>.
""")
name1 = "acl_1"
items1 = [
    "remark text",
    "permit icmp any any",
    "deny ip any any",
]
acl1 = Acl(name=name1, items=items1)
print(acl1)
print()
# ip access-list extended acl_1
#   remark text
#   permit icmp any any
#   deny ip any any

print(acl1.name)
print(acl1.ip_acl_name)
for item in acl1:
    print(repr(item))
print()
# acl_1
# ip access-list extended acl_1
# Remark('remark text')
# Ace('permit icmp any any')
# Ace('deny ip any any')


print("""
============================= Example2 =============================
Create ACL from objects. 
Note that the items type is <object>.
""")

name2 = "acl_2"
items2 = [
    Remark("remark text"),
    Ace("permit icmp any any"),
    Ace("deny ip any any"),
]
acl2 = Acl(name=name2, items=items2)
print(acl2)
print()
# ip access-list extended acl_2
#   remark text
#   permit icmp any any
#   deny ip any any

for item in acl2:
    print(repr(item))
print()
# Remark('remark text')
# Ace('permit icmp any any')
# Ace('deny ip any any')

print("""
============================= Example3 =============================
Create ACL with groups (rules). Move group and resequence ACEs.
""")
rule0 = Remark("remark ===== acl3 =====")
rule1 = Ace("permit icmp any any")
rule2 = AceGroup(["remark ===== web =====", "permit tcp any any eq 80"])
rule3 = AceGroup(["remark ===== dns =====", "permit udp any any eq 53", "permit tcp any any eq 53"])
rule4 = Ace("deny ip any any")
acl3 = Acl(name="acl_3", items=[rule0, rule1, rule2, rule3, rule4])

print(acl3)
print()
# ip access-list extended acl_3
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
# ip access-list extended acl_3
#   10 remark ===== acl3 =====
#   20 permit icmp any any
#   30 remark ===== web =====
#   40 permit tcp any any eq 80
#   50 remark ===== dns =====
#   60 permit udp any any eq 53
#   70 permit tcp any any eq 53
#   80 deny ip any any

# Change places of rule1 and rule3.
# Note that grouped DNS rules have been moved up with the old sequence numbers.
acl3.items[1], acl3.items[3] = acl3.items[3], acl3.items[1]
print(str(acl3))
print()
# ip access-list extended acl_3
#   10 remark ===== acl3 =====
#   50 remark ===== dns =====
#   60 permit udp any any eq 53
#   70 permit tcp any any eq 53
#   30 remark ===== web =====
#   40 permit tcp any any eq 80
#   20 permit icmp any any
#   80 deny ip any any


# Resequence with custom start and step.
acl3.resequence(start=100, step=1)
print(str(acl3))
print()
# ip access-list extended acl_3
#   100 remark ===== acl3 =====
#   101 remark ===== dns =====
#   102 permit udp any any eq 53
#   103 permit tcp any any eq 53
#   104 remark ===== web =====
#   105 permit tcp any any eq 80
#   106 permit icmp any any
#   107 deny ip any any
