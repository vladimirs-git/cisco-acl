"""**AceGroup sequence numbers and sorting**

- Create AceGroup, with 2 items (1st is remark, 2nd is rule)
- Create AceGroup, with 3 items (1st is remark, 2nd and 3rd are rules)
- Add AceGroup to Acl
- Sorting (changing sequence) rules by notes
    AceGroup behaves like a ACE item (Items inside AceGroup save the same order)
"""

from cisco_acl import Acl, AceGroup

# Create AceGroup, with 2 items (1st is remark, 2nd is rule)
lines = """
remark ===== web =====
permit tcp any any eq 80
"""
group1 = AceGroup(lines)
print(str(group1))
print()
# remark ===== web =====
# permit tcp any any eq www


# Create AceGroup, with 3 items (1st is remark, 2nd and 3rd are rules)
# We are creating Acl object and then converting Acl to AceGroup object only for demonstration
lines = """
ip access-list extended ACL2
  remark ===== dns =====
  permit udp any any eq 53
  deny tcp any any eq domain
"""
acl = Acl(lines)
group2 = AceGroup(str(acl))
print(str(group2))
print()
# remark ===== dns =====
# permit udp any any eq domain
# deny tcp any any eq domain


# Create Acl with 3 Ace items, add AceGroup to Acl
lines = """
ip access-list extended ACL1
  permit icmp any any
  permit ip object-group A object-group B log
  permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4
"""
acl = Acl(lines)
print(acl.line)
print()
# ip access-list extended ACL1
#   permit icmp any any
#   permit ip object-group A object-group B log
#   permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4


# Add AceGroup to Acl
# Note, acl.append() and acl.items.append() make the same action
# Note, Acl object implements all list methods (append, extend, etc)
# For demonstration, one group added by append() other by extend() methods
acl.append(group1)
acl.extend([group2])
print(str(acl))
print()
# ip access-list extended ACL1
#   permit icmp any any
#   permit ip object-group A object-group B log
#   permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4
#   remark ===== web =====
#   permit tcp any any eq www
#   remark ===== dns =====
#   permit udp any any eq domain
#   deny tcp any any eq domain


# Generate sequence numbers
acl.resequence()
print(acl.line)
print()
# ip access-list extended ACL1
#   10 permit icmp any any
#   20 permit ip object-group A object-group B log
#   30 permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4
#   40 remark ===== web =====
#   50 permit tcp any any eq www
#   60 remark ===== dns =====
#   70 permit udp any any eq domain
#   80 deny tcp any any eq domain


# Add note to Acl items
notes = ["icmp", "object-group", "host 1.1.1.1", "web", "dns"]
for idx, note in enumerate(notes):
    acl[idx].note = note
for item in acl:
    print(repr(item))
print()
# Ace("10 permit icmp any any", note="icmp")
# Ace("20 permit ip object-group A object-group B log", note="object-group")
# Ace("30 permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4", note="host 1.1.1.1")
# AceGroup("40 remark ===== web =====\n50 permit tcp any any eq www", note="web")
# AceGroup("60 remark ===== dns =====\n
#           70 permit udp any any eq domain\n
#           80 deny tcp any any eq domain", note="dns")


# Sorting (changing sequence) rules by notes
# Note, AceGroup behaves like a ACE item (Items inside AceGroup save the same order)
# Note, that ACE has been moved up with the same sequence numbers, later I will resequence
acl.sort(key=lambda o: o.note)
print(acl)
print()
# ip access-list extended ACL1
#   60 remark ===== dns =====
#   70 permit udp any any eq domain
#   80 deny tcp any any eq domain
#   30 permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4
#   10 permit icmp any any
#   20 permit ip object-group A object-group B log
#   40 remark ===== web =====
#   50 permit tcp any any eq www


# Resequence numbers with custom start and step
acl.resequence(start=100, step=1)
print(acl)
print()
# ip access-list extended ACL1
#   100 remark ===== dns =====
#   101 permit udp any any eq domain
#   102 deny tcp any any eq domain
#   103 permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4
#   104 permit icmp any any
#   105 permit ip object-group A object-group B log
#   106 remark ===== web =====
#   107 permit tcp any any eq www
