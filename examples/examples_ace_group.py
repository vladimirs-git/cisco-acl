"""**AceGroup sequence numbers and sorting**

- Create ACL with groups
- Generate sequence numbers
- Sort rules by comment
- Resequence numbers
"""

from cisco_acl import Acl, AceGroup

lines = """
ip access-list extended ACL1
  permit icmp any any
  permit ip object-group A object-group B log
  permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4
"""

# Create ACL1.
# Note, str(acl1) and acl1.line return the same value.
acl1 = Acl(lines)
print(str(acl1))
print()
# ip access-list extended ACL1
#   permit icmp any any
#   permit ip object-group A object-group B log
#   permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4

# Create Ace groups. One making from string, other from Acl object.
lines1 = """
remark ===== web =====
permit tcp any any eq 80
"""
group1 = AceGroup(lines1)
print(str(group1))
print()
# remark ===== web =====
# permit tcp any any eq www

lines2 = """
ip access-list extended ACL2
  remark ===== dns =====
  permit udp any any eq 53
  permit tcp any any eq 53
"""
acl2 = Acl(lines2)
print(str(acl2))
print()
# ip access-list extended ACL2
#   remark ===== dns =====
#   permit udp any any eq domain
#   permit tcp any any eq domain

# Convert Acl object to AceGroup.
group2 = AceGroup(str(acl2))
print(str(group2))
print()
# remark ===== dns =====
# permit udp any any eq domain
# permit tcp any any eq domain

# Add groups to acl1.
# Note, acl1.append() and acl1.items.append() make the same action.
# The Acl class implements all list methods.
# For demonstration, one group added by append() other by extend() methods.
acl1.append(group1)
acl1.extend([group2])
print(str(acl1))
print()
# ip access-list extended ACL1
#   permit icmp any any
#   permit ip object-group A object-group B log
#   permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4
#   remark ===== web =====
#   permit tcp any any eq www
#   remark ===== dns =====
#   permit udp any any eq domain
#   permit tcp any any eq domain

# Generate sequence numbers.
acl1.resequence()
print(acl1.line)
print()
# ip access-list extended ACL1
#   10 permit icmp any any
#   20 permit ip object-group A object-group B log
#   30 permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4
#   40 remark ===== web =====
#   50 permit tcp any any eq www
#   60 remark ===== dns =====
#   70 permit udp any any eq domain
#   80 permit tcp any any eq domain

# Add note to Acl items
notes = ["icmp", "object-group", "host 1.1.1.1", "web", "dns"]
for idx, note in enumerate(notes):
    acl1[idx].note = note
for item in acl1:
    print(repr(item))
print()
# Ace('10 permit icmp any any', note='icmp')
# Ace('20 permit ip object-group A object-group B log', note='object-group')
# Ace('30 permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4', note='host 1.1.1.1')
# AceGroup('40 remark ===== web =====\n50 permit tcp any any eq www', note='web')
# AceGroup('60 remark ===== dns =====\n
#           70 permit udp any any eq domain\n
#           80 permit tcp any any eq domain', note='dns')

# Sorting rules by notes.
# Note that ACE has been moved up with the same sequence numbers.
acl1.sort(key=lambda o: o.note)
print(acl1)
print()
# ip access-list extended ACL1
#   60 remark ===== dns =====
#   70 permit udp any any eq domain
#   80 permit tcp any any eq domain
#   30 permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4
#   10 permit icmp any any
#   20 permit ip object-group A object-group B log
#   40 remark ===== web =====
#   50 permit tcp any any eq www

# Resequence numbers with custom start and step.
acl1.resequence(start=100, step=1)
print(acl1)
print()
# ip access-list extended ACL1
#   100 remark ===== dns =====
#   101 permit udp any any eq domain
#   102 permit tcp any any eq domain
#   103 permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4
#   104 permit icmp any any
#   105 permit ip object-group A object-group B log
#   106 remark ===== web =====
#   107 permit tcp any any eq www
