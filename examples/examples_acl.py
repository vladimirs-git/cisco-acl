"""**Acl change platform**

- Create ACL
- Generate sequence numbers
- Moved up ACE "deny tcp any any eq 53"
- Resequence numbers
- Delete sequences
- Change syntax from Cisco IOS platform to Cisco Nexus NX-OS
- Change syntax from Cisco Nexus NX-OS platform to Cisco IOS
"""

from cisco_acl import Acl

lines1 = """
ip access-list extended ACL1
  permit icmp any any
  permit ip object-group A object-group B log
  permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4
  deny tcp any any eq 53
"""

# Create ACL.
# Note, str(acl1) and acl1.line return the same value.
acl1 = Acl(lines1)
print(str(acl1))
print()
# ip access-list extended ACL1
#   permit icmp any any
#   permit ip object-group A object-group B log
#   permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4
#   deny tcp any any eq domain

# TCP/UDP ports represented numerically.
acl1.numerically = True
print(acl1.line)
acl1.numerically = False
print()
# ip access-list extended ACL1
#   permit icmp any any
#   permit ip object-group A object-group B log
#   permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4
#   deny tcp any any eq 53

# Generate sequence numbers.
acl1.resequence()
print(acl1.line)
print()
# ip access-list extended ACL1
#   10 permit icmp any any
#   20 permit ip object-group A object-group B log
#   30 permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4
#   40 deny tcp any any eq domain

# Moved up ACE "deny tcp any any eq 53".
# Note that ACE have been moved up with the same sequence numbers.
# Note, Ace class has list methods pop(), insert().
rule1 = acl1.pop(3)
acl1.insert(0, rule1)
print(acl1)
print()
# ip access-list extended ACL1
#   40 deny tcp any any eq domain
#   10 permit icmp any any
#   20 permit ip object-group A object-group B log
#   30 permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4

# Resequence numbers with custom start and step.
acl1.resequence(start=100, step=1)
print(acl1)
print()
# ip access-list extended ACL1
#   100 deny tcp any any eq domain
#   101 permit icmp any any
#   102 permit ip object-group A object-group B log
#   103 permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4

# Delete sequences.
acl1.resequence(start=0)
print(f"{acl1.platform=}")
print(acl1)
print()
# acl1.platform='ios'
# ip access-list extended ACL1
#   deny tcp any any eq domain
#   permit icmp any any
#   permit ip object-group A object-group B log
#   permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4

# Change syntax from Cisco IOS platform to Cisco Nexus NX-OS.
acl1.platform = "nxos"
print(f"{acl1.platform=}")
print(acl1)
print()
# acl1.platform='nxos'
# ip access-list ACL1
#   deny tcp any any eq domain
#   permit icmp any any
#   permit ip addrgroup A addrgroup B log
#   permit tcp 1.1.1.1/32 eq 1 2.2.2.0/24 eq 3
#   permit tcp 1.1.1.1/32 eq 1 2.2.2.0/24 eq 4
#   permit tcp 1.1.1.1/32 eq 2 2.2.2.0/24 eq 3
#   permit tcp 1.1.1.1/32 eq 2 2.2.2.0/24 eq 4

# Change syntax from Cisco Nexus NX-OS platform to Cisco IOS
acl1.platform = "ios"
print(f"{acl1.platform=}")
print(acl1)
print()
# acl1.platform='ios'
# ip access-list extended ACL1
#   deny tcp any any eq domain
#   permit icmp any any
#   permit ip object-group A object-group B log
#   permit tcp host 1.1.1.1 eq 1 2.2.2.0 0.0.0.255 eq 3
#   permit tcp host 1.1.1.1 eq 1 2.2.2.0 0.0.0.255 eq 4
#   permit tcp host 1.1.1.1 eq 2 2.2.2.0 0.0.0.255 eq 3
#   permit tcp host 1.1.1.1 eq 2 2.2.2.0 0.0.0.255 eq 4
