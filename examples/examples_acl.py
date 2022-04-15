"""Examples ACL objects"""
from cisco_acl import Acl

print("""
============================= Example1 =============================
- Create ACL.
- Generate sequence numbers.
- Moved up ACE "deny tcp any any eq 53".
- Resequence numbers.
- Delete sequences.
""")

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
#   deny tcp any any eq 53


# Generate sequence numbers.
acl1.resequence()
print(acl1.line)
print()
# ip access-list extended ACL1
#   10 permit icmp any any
#   20 permit ip object-group A object-group B log
#   30 permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4
#   40 deny tcp any any eq 53

# Moved up ACE "deny tcp any any eq 53".
# Note that ACE have been moved up with the same sequence numbers.
rule1 = acl1.pop()
acl1.insert(0, rule1)
print(acl1)
print()
# ip access-list extended ACL1
#   40 deny tcp any any eq 53
#   10 permit icmp any any
#   20 permit ip object-group A object-group B log
#   30 permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4

# Resequence numbers with custom start and step.
acl1.resequence(start=100, step=1)
print(acl1)
print()
# ip access-list extended ACL1
#   100 deny tcp any any eq 53
#   101 permit icmp any any
#   102 permit ip object-group A object-group B log
#   103 permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4

# Delete sequences.
acl1.delete_sequence()
print(f"{acl1.platform=}")
print(acl1)
print()
# acl1.platform='ios'
# ip access-list extended ACL1
#   deny tcp any any eq 53
#   permit icmp any any
#   permit ip object-group A object-group B log
#   permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4

# Change syntax from Cisco IOS platform to Cisco Nexus NX-OS.
acl1.platform = "cnx"  # TODO
