"""Examples ACL objects"""
from cisco_acl import Acl

print("""
============================= Example1 =============================
- Create flat ACL.
- Move one ACE.
- Resequence ACEs.
""")

lines1 = """
ip access-list extended acl1
  permit icmp any any
  permit tcp any any
  permit udp any any eq 53
  deny ip any any
  deny tcp any any eq 53
"""
acl1 = Acl(lines1)
print(acl1)
print()
# ip access-list extended acl1
#   permit icmp any any
#   permit tcp any any
#   permit udp any any eq 53
#   deny ip any any
#   deny tcp any any eq 53


# Generate sequences for ACEs.
acl1.resequence()
print(str(acl1))
print()
# ip access-list extended acl1
#   10 permit icmp any any
#   20 permit tcp any any
#   30 permit udp any any eq 53
#   40 deny ip any any
#   50 deny tcp any any eq 53

# Change places of ace "deny tcp any any eq 53".
# Note that ACE have been moved up with the old sequence numbers.
rule1 = acl1.items.pop()
acl1.items.insert(0, rule1)
print(str(acl1))
print()
# ip access-list extended acl1
#   50 deny tcp any any eq 53
#   10 permit icmp any any
#   20 permit tcp any any
#   30 permit udp any any eq 53
#   40 deny ip any any

# Resequence with custom start and step.
acl1.resequence(start=100, step=1)
print(str(acl1))
print()
# ip access-list extended acl1
#   100 deny tcp any any eq 53
#   101 permit icmp any any
#   102 permit tcp any any
#   103 permit udp any any eq 53
#   104 deny ip any any
