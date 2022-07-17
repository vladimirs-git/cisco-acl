"""Creates *Acl* objects based on the "show running-config" output.
*Acl* contains *Ace* items, where each ACE line is treated as an independent element
"""

from cisco_acl import config_to_ace, Ace, AceGroup

config = """
hostname ROUTER_IOS
ip access-list extended ACL_NAME
  5 permit tcp host 10.0.0.1 10.0.0.0 0.0.0.255 eq 21 22 23
  10 deny tcp any any eq 53
  15 permit ip any any
"""

# Create ACL
# Note, ACL represented with TCP/UDP ports as well-known names
acls = config_to_ace(config=config)
acl = acls[0]
print(acl)
print()
# ip access-list extended ACL_NAME
#   5 permit tcp host 10.0.0.1 10.0.0.0 0.0.0.255 eq ftp 22 telnet
#   10 deny tcp any any eq domain
#   15 permit ip any any

# TCP/UDP ports represented numerically
acl.numerically = True
print(acl)
print()
# ip access-list extended ACL_NAME
#   5 permit tcp host 10.0.0.1 10.0.0.0 0.0.0.255 eq 21 22 23
#   10 deny tcp any any eq 53
#   15 permit ip any any

# Insert new ACEs to ACL
# Note, ACEs has invalid sequence numbers
ace = Ace("deny ip object-group A object-group B log")
aceg = AceGroup("remark ICMP\npermit icmp any any")
acl.items.extend([ace, aceg])
ace.sequence = 1
aceg.sequence = 7
acl.items.sort(key=lambda o: o.sequence)
print(acl)
print()
# ip access-list extended ACL_NAME
#   1 deny ip object-group A object-group B log
#   5 permit tcp host 10.0.0.1 10.0.0.0 0.0.0.255 eq 21 22 23
#   remark ICMP
#   permit icmp any any
#   10 deny tcp any any eq 53
#   15 permit ip any any

# Delete sequence numbers
acl.resequence(start=0)
print(acl)
print()
# ip access-list extended ACL_NAME
#   deny ip object-group A object-group B log
#   permit tcp host 10.0.0.1 10.0.0.0 0.0.0.255 eq 21 22 23
#   remark ICMP
#   permit icmp any any
#   deny tcp any any eq 53
#   permit ip any any

# Set sequence numbers
acl.resequence(start=20, step=2)
print(acl)
print()
# ip access-list extended ACL_NAME
#   20 deny ip object-group A object-group B log
#   22 permit tcp host 10.0.0.1 10.0.0.0 0.0.0.255 eq 21
#   24 remark ICMP
#   26 permit icmp any any
#   28 deny tcp any any eq 53
#   30 permit ip any any


# Change syntax from IOS to NX-OS.
acl.platform = "nxos"
acl.resequence(start=20, step=2)
print(acl)
print()
# ip access-list ACL_NAME
#   20 deny ip addrgroup A addrgroup B log
#   22 permit tcp 10.0.0.1/32 10.0.0.0/24 eq ftp
#   24 permit tcp 10.0.0.1/32 10.0.0.0/24 eq 22
#   26 permit tcp 10.0.0.1/32 10.0.0.0/24 eq telnet
#   28 remark ICMP
#   30 permit icmp any any
#   32 deny tcp any any eq domain
#   34 permit ip any any
