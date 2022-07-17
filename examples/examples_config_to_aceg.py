"""Creates *Acl* objects based on the "show running-config" output.
*Acl* contains *AceGroup* items, where ACE lines grouped by remarks
"""

from cisco_acl import config_to_aceg, AceGroup

config = """
hostname ROUTER_IOS
ip access-list extended ACL_NAME
  remark ========== ACE_NAME1 ==========
  permit tcp host 10.0.0.1 10.0.0.0 0.0.0.255 eq 21 22 23
  deny tcp any any eq 53
  remark ========== ACE_NAME2 ==========
  permit ip any any
"""

# Create ACL
acls = config_to_aceg(config=config)
acl = acls[0]
print(acl)
print()
# ip access-list extended ACL_NAME
#   remark ========== ACE_NAME1 ==========
#   permit tcp host 10.0.0.1 10.0.0.0 0.0.0.255 eq ftp 22 telnet
#   deny tcp any any eq domain
#   remark ========== ACE_NAME2 ==========
#   permit ip any any


# Insert new AceGroup to ACL
aceg = AceGroup("remark ========== ACE_NAME3 ==========\npermit icmp any any")
acl.items.insert(1, aceg)
acl.resequence(start=20, step=1)
print(acl)
print()
# ip access-list extended ACL_NAME
#   20 remark ========== ACE_NAME1 ==========
#   21 permit tcp host 10.0.0.1 10.0.0.0 0.0.0.255 eq ftp 22 telnet
#   22 deny tcp any any eq domain
#   23 remark ========== ACE_NAME3 ==========
#   24 permit icmp any any
#   25 remark ========== ACE_NAME2 ==========
#   26 permit ip any any

# Move ACE_NAME3 to top
aceg.sequence = 1
acl.items.sort(key=lambda o: o.sequence)
acl.resequence(start=20, step=1)
print(acl)
print()
# ip access-list extended ACL_NAME
#   20 remark ========== ACE_NAME3 ==========
#   21 permit icmp any any
#   22 remark ========== ACE_NAME1 ==========
#   23 permit tcp host 10.0.0.1 10.0.0.0 0.0.0.255 eq ftp 22 telnet
#   24 deny tcp any any eq domain
#   25 remark ========== ACE_NAME2 ==========
#   26 permit ip any any

# Ordering by notes
acl.items[0].note = "B"
acl.items[1].note = "A"
acl.items[2].note = "C"
acl.items.sort(key=lambda o: o.note)
print(acl)
print()
# ip access-list extended ACL_NAME
#   22 remark ========== ACE_NAME1 ==========
#   23 permit tcp host 10.0.0.1 10.0.0.0 0.0.0.255 eq ftp 22 telnet
#   24 deny tcp any any eq domain
#   20 remark ========== ACE_NAME3 ==========
#   21 permit icmp any any
#   25 remark ========== ACE_NAME2 ==========
#   26 permit ip any any
