# Todo

### Convert Acl to AceGroup
```python
from cisco_acl import Acl
line = """
ip access-list extended NAME
  permit tcp object-group GROUP eq 1 2 10.0.0.0 0.0.0.255 eq 3 4
"""
acl = Acl(line=line, platform="ios")
print(acl)
print()
# ip access-list extended NAME
#   permit tcp object-group GROUP eq 1 2 10.0.0.0 0.0.0.255 eq 3 4

# Convert from Cisco IOS to Cisco NX-OS syntax.
acl.convert(platform="cnx")
print(acl)
print()
# ip access-list extended NAME
#   permit tcp addrgroup GROUP eq 1 10.0.0.0/24 eq 3
#   permit tcp addrgroup GROUP eq 1 10.0.0.0/24 eq 4
#   permit tcp addrgroup GROUP eq 2 10.0.0.0/24 eq 3
#   permit tcp addrgroup GROUP eq 2 10.0.0.0/24 eq 4


# Convert from Cisco NX-OS to Cisco IOS syntax.
line = """
ip access-list extended NAME
  permit tcp addrgroup GROUP eq 1 10.0.0.0/24 eq 3
  permit tcp addrgroup GROUP eq 1 10.0.0.0/24 eq 4
  permit tcp addrgroup GROUP eq 2 10.0.0.0/24 eq 3
  permit tcp addrgroup GROUP eq 2 10.0.0.0/24 eq 4
"""
acl = Acl(line=line, platform="cnx")
acl.convert(platform="ios")
print(acl)
print()
# ip access-list extended NAME
#   permit tcp object-group GROUP eq 1 2 10.0.0.0 0.0.0.255 eq 3 4
```

### Convert Acl to other platform
```python
from cisco_acl import Acl
line = """
ip access-list extended NAME
  remark TEXT
  permit icmp any any
  deny ip any any
"""
acl = Acl(line=line, platform="ios")
print(acl)
print()
# ip access-list extended NAME
#   remark TEXT
#   permit icmp any any
#   deny ip any any

# Convert from Acl to AceGroup.
group = acl.ace_group(platform="cnx")
print(repr(group))
print()
# AceGroup('remark TEXT\npermit icmp any any\ndeny ip any any')
```
