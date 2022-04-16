# Todo

### Convert Acl to AceGroup
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

### __eq__
Make Address, Port, Protocol ready for sorting

### Convert cisco config with ACL and Interface sections to list of Acls objects.
```python
from cisco_acl import Acl
line = """
ip access-list extended NAME
  permit icmp any any
interface FastEthernet1
  ip access-group NAME in
"""
acl = Acl(line=line, platform="ios")
print(acl)
print(acl.interface.input)
print()
# ip access-list extended NAME
#   permit icmp any any
# interface FastEthernet1
```