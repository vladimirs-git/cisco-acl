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
