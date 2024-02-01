"""Standard Acl."""

from cisco_acl import Acl

lines1 = """
ip access-list standard ACL1
  permit 10.0.0.1
  permit host 10.0.0.2
  permit host 10.0.0.3 0.0.0.0
  permit 10.0.0.4 0.0.0.3
"""

# Create ACL.
acl1 = Acl(lines1)
print(str(acl1))
# ip access-list standard ACL1
#   permit host 10.0.0.1
#   permit host 10.0.0.2
#   permit host 10.0.0.3 0.0.0.0
#   permit 10.0.0.4 0.0.0.3

# todo
# **Change:**
# Host in standard ACL.
# ip access-list standard ACL1
#   permit 10.0.0.1
#   permit 10.0.0.2
#   permit 10.0.0.3 0.0.0.0
#   permit 10.0.0.4 0.0.0.3
