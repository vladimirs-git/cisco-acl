"""**Protocol(line)**
The following example demonstrates Protocol object.
"""

from cisco_acl import Protocol

proto = Protocol("tcp")
assert proto.line == "tcp"
assert proto.platform == "ios"
assert proto.name == "tcp"
assert proto.number == 6

proto = Protocol("ip")
assert proto.line == "ip"
assert proto.platform == "ios"
assert proto.name == "ip"
assert proto.number == 0
