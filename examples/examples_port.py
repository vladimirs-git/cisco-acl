"""Port.

The following example demonstrates Port object.
"""

from cisco_acl import Port

port = Port("eq 20 21 22 23", platform="ios", protocol="tcp", port_nr=False)
assert port.line == "eq ftp-data ftp 22 telnet"
assert port.platform == "ios"
assert port.operator == "eq"
assert port.items == [20, 21, 22, 23]
assert port.ports == [20, 21, 22, 23]
assert port.sport == "20-23"
print(port.line)
# eq ftp-data ftp 22 telnet
port.port_nr = True
print(port.line)
# eq 20 21 22 23
print()

port = Port("range 1 5", platform="ios", protocol="tcp")
assert port.line == "range 1 5"
assert port.platform == "ios"
assert port.operator == "range"
assert port.items == [1, 5]
assert port.ports == [1, 2, 3, 4, 5]
assert port.sport == "1-5"
print(port.line)
# range 1 5


# software version
port = Port("eq 135", platform="ios", protocol="tcp", version="15")
assert port.line == "eq 135"
print(port.line)
# eq 135

port = Port("eq 135", platform="ios", protocol="tcp")
assert port.line == "eq msrpc"
print(port.line)
# eq msrpc
