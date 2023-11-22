"""Create Ace objects based on the "show running-config" output."""
from pprint import pprint

import cisco_acl

config = """
permit tcp 10.0.0.0 0.0.0.255 range 1 4 any eq 21 22 23 syn ack log
permit tcp host 10.0.0.1 any eq 21
deny tcp object-group ADDR_GROUP any eq 53
permit icmp any any
"""

# Create list of ACEs
aces = cisco_acl.aces(config=config, platform="ios")
for ace in aces:
    print(f"{ace.line=}")
print()
# ace.line="permit tcp 10.0.0.0 0.0.0.255 range 1 4 any eq ftp 22 telnet syn ack log"
# ace.line="permit tcp host 10.0.0.1 any eq ftp"
# ace.line="deny tcp object-group ADDR_GROUP any eq domain"
# ace.line="permit icmp any any"


# Ace some attributes demonstration
ace = aces[0]
print(f"{ace.line=}")
print(f"{ace.platform=}")
print(f"{ace.type=}")
print(f"{ace.sequence=}")
print(f"{ace.action=}")
print(f"{ace.protocol.name=}")
print(f"{ace.protocol.number=}")
print()
print(f"{ace.srcaddr.line=}")
print(f"{ace.srcaddr.addrgroup=}")
print(f"{ace.srcaddr.ipnet=}")
print(f"{ace.srcaddr.prefix=}")
print(f"{ace.srcaddr.subnet=}")
print(f"{ace.srcaddr.wildcard=}")
print()
print(f"{ace.srcport.line=}")
print(f"{ace.srcport.protocol=}")
print(f"{ace.srcport.items=}")
print(f"{ace.srcport.operator=}")
print(f"{ace.srcport.ports=}")
print(f"{ace.srcport.sport=}")
print()
print(f"{ace.dstaddr.line=}")
print(f"{ace.dstaddr.addrgroup=}")
print(f"{ace.dstaddr.ipnet=}")
print(f"{ace.dstaddr.prefix=}")
print(f"{ace.dstaddr.subnet=}")
print(f"{ace.dstaddr.wildcard=}")
print()
print(f"{ace.dstport.line=}")
print(f"{ace.dstport.protocol=}")
print(f"{ace.dstport.items=}")
print(f"{ace.dstport.operator=}")
print(f"{ace.dstport.ports=}")
print(f"{ace.dstport.sport=}")
print()
print(f"{ace.option.line=}")
print(f"{ace.option.flags=}")
print(f"{ace.option.logs=}")
print()
# ace.line="permit tcp 10.0.0.0 0.0.0.255 range 1 4 any eq ftp 22 telnet syn ack log"
# ace.platform="ios"
# ace.type="extended"
# ace.sequence=0
# ace.action="permit"
# ace.protocol.name="tcp"
# ace.protocol.number=6
#
# ace.srcaddr.line="10.0.0.0 0.0.0.255"
# ace.srcaddr.addrgroup=""
# ace.srcaddr.ipnet=IPv4Network("10.0.0.0/24")
# ace.srcaddr.prefix="10.0.0.0/24"
# ace.srcaddr.subnet="10.0.0.0 255.255.255.0"
# ace.srcaddr.wildcard="10.0.0.0 0.0.0.255"
#
# ace.srcport.line="range 1 4"
# ace.srcport.protocol="tcp"
# ace.srcport.items=[1, 4]
# ace.srcport.operator="range"
# ace.srcport.ports=[1, 2, 3, 4]
# ace.srcport.sport="1-4"
#
# ace.dstaddr.line="any"
# ace.dstaddr.addrgroup=""
# ace.dstaddr.ipnet=IPv4Network("0.0.0.0/0")
# ace.dstaddr.prefix="0.0.0.0/0"
# ace.dstaddr.subnet="0.0.0.0 0.0.0.0"
# ace.dstaddr.wildcard="0.0.0.0 255.255.255.255"
#
# ace.dstport.line="eq ftp 22 telnet"
# ace.dstport.protocol="tcp"
# ace.dstport.items=[21, 22, 23]
# ace.dstport.operator="eq"
# ace.dstport.ports=[21, 22, 23]
# ace.dstport.sport="21-23"
#
# ace.option.line="syn ack log"
# ace.option.flags=["syn", "ack"]
# ace.option.logs=["log"]


# Convert object to dictionary
data = ace.data()
pprint(data)
print()
# {"line": "permit tcp 10.0.0.0 0.0.0.255 range 1 4 any eq ftp 22 telnet syn ack log"
#  "platform": "ios",
#  "action": "permit",
#  "srcaddr": {"addrgroup": "",
#              "ipnet": IPv4Network("10.0.0.0/24"),
#              "line": "10.0.0.0 0.0.0.255",
#              "prefix": "10.0.0.0/24",
#              "subnet": "10.0.0.0 255.255.255.0",
#              "type": "wildcard",
#              "wildcard": "10.0.0.0 0.0.0.255"},
#  "srcport": {"items": [1, 4],
#              "line": "range 1 4",
#              "operator": "range",
#              "ports": [1, 2, 3, 4],
#              "protocol": "tcp",
#              "sport": "1-4"},
# ...


# Copy Ace object
ace2 = ace.copy()
print(f"{ace2.line=}", "\n")
# ace2.line="permit tcp 10.0.0.0 0.0.0.255 range 1 4 any eq ftp 22 telnet syn ack log"
