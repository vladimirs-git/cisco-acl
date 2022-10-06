"""**Ace(line)**
The following example creates an Ace object and demonstrate various manipulation approaches.
"""

from ipaddress import IPv4Network

from cisco_acl import Ace

ace = Ace(line="10 permit tcp host 10.0.0.1 range 21 23 10.0.0.0 0.0.0.3 eq 80 443 log",
          platform="ios",
          note="allow web")

assert ace.note == "allow web"
assert ace.line == "10 permit tcp host 10.0.0.1 range ftp telnet 10.0.0.0 0.0.0.3 eq www 443 log"
assert ace.platform == "ios"
assert ace.sequence == 10
assert ace.action == "permit"
assert ace.protocol.line == "tcp"
assert ace.protocol.name == "tcp"
assert ace.protocol.number == 6
assert ace.srcaddr.line == "host 10.0.0.1"
assert ace.srcaddr.addrgroup == ""
assert ace.srcaddr.ipnet == IPv4Network("10.0.0.1/32")
assert ace.srcaddr.prefix == "10.0.0.1/32"
assert ace.srcaddr.subnet == "10.0.0.1 255.255.255.255"
assert ace.srcaddr.wildcard == "10.0.0.1 0.0.0.0"
assert ace.srcport.line == "range ftp telnet"
assert ace.srcport.operator == "range"
assert ace.srcport.ports == [21, 22, 23]
assert ace.srcport.sport == "21-23"
assert ace.dstaddr.line == "10.0.0.0 0.0.0.3"
assert ace.dstaddr.addrgroup == ""
assert ace.dstaddr.ipnet == IPv4Network("10.0.0.0/30")
assert ace.dstaddr.prefix == "10.0.0.0/30"
assert ace.dstaddr.subnet == "10.0.0.0 255.255.255.252"
assert ace.dstaddr.wildcard == "10.0.0.0 0.0.0.3"
assert ace.dstport.line == "eq www 443"
assert ace.dstport.operator == "eq"
assert ace.dstport.ports == [80, 443]
assert ace.dstport.sport == "80,443"
assert ace.option.line == "log"

# prints well-known TCP/UDP ports as names or as numbers
print(ace.line)
# 10 permit tcp host 10.0.0.1 range ftp telnet 10.0.0.0 0.0.0.3 eq www 443 log
ace.port_nr = True
print(ace.line)
# 10 permit tcp host 10.0.0.1 range 21 23 10.0.0.0 0.0.0.3 eq 80 443 log

ace.port_nr = False
ace.sequence = 20
ace.protocol.name = "udp"
# ace.srcaddr.prefix = "10.0.0.0/24"
# ace.dstaddr.addrgroup = "NAME"
ace.srcport.line = "eq 179"
ace.dstport.ports = [80]
ace.option.line = ""
print(ace.line)
# 20 permit udp 10.0.0.0 0.0.0.255 eq 179 object-group NAME eq 80

ace.sequence = 0
ace.protocol.number = 1
# ace.srcaddr.prefix = "0.0.0.0/0"
ace.dstaddr.line = "any"
ace.srcport.line = ""
ace.dstport.line = ""

print(ace.line)
print()
# 10 permit tcp any any

# copy
ace1 = Ace("permit ip any any")
ace2 = ace1.copy()
# ace1.srcaddr.prefix = "10.0.0.0/24"
print(ace1)
print(ace2)
print()
# permit ip 10.0.0.0 0.0.0.255 any
# permit ip any any
