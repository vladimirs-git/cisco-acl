# cisco-acl

Python package to parse and manage Cisco ACL (Access Control List). Supported platforms: IOS, NX-OS.

Main features:

- Parse ACL from text of Cisco config.
- Grouping and sorting ACEs. The order of the lines within the AceGroup does not change.
- Sequencing ACEs in ACL.
- Change syntax from Cisco IOS platform to Cisco Nexus NX-OS and vice vera.

### Installation

```bash
pip install cisco-acl
```

## class Acl

ACL - Access Control List. List of Ace (Access Control Entry), Remark, AceGroup. Items in ACL list
can be edited, sorted, indexed by sequence numbers.

### Params

    Param       Default     Description
    ==========  ==========  ========================================================================
    line                    ACL config (name and following remarks and access entries).
    platform    "ios"       Supported platforms: "ios", "cnx". By default: "ios".
    name                    By default parsed from line.
    items                   List of ACE (strings or Ace, AceGroup, Remark objects).
                            By default parsed from line.
    input                   Interfaces, where Acl is used on input.
    output                  Interfaces, where Acl is used on output.
    indent      2           ACE lines indentation. By default 2 spaces.
    note                    Object description (used only in object).

```python
from cisco_acl import Acl, Remark, Ace

line = """
ip access-list extended NAME
  remark TEXT
  permit icmp any any
"""
acl = Acl(line=line, platform="ios", indent=1, note="allow icmp")

# result
assert acl.line == "ip access-list extended NAME\n remark TEXT\n permit icmp any any"
assert acl.platform == "ios"
assert acl.name == "NAME"
assert acl.items == [Remark("remark TEXT"), Ace("permit icmp any any")]
assert acl.ip_acl_name == "ip access-list extended NAME"
assert acl.indent == " "
assert acl.note == "allow icmp"
```

### Methods

#### copy()

Returns a copy of the Acl object with the Ace items copied.

```python
# Create an Ace object `ace`. Add it to 2 Acl objects and then change source address in `ace`.
# The print shows that in `acl1` the source address will be changed, 
# but in copied `acl2` the source address will remain unchanged.
from cisco_acl import Acl, Ace

ace = Ace("permit ip any any")
acl1 = Acl(name="ACL1", items=[ace])
acl2 = acl1.copy()
ace.srcaddr.prefix = "10.0.0.0/24"
print(acl1)
print(acl2)
print()
# ip access-list extended ACL1
#   permit ip 10.0.0.0 0.0.0.255 any
# ip access-list extended ACL1
#   permit ip any any
```

#### resequence(start, step)

Resequence all entries in an ACL.

    Parameter	Description
    ==============================
    start       Starting sequence number. start=0 - delete all sequence numbers.
    step        Step to increment the sequence number.

```python
from cisco_acl import Ace, Protocol, Address, Port
from netaddr import IPNetwork
from cisco_acl import Acl

lines = """
ip access-list extended ACL1
  permit icmp any any
  permit tcp host 10.0.0.1 any
  deny ip any any
"""
acl1 = Acl(lines)
print(acl1)
print()
# ip access-list extended ACL1
#   permit icmp any any
#   permit tcp host 10.0.0.1 any
#   deny ip any any

acl1.resequence()
print(acl1)
print()
# ip access-list extended ACL1
#   10 permit icmp any any
#   20 permit tcp host 10.0.0.1 any
#   30 deny ip any any

acl1.resequence(start=2, step=3)
print(acl1)
print()
# ip access-list extended ACL1
#   2 permit icmp any any
#   5 permit tcp host 10.0.0.1 any
#   8 deny ip any any

acl1.resequence(start=0)
print(acl1)
print()
# ip access-list extended ACL1
#   permit icmp any any
#   permit tcp host 10.0.0.1 any
#   deny ip any any
```

## class Ace

ACE (Access Control Entry). Each entry statement permit or deny in the ACL (Access Control List).

### Params

    Param          Default  Description
    =============  =======  ========================================================================
    line            ""      ACE line.
    platform        "ios"   Supported platforms: Cisco IOS - "ios", Cisco NX-OS - "cnx".
    note            ""      Object description (used only in object).

```python
from cisco_acl import Ace
from netaddr import IPNetwork

ace = Ace(line="10 permit tcp host 10.0.0.1 range 1 3 10.0.0.0 0.0.0.3 eq www 443 log",
          platform="ios",
          note="allow web")
# result
assert ace.note == "allow web"
assert ace.line == "10 permit tcp host 10.0.0.1 range 1 3 10.0.0.0 0.0.0.3 eq www 443 log"
assert ace.platform == "ios"
assert ace.sequence == 10
assert ace.action == "permit"
assert ace.protocol.line == "tcp"
assert ace.protocol.name == "tcp"
assert ace.protocol.number == 6
assert ace.srcaddr.line == "host 10.0.0.1"
assert ace.srcaddr.addrgroup == ""
assert ace.srcaddr.ipnet == IPNetwork("10.0.0.1/32")
assert ace.srcaddr.prefix == "10.0.0.1/32"
assert ace.srcaddr.subnet == "10.0.0.1 255.255.255.255"
assert ace.srcaddr.wildcard == "10.0.0.1 0.0.0.0"
assert ace.srcport.line == "range 1 3"
assert ace.srcport.operator == "range"
assert ace.srcport.ports == [1, 2, 3]
assert ace.srcport.sport == "1-3"
assert ace.dstaddr.line == "10.0.0.0 0.0.0.3"
assert ace.dstaddr.addrgroup == ""
assert ace.dstaddr.ipnet == IPNetwork("10.0.0.0/30")
assert ace.dstaddr.prefix == "10.0.0.0/30"
assert ace.dstaddr.subnet == "10.0.0.0 255.255.255.252"
assert ace.dstaddr.wildcard == "10.0.0.0 0.0.0.3"
assert ace.dstport.line == "eq www 443"
assert ace.dstport.operator == "eq"
assert ace.dstport.ports == [80, 443]
assert ace.dstport.sport == "80,443"
assert ace.option == "log"
```

### Methods

#### copy()

Returns a copy of the Ace object.

```python
from cisco_acl import Ace

ace1 = Ace("permit ip any any")
ace2 = ace1.copy()
ace1.srcaddr.prefix = "10.0.0.0/24"
print(ace1)
print(ace2)
print()
# permit ip 10.0.0.0 0.0.0.255 any
# permit ip any any
```

## class AceGroup

Group of ACE (Access Control Entry). Useful for sorting ACL entries with frozen sections within
which the sequence does not change.

### Params

    Param          Default  Description
    =============  =======  ========================================================================
    items                   List of ACE (strings or Ace objects).
    platform        "ios"   Supported platforms: Cisco IOS - "ios", Cisco NX-OS - "cnx".
    note                    Object description (used only in object).
    items                   List of ACE (strings or Ace objects). By default parsed from line.

```python
from cisco_acl import AceGroup, Remark, Ace

lines = """
remark ===== dns =====
permit udp any any eq 53
"""
group = AceGroup(line=lines, note="allow dns")

assert group.line == "remark ===== dns =====\npermit udp any any eq 53"
assert group.platform == "ios"
assert group.items == [Remark("remark ===== dns ====="), Ace("permit udp any any eq 53"), ]
assert group.note == "allow dns"
print(group)
print()
# remark ===== dns =====
# permit udp any any eq 53
```

### Methods

#### copy()

Returns a copy of the AceGroup object.

## class Remark

Remark (comment) about entries in access list.

### Params

    Param          Default  Description
    =============  =======  ========================================================================
    line                    Remark line.
    note                    Object description (used only in object).

### Example

```python
from cisco_acl import Remark

remark = Remark(line="10 remark text", note="description")

assert remark.line == "10 remark text"
assert remark.sequence == 10
assert remark.action == "remark"
assert remark.text == "text"
assert remark.note == "description"
```

### Methods

#### copy()

Returns a copy of the Remark object.

## class Address

### Params

    Param          Default  Description
    =============  =======  ========================================================================
    line                    Address line.

            line pattern        platform    description
            ==================  ==========  ===========================
            A.B.C.D A.B.C.D                 Address and wildcard bits
            A.B.C.D/LEN         cnx         Network prefix
            any                             Any host
            host A.B.C.D        ios         A single host
            object-group NAME   ios         Network object group
            addrgroup NAME      cnx         Network object group

    platform       "ios"    Supported platforms: "ios", "cnx". By default: "ios".
    note                    Object description (used only in object).

### Example

```python
from cisco_acl import Address
from netaddr import IPNetwork

addr = Address("10.0.0.0 0.0.0.3", platform="ios")
assert addr.line == "10.0.0.0 0.0.0.3"
assert addr.platform == "ios"
assert addr.addrgroup == ""
assert addr.prefix == "10.0.0.0/30"
assert addr.subnet == "10.0.0.0 255.255.255.252"
assert addr.wildcard == "10.0.0.0 0.0.0.3"
assert addr.ipnet == IPNetwork("10.0.0.0/30")

# Change syntax from Cisco IOS platform to Cisco Nexus NX-OS.
addr = Address("10.0.0.0 0.0.0.3", platform="ios")
assert addr.line == "10.0.0.0 0.0.0.3"
addr.platform = "cnx"
assert addr.line == "10.0.0.0/30"

addr = Address("host 10.0.0.1", platform="ios")
assert addr.line == "host 10.0.0.1"
addr.platform = "cnx"
assert addr.line == "10.0.0.1/32"

addr = Address("object-group NAME", platform="ios")
assert addr.line == "object-group NAME"
addr.platform = "cnx"
assert addr.line == "addrgroup NAME"
```

[examples/examples_address.py](examples/examples_address.py)

## class Port

### Params

    Param          Default  Description
    =============  =======  ========================================================================
    line                    TCP/UDP ports line.
    platform       "ios"    Supported platforms: "ios", "cnx". By default: "ios".
    note                    Object description (used only in object).

### Example

```python
from cisco_acl import Port

port = Port("eq www 443 444 445", platform="ios")
assert port.line == "eq www 443 444 445"
assert port.platform == "ios"
assert port.operator == "eq"
assert port.items == [80, 443, 444, 445]
assert port.ports == [80, 443, 444, 445]
assert port.sport == "80,443-445"

port = Port("range 1 5", platform="ios")
assert port.line == "range 1 5"
assert port.platform == "ios"
assert port.operator == "range"
assert port.items == [1, 5]
assert port.ports == [1, 2, 3, 4, 5]
assert port.sport == "1-5"
```

[examples/examples_port.py](examples/examples_port.py)

## class Protocol

### Params

    Param          Default  Description
    =============  =======  ========================================================================
    line                    Protocol line.
    platform       "ios"    Supported platforms: "ios", "cnx". By default: "ios".
    note                    Object description (used only in object).

### Example

```python
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
```

[examples/examples_protocol.py](examples/examples_protocol.py)

# Examples1

- Create ACL.
- Generate sequence numbers.
- Moved up ACE "deny tcp any any eq 53".
- Resequence numbers.
- Delete sequences.
- Change syntax from Cisco IOS platform to Cisco Nexus NX-OS.
- Change syntax from Cisco Nexus NX-OS platform to Cisco IOS.

```python
from cisco_acl import Acl

lines1 = """
ip access-list extended ACL1
  permit icmp any any
  permit ip object-group A object-group B log
  permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4
  deny tcp any any eq 53
"""

# Create ACL.
# Note, str(acl1) and acl1.line return the same value.
acl1 = Acl(lines1)
print(str(acl1))
print()
# ip access-list extended ACL1
#   permit icmp any any
#   permit ip object-group A object-group B log
#   permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4
#   deny tcp any any eq 53


# Generate sequence numbers.
acl1.resequence()
print(acl1.line)
print()
# ip access-list extended ACL1
#   10 permit icmp any any
#   20 permit ip object-group A object-group B log
#   30 permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4
#   40 deny tcp any any eq 53

# Moved up ACE "deny tcp any any eq 53".
# Note that ACE have been moved up with the same sequence numbers.
# Note, Ace class has list methods pop(), insert().
rule1 = acl1.pop(3)
acl1.insert(0, rule1)
print(acl1)
print()
# ip access-list extended ACL1
#   40 deny tcp any any eq 53
#   10 permit icmp any any
#   20 permit ip object-group A object-group B log
#   30 permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4

# Resequence numbers with custom start and step.
acl1.resequence(start=100, step=1)
print(acl1)
print()
# ip access-list extended ACL1
#   100 deny tcp any any eq 53
#   101 permit icmp any any
#   102 permit ip object-group A object-group B log
#   103 permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4

# Delete sequences.
acl1.resequence(start=0)
print(f"{acl1.platform=}")
print(acl1)
print()
# acl1.platform='ios'
# ip access-list extended ACL1
#   deny tcp any any eq 53
#   permit icmp any any
#   permit ip object-group A object-group B log
#   permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4

# Change syntax from Cisco IOS platform to Cisco Nexus NX-OS.
acl1.platform = "cnx"
print(f"{acl1.platform=}")
print(acl1)
print()
# acl1.platform='cnx'
# ip access-list ACL1
#   deny tcp any any eq 53
#   permit icmp any any
#   permit ip addrgroup A addrgroup B log
#   permit tcp 1.1.1.1/32 eq 1 2.2.2.0/24 eq 3
#   permit tcp 1.1.1.1/32 eq 1 2.2.2.0/24 eq 4
#   permit tcp 1.1.1.1/32 eq 2 2.2.2.0/24 eq 3
#   permit tcp 1.1.1.1/32 eq 2 2.2.2.0/24 eq 4

# Change syntax from Cisco Nexus NX-OS platform to Cisco IOS.
acl1.platform = "ios"
print(f"{acl1.platform=}")
print(acl1)
print()
# acl1.platform='ios'
# ip access-list extended ACL1
#   deny tcp any any eq 53
#   permit icmp any any
#   permit ip object-group A object-group B log
#   permit tcp host 1.1.1.1 eq 1 2.2.2.0 0.0.0.255 eq 3
#   permit tcp host 1.1.1.1 eq 1 2.2.2.0 0.0.0.255 eq 4
#   permit tcp host 1.1.1.1 eq 2 2.2.2.0 0.0.0.255 eq 3
#   permit tcp host 1.1.1.1 eq 2 2.2.2.0 0.0.0.255 eq 4

```

[examples/examples_acl.py](examples/examples_acl.py)

# Examples2

- Create ACL with groups.
- Generate sequence numbers.
- Sort rules by comment.
- Resequence numbers.

```python
from cisco_acl import Acl, AceGroup

lines = """
ip access-list extended ACL1
  permit icmp any any
  permit ip object-group A object-group B log
  permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4
"""

# Create ACL1.
# Note, str(acl1) and acl1.line return the same value.
acl1 = Acl(lines)
print(str(acl1))
print()
# ip access-list extended ACL1
#   permit icmp any any
#   permit ip object-group A object-group B log
#   permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4

# Create Ace groups. One making from string, other from Acl object.
lines1 = """
remark ===== web =====
permit tcp any any eq 80
"""
group1 = AceGroup(lines1)
print(str(group1))
print()
# remark ===== web =====
# permit tcp any any eq 80

lines2 = """
ip access-list extended ACL2
  remark ===== dns =====
  permit udp any any eq 53
  permit tcp any any eq 53
"""
acl2 = Acl(lines2)
print(str(acl2))
print()
# ip access-list extended ACL2
#   remark ===== dns =====
#   permit udp any any eq 53
#   permit tcp any any eq 53

# Convert Acl object to to AceGroup.
group2 = AceGroup(str(acl2))
print(str(group2))
print()
# remark ===== dns =====
# permit udp any any eq 53
# permit tcp any any eq 53

# Add groups to acl1.
# Note, acl1.append() and acl1.items.append() make the same action.
# The Acl class implements all list methods.
# For demonstration, one group added by append() other by extend() methods.
acl1.append(group1)
acl1.extend([group2])
print(str(acl1))
print()
# ip access-list extended ACL1
#   permit icmp any any
#   permit ip object-group A object-group B log
#   permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4
#   remark ===== web =====
#   permit tcp any any eq 80
#   remark ===== dns =====
#   permit udp any any eq 53
#   permit tcp any any eq 53

# Generate sequence numbers.
acl1.resequence()
print(acl1.line)
print()
# ip access-list extended ACL1
#   10 permit icmp any any
#   20 permit ip object-group A object-group B log
#   30 permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4
#   40 remark ===== web =====
#   50 permit tcp any any eq 80
#   60 remark ===== dns =====
#   70 permit udp any any eq 53
#   80 permit tcp any any eq 53

# Add note to Acl items
notes = ["icmp", "object-group", "host 1.1.1.1", "web", "dns"]
for idx, note in enumerate(notes):
    acl1[idx].note = note
for item in acl1:
    print(repr(item))
print()
# Ace('10 permit icmp any any', note='icmp')
# Ace('20 permit ip object-group A object-group B log', note='object-group')
# Ace('30 permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4', note='host 1.1.1.1')
# AceGroup('40 remark ===== web =====\n50 permit tcp any any eq 80', note='web')
# AceGroup('60 remark ===== dns =====\n70 permit udp any any eq 53\n80 permit tcp any any eq 53', note='dns')

# Sorting rules by notes.
# Note that ACE have been moved up with the same sequence numbers.
acl1.sort(key=lambda o: o.note)
print(acl1)
print()
# ip access-list extended ACL1
#   60 remark ===== dns =====
#   70 permit udp any any eq 53
#   80 permit tcp any any eq 53
#   30 permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4
#   10 permit icmp any any
#   20 permit ip object-group A object-group B log
#   40 remark ===== web =====
#   50 permit tcp any any eq 80

# Resequence numbers with custom start and step.
acl1.resequence(start=100, step=1)
print(acl1)
print()
# ip access-list extended ACL1
#   100 remark ===== dns =====
#   101 permit udp any any eq 53
#   102 permit tcp any any eq 53
#   103 permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4
#   104 permit icmp any any
#   105 permit ip object-group A object-group B log
#   106 remark ===== web =====
#   107 permit tcp any any eq 80

```

[examples/examples_acl_group.py](examples/examples_acl_group.py)

# Examples3

- Create ACL from objects, with groups.

```python
from cisco_acl import Acl, Ace, AceGroup, Remark

name1 = "ACL1"
items1 = [
    Remark("remark text"),
    Ace("permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 range 3 4"),
    Ace("deny ip any any"),
    AceGroup(items=[Remark("remark ===== web ====="),
                    Ace("permit tcp any any eq 80")]),
    AceGroup(items=[Remark("remark ===== dns ====="),
                    Ace("permit udp any any eq 53"),
                    Ace("permit tcp any any eq 53")]),
]

# Create ACL from objects.
# Note that the items type is <object>.
acl1 = Acl(name=name1, items=items1)
print(acl1)
print()
# ip access-list extended ACL1
#   remark text
#   permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 range 3 4
#   deny ip any any
#   remark ===== web =====
#   permit tcp any any eq 80
#   remark ===== dns =====
#   permit udp any any eq 53
#   permit tcp any any eq 53

for item in acl1:
    print(repr(item))
print()
# Remark('remark text')
# Ace('permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 range 3 4')
# Ace('deny ip any any')
# AceGroup('remark ===== web =====\npermit tcp any any eq 80')
# AceGroup('remark ===== dns =====\npermit udp any any eq 53\npermit tcp any any eq 53')
```

[examples/examples_acl_objects.py](examples/examples_acl_objects.py)

# Planned features

[TODO.md](TODO.md) 