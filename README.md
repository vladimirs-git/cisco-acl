# cisco-acl

Python package to parse and manage Cisco extended ACL (Access Control List). Supported platforms:
Cisco IOS, Cisco Nexus NX-OS.

Main features:

- Parse ACL from part of Cisco config.
- Sequencing ACEs.
- Change the Cisco IOS syntax to Nexus NX-OS and vice vera.
- Grouping and sorting ACEs (Access Control Entries). The order of lines within a group does not
  change.

Contents

- [Acronyms](#acronyms)
- [Installation](#installation)
- [Code Documentation](#code-documentation)
    - [class Acl](#class-acl)
    - [class Ace](#class-ace)
    - [class AceGroup](#class-acegroup)
    - [class Remark](#class-remark)
    - [class Address](#class-address)
    - [class Port](#class-port)
    - [class Protocol](#class-protocol)
- [Examples1](#examples1)
- [Examples2](#examples2)
- [Examples3](#examples3)

# Acronyms

    Acronym     Defenition
    ==========  =======================================
    ACL         Access Control List.
    ACE         Access Control Entry.
    ACEs        Multiple Access Control Entries.
    Acl.items   List of objjects: Ace, AceGroup, Remark.

# Installation

```bash
pip install cisco-acl
```

# Code Documentation

## class Acl

ACL - Access Control List. Class has methods to manipulate with Acl.items: Ace, Remark, AceGroup.
This class implements most of the Python list methods: append(), extend(), pop(), sort(), etc.
Acl.items can be edited, sorted, indexed by sequence numbers or notes.

### Parameters

    Param       Description
    ==========  ====================================================================================
    line        ACL config (name and following remarks and access entries).
    platform    Supported platforms: "ios", "cnx". By default: "ios".
    name        By default parsed from line.
    items       List of ACE (strings or Ace, AceGroup, Remark objects). By default parsed from line.
    input       Interfaces, where Acl is used on input.
    output      Interfaces, where Acl is used on output.
    indent      ACE lines indentation. By default 2 spaces.
    note        Object description (can be used for ACEs sorting).

In the following example create Acl with default parameters. All data is parsed from the
configuration string.

```python
from cisco_acl import Acl, Remark, Ace

line = """
ip access-list extended ACL1
  remark TEXT
  permit icmp host 10.0.0.1 object-group NAME
"""
acl = Acl(line)
assert acl.line == "ip access-list extended ACL1\n  remark TEXT\n  permit icmp host 10.0.0.1 object-group NAME"
assert acl.platform == "ios"
assert acl.name == "ACL1"
assert acl.items == [Remark("remark TEXT"), Ace("permit icmp host 10.0.0.1 object-group NAME")]
assert acl.indent == "  "
assert acl.note == ""
print(acl)
# ip access-list extended ACL1
#   remark TEXT
#   permit icmp host 10.0.0.1 object-group NAME
```

In the following example create Acl with optional parameters. The data is taken from params. Note,
line is empty.

```python
from cisco_acl import Acl, Remark, Ace

acl = Acl(line="",
          platform="ios",
          name="ACL1",
          items=[Remark("remark TEXT"), Ace("permit icmp host 10.0.0.1 object-group NAME")],
          input=["interface FastEthernet1"],
          output=[],
          indent=1,
          note="allow icmp")
assert acl.line == "ip access-list extended ACL1\n remark TEXT\n permit icmp host 10.0.0.1 object-group NAME"
assert acl.platform == "ios"
assert acl.name == "ACL1"
assert acl.ip_acl_name == "ip access-list extended ACL1"
assert acl.items == [Remark("remark TEXT"), Ace("permit icmp host 10.0.0.1 object-group NAME")]
assert acl.indent == " "
assert acl.note == "allow icmp"
print(acl)
# ip access-list extended ACL1
#  remark TEXT
#  permit icmp host 10.0.0.1 object-group NAME
```

### Methods

    Method      Description
    ==========  ====================================================================================
    resequence  Resequence all Acl.items. Change sequence numbers.

    add         Add new Ace to Acl.items, if it is not in list (append without duplicates).
    append      Append Ace to the end of the Acl.items.
    clear       Remove all items from the Acl.items.
    copy        Return a copy of the Acl object with the Ace items copied.
    count       Return number of occurrences of items.
    delete      Remove Ace from Acl.items.
    extend      Extend Acl.items by appending items.
    index       Return first index of Ace.
    insert      Insert Ace before index.
    pop         Remove and return Ace at index (default last).
    remove      Remove first occurrence of Acl.items.
    reverse     Reverse order of items in Acl.items.
    sort        Sort Acl.items in ascending order.
    update      Extend Acl.items by adding items, if it is not in list (extend without duplicates).

#### Acl.copy()

Return a copy of the Acl object with the Ace items copied.

In the following example create an Ace object `ace`. Add it to 2 Acl objects and then change source
address in `ace`. The print shows that in `acl1` the source address will be changed, but in
copied `acl2` the source address will remain unchanged.

```python
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

#### Acl.resequence(start=10, step=10)

Resequence all Acl.items. Change sequence numbers.

    Parameter	Description
    ==============================
    start       Starting sequence number. start=0 - delete all sequence numbers.
    step        Step to increment the sequence number.

In the following example create Acl with not ordered groups, then sorting and resequence by notes.

```python
from cisco_acl import Acl, Ace, AceGroup

group1 = """
remark ====== dns ======
permit udp any any eq 53
deny udp any any
"""
group2 = """
remark ====== web ======
permit tcp any any eq 80
deny tcp any any
"""
acl = Acl("ip access-list extended ACL1")
acl.extend(items=[Ace("permit ip any any", note="3rd"),
                  AceGroup(group2, note="2nd"),
                  AceGroup(group1, note="1st")])
acl.resequence()
print(str(acl))
print()
# ip access-list extended ACL1
#   10 permit ip any any
#   20 remark ====== web ======
#   30 permit tcp any any eq 80
#   40 deny tcp any any
#   50 remark ====== dns ======
#   60 permit udp any any eq 53
#   70 deny udp any any

acl.sort(key=lambda o: o.note)
acl.resequence()
print(str(acl))
print()
# ip access-list extended ACL1
#   10 remark ====== dns ======
#   20 permit udp any any eq 53
#   30 deny udp any any
#   40 remark ====== web ======
#   50 permit tcp any any eq 80
#   60 deny tcp any any
#   70 permit ip any any
```

## class Ace

ACE (Access Control Entry). Each entry statement permit or deny in the ACL (Access Control List).

### Parameters

    Param          Description
    =============  =================================================================================
    line           ACE line.
    platform       Supported platforms: Cisco IOS - "ios", Cisco NX-OS - "cnx".
    note           Object description (can be used for ACEs sorting).

In the following example, create an Ace object and demonstrate various manipulation approaches.

```python
from cisco_acl import Ace
from netaddr import IPNetwork  # type: ignore

ace = Ace(line="10 permit tcp host 10.0.0.1 range 1 3 10.0.0.0 0.0.0.3 eq www 443 log",
          platform="ios",
          note="allow web")

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

print(ace.line)
# 10 permit tcp host 10.0.0.1 range 1 3 10.0.0.0 0.0.0.3 eq www 443 log

ace.sequence = 20
ace.protocol.name = "udp"
ace.srcaddr.prefix = "10.0.0.0/24"
ace.dstaddr.addrgroup = "NAME"
ace.srcport.line = "eq 179"
ace.dstport.ports = [80]
ace.option = ""
print(ace.line)
# 20 permit udp 10.0.0.0 0.0.0.255 eq 179 object-group NAME eq 80

ace.sequence = 0
ace.protocol.number = 1
ace.srcaddr.prefix = "0.0.0.0/0"
ace.dstaddr.line = "any"
ace.srcport.line = ""
ace.dstport.line = ""

print(ace.line)
# 10 permit tcp any any
```

### Methods

#### Ace.copy()

Returns a copy of the Ace object.

In the following example create Ace object and copy them, then change prefix in `ace1`. The print
shows that in `ace1` the prefix will be changed, but in copied `ace2` the prefix will remain
unchanged.

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

Group of ACEs. Useful for sorting ACL entries with frozen sections within which the sequence does
not change.

### Parameters

    Param          Default  Description
    =============  =======  ========================================================================
    items                   List of ACE (strings or Ace objects).
    platform        "ios"   Supported platforms: Cisco IOS - "ios", Cisco NX-OS - "cnx".
    note                    Object description (can be used for ACEs sorting).
    items                   An alternate way to create AceGroup object from a list of Ace objects. 
                            By default, an object is created from a line.
    data                    An alternate way to create AceGroup object from a *dict*. 
                            By default, an object is created from a line.

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

#### AceGroup.copy()

Returns a copy of the AceGroup object.

In the following example create AceGroup object and copy them, then change prefix in `aceg1`. The
print shows that in `aceg1` the prefix will be changed, but in copied `aceg2` the prefix will remain
unchanged.

```python
from cisco_acl import AceGroup

aceg1 = AceGroup("permit icmp any any\npermit ip any any")
aceg2 = aceg1.copy()
aceg1.items[0].srcaddr.prefix = "10.0.0.0/24"
aceg1.items[1].srcaddr.prefix = "10.0.0.0/24"
print(aceg1)
print(aceg2)
print()
# permit icmp 10.0.0.0 0.0.0.255 any
# permit ip 10.0.0.0 0.0.0.255 any
# permit icmp any any
# permit ip any any
```

#### AceGroup.data()

Returns a data of objects in dict format.

```python
from cisco_acl import AceGroup

aceg = AceGroup("permit icmp any any\npermit ip any any")
print(aceg.data())
print()
# {'platform': 'ios', 
#  'note': '', 
#  'sequence': 0, 
#  'items': ['permit icmp any any', 'permit ip any any']}
```

## class Remark

Remark (comment) about entries in access list.

### Parameters

    Param          Default  Description
    =============  =======  ========================================================================
    line                    Remark line.
    note                    Object description (can be used for ACEs sorting).

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

#### Remark.copy()

Returns a copy of the Remark object.

## class Address

### Parameters

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
    note                    Object description (can be used for ACEs sorting).

### Example

```python
from cisco_acl import Address
from netaddr import IPNetwork  # type: ignore

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

### Parameters

    Param          Default  Description
    =============  =======  ========================================================================
    line                    TCP/UDP ports line.
    platform       "ios"    Supported platforms: "ios", "cnx". By default: "ios".
    note                    Object description (can be used for ACEs sorting).

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

### Parameters

    Param          Default  Description
    =============  =======  ========================================================================
    line                    Protocol line.
    platform       "ios"    Supported platforms: "ios", "cnx". By default: "ios".
    note                    Object description (can be used for ACEs sorting).

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
