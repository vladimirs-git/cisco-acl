# cisco-acl
Python package to parse and manage Cisco ACL (Access Control List).
Supported platforms: IOS, NX-OS.

Main features:
- Parse ACL from text of Cisco config.
- Grouping and sorting ACE (Access Control Entry)
- Sequencing ACEs in ACL.
- Sorting ACE and AceGroups. The order of the lines within the AceGroup does not change.
- Generate ACL config commands (ready for ssh console)


### Installation
To install by pip
```bash
pip install cisco-acl
```

## class Acl
ACL - Access Control List. List of  Ace (Access Control Entry), Remark, AceGroup.
Items in ACL list can be sorted, indexed by sequence numbers.

### Params

    Param           Default  Description
    ==============  =======  ========================================================================
    line                    ACL config (name and following remarks and access entries).
    name            ""      ACL name.
    items           ""      List of objects: Remark, Ace, AceGroup
    platform        "ios"   Supported platforms: Cisco IOS - "ios", Cisco NX-OS - "cnx".
    note            ""      Object description (used only in object).
    indent          2       ACE lines indentation. By default 2 spaces.
    name:                   ACL name (by default taken from line param).
    input:                  Interfaces, where Acl is used on input.
    output:                 Interfaces, where Acl is used on output.

### Example
```python
from cisco_acl import Acl, Remark, Ace
line = """
ip access-list extended NAME
  remark TEXT
  permit icmp any any
  deny ip any any
"""
acl = Acl(line=line, input="interface FastEthernet1", note="allow icmp")

# result
assert acl.line == "ip access-list extended NAME\n" \
                   "  remark TEXT\n" \
                   "  permit icmp any any\n" \
                   "  deny ip any any"
assert acl.platform == "ios"
assert acl.name == "NAME"
assert acl.ip_acl_name == "ip access-list extended NAME"
assert acl.items == [Remark("remark TEXT"), Ace("permit icmp any any"), Ace("deny ip any any")]
assert acl.interface.input == ["interface FastEthernet1"]
assert acl.interface.output == []
assert acl.indent == "  "
assert acl.note == "allow icmp"
```

## class Ace
ACE - Access Control Entry. Each entry statement permit or deny in the ACL (Access Control List).

### Params

    Param          Default  Description
    =============  =======  ========================================================================
    line            ""      ACE line.
    platform        "ios"   Supported platforms: Cisco IOS - "ios", Cisco NX-OS - "cnx".
    note            ""      Object description (used only in object).

### Example
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


## class AceGroup
Grouped Access Control Entries. 
No sorting by sequence number inside group (All entries move together).

### Params

    Param          Default  Description
    =============  =======  ========================================================================
    items                   List of ACE (strings or Ace objects).
    platform        "ios"   Supported platforms: Cisco IOS - "ios", Cisco NX-OS - "cnx".
    note            ""      Object description (used only in object).

### Example
```python
from cisco_acl import AceGroup, Remark, Ace

items = ["remark TEXT", "permit icmp any any", "deny ip any any"]
group = AceGroup(items=items, note="allow icmp")

# result
assert group.line == "remark TEXT\npermit icmp any any\ndeny ip any any"
assert group.platform == "ios"
assert group.items == [Remark("remark TEXT"), Ace("permit icmp any any"), Ace("deny ip any any")]
assert group.note == "allow icmp"
```


## class Remark
Remark (comment) about entries in access list.

### Params

    Param          Default  Description
    =============  =======  ========================================================================
    line            ""      Remark line.
    note            ""      Object description (used only in object).

### Example
```python
from cisco_acl import Remark
from netaddr import IPNetwork

remark = Remark(line="10 remark text", note="allow web")

# result
assert remark.line == "10 remark text"
assert remark.sequence == 10
assert remark.action == "remark"
assert remark.text == "text"
assert remark.note == "description"
```


# Examples
[examples/examples_acl.py](examples/examples_acl.py) 
- Create flat ACL.
- Generate sequences for ACEs.
- Move one ACE.
- Resequence ACEs.

[examples/examples_acl.py](examples/examples_acl_objects.py) 
- Create ACL from strings.
- Create ACL from objects.
- Create ACL with groups (rules). 
- Generate sequences for ACEs.
- Move group and resequence ACEs.


# Planned features
[TODO.md](TODO.md) 