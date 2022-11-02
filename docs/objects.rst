
cisco-acl Objects
=================

.. contents:: **Contents**
	:local:


Acl
---
ACL - Access Control List. Support lines that starts with "allow", "deny", "remark".
This class implements most of the Python list methods: append(), extend(), sort(), etc.

=============== ============ =======================================================================
Parameter       Type         Description
=============== ============ =======================================================================
line            *str*        ACL config, "show running-config" output
platform        *str*        Platform: "ios" (default), "nxos"
input           *str*        Interfaces, where Acl is used on input
output          *str*        Interfaces, where Acl is used on output
note            *Any*        Object description
indent          *str*        ACE lines indentation (default "  ")
protocol_nr     *bool*       Well-known ip protocols as numbers, True  - all ip protocols as numbers, False - well-known ip protocols as names (default)
port_nr         *bool*       Well-known TCP/UDP ports as numbers, True  - all tcp/udp ports as numbers, False - well-known tcp/udp ports as names (default)
group_by        *str*        group_by        *str*        Startswith in remark line. ACEs group, starting from the Remark, where line startswith `group_by`, will be applied to the same AceGroup, until next Remark that also startswith `group_by`
type            *str*        ACL type: "extended", "standard" (default from `line`)
name            *str*        ACL name (default from `line`)
items           *List[str]*  ACEs items: *str*, *Ace*, *AceGroup*, *Remark* objects (default from `line`)
=============== ============ =======================================================================


Attributes
::::::::::

=============== ============ =======================================================================
Attributes      Type         Description
=============== ============ =======================================================================
group_by        *str*        Groups ACEs to *AceGroup* by startswith ot this value in remarks
indent          *str*        ACE lines indentation (default "  ")
input           *List[str]*  Interfaces where Acl is used on input
items           *List[Ace]*  List of ACE items: *Ace*, *Remark*, *AceGroup*
line            *str*        ACL config line
name            *str*        ACL name
note            *Any*        Object description
output          *List[str]*  Interfaces where Acl is used on output
platform        *str*        Platform: "ios" Cisco IOS, "nxos" Cisco Nexus NX-OS
=============== ============ =======================================================================


Methods
:::::::


copy()
......
**Acl.copy()** - Returns copy ot self object


data()
......
**Acl.data()** - Converts *Acl* object to *dict*


group()
.......
**Acl.group(group_by)** - Groups ACEs to *AceGroup* by `group_by` startswith in remarks


delete_shadow()
...............
**Acl.delete_shadow(skip)** - Removes ACEs in the shadow (in the bottom, without hits) from ACL

=============== ============ =======================================================================
Parameter       Type         Description
=============== ============ =======================================================================
skip            *List[str]*  Skips checking specified address type: "addrgroup", "nc_wildcard"
=============== ============ =======================================================================

Return
    *dict* Shading (in the top) and shadow (in the bottom) ACEs



resequence()
............
**Acl.resequence()** - Resequences all Acl.items and change sequence numbers

=============== ============ =======================================================================
Parameter       Type         Description
=============== ============ =======================================================================
start           *int*        Starting sequence number. start=0 - delete all sequence numbers
step            *int*        Step to increment the sequence number
items           *List[Ace]*  List of Ace objects.  (default self.items)
=============== ============ =======================================================================

Return
    Last sequence number


shadow_of()
...........
**Acl.shadow_of(skip)** - Returns ACEs in the shadow (in the bottom)
NOTES:
- Method compare *Ace* with the same action. ACEs where self.action=="permit" and other.action=="deny" not taken into account (skip checking)
- Not supported: non-contiguous wildcard

=============== ============ =======================================================================
Parameter       Type         Description
=============== ============ =======================================================================
skip            *List[str]*  Skips checking specified address type: "addrgroup", "nc_wildcard"
=============== ============ =======================================================================

Return
    *List[str]* ACEs in the shadow


shading()
.........
**Acl.shading(skip)** - Returns shading (in the top) and shadow (in the bottom) ACEs as *dict*,
where *key* is shading rule, *value* shadow rules.
NOTES:
- Method compare *Ace* with the same action. ACEs where self.action=="permit" and other.action=="deny" not taken into account (skip checking)
- Not supported: non-contiguous wildcard

=============== ============ =======================================================================
Parameter       Type         Description
=============== ============ =======================================================================
skip            *List[str]*  Skips checking specified address type: "addrgroup", "nc_wildcard"
=============== ============ =======================================================================


Return
    *dict* Shading (in the top) and shadow (in the bottom) ACEs


tcam_count()
............
**Acl.tcam_count()** - Calculates sum of ACEs.
Also takes into account the addresses in the address group.
Useful for getting an estimate of the amount of TCAM resources needed for this ACL

Return
    *int* Count of TCAM resources


ungroup_ports()
...............
**Acl.ungroup_ports()** - Ungroups ACEs with multiple ports in single line ("eq" or "neq")
to multiple lines with single port


ungroup()
.........
**Acl.ungroup()** - Ungroups *AceGroup* to a flat list of *Ace* items



Generic List Methods
::::::::::::::::::::
`.list_methods__acl.rst`_


**Examples**

`./examples/examples_acl.py`_



Ace
---
ACE - Access Control Entry

=============== ============ =======================================================================
Parameter       Type         Description
=============== ============ =======================================================================
line            *str*        ACE config, a line that starts with "allow" or "deny"
platform        *str*        Platform: "ios" (default), "nxos"
note            *Any*        Object description
protocol_nr     *bool*       Well-known ip protocols as numbers, True  - all ip protocols as numbers, False - well-known ip protocols as names (default)
port_nr         *bool*       Well-known TCP/UDP ports as numbers, True  - all tcp/udp ports as numbers, False - well-known tcp/udp ports as names (default)
=============== ============ =======================================================================


Attributes
::::::::::

=============== ============ =======================================================================
Attributes      Type         Description
=============== ============ =======================================================================
action          *str*        ACE action: "permit", "deny"
dstaddr         *Address*    ACE source address: "any", "host A.B.C.D", "A.B.C.D A.B.C.D", "A.B.C.D/24",
dstport         *Port*       ACE destination ports: "eq www 443", ""neq 1 2", "lt 2", "gt 2", "range 1 3"
line            *str*        ACE config, a line that starts with "allow" or "deny"
note            *Any*        Object description
option          *Option*     ACE option: "syn", "ack", "log", etc
platform        *str*        Platform: "ios" Cisco IOS, "nxos" Cisco Nexus NX-OS
protocol        *Protocol*   ACE protocol: "ip", "icmp", "tcp", etc.
sequence        *int*        ACE sequence number in ACL
srcaddr         *Address*    ACE source address: "any", "host A.B.C.D", "A.B.C.D A.B.C.D", "A.B.C.D/24",
srcport         *Port*       ACE source Port object
=============== ============ =======================================================================


Methods
:::::::


copy()
......
**Ace.copy()** - Copies the self object


data()
......
**Ace.data()** - Converts *Ace* object to *dict*


shadow_of()
..............
**Ace.shadow_of(other, skip)** - Checks is ACE in the shadow of other ACE
NOTES:
- Method compare *Ace* with the same action. ACEs where self.action=="permit" and other.action=="deny" not taken into account (skip checking)
- Not supported: non-contiguous wildcard

=============== ============ =======================================================================
Parameter       Type         Description
=============== ============ =======================================================================
other           *Ace*        Other *Ace* object
skip            *List[str]*  Skips checking specified address type: "addrgroup", "nc_wildcard"
=============== ============ =======================================================================

Return
	True - self *Ace* is in the shadow of other *Ace*

Raises
	ValueError if one of addresses is non-contiguous wildcard


ungroup_ports()
...............
**Ace.ungroup_ports()** - If self.srcport or self.dstport has "eq" or "neq" with multiple ports,
then split them to multiple *Ace*

Return
	List of *Ace* with single port in each line


**Examples**

`./examples/examples_ace.py`_



AceGroup
--------
Group of ACE (Access Control Entry).
These are multiple ACEe items, which must be in a certain order.
If you are changing *Ace* items order (sequence numbers) inside *Acl*,
the AceGroup behaves like a single item and order of ACE items inside AceGroup is not changed.
AceGroup is useful for freezing ACEs section, to hold "deny" after certain "permit".
This class implements most of the Python list methods: append(), extend(), sort(), etc.

=============== ============ =======================================================================
Parameter       Type         Description
=============== ============ =======================================================================
line            *str*        String of ACEs, lines that starts with "allow", "deny", "remark".
platform        *str*        Platform: "ios" (default), "nxos"
note            *Any*        Object description
protocol_nr     *bool*       Well-known ip protocols as numbers, True  - all ip protocols as numbers, False - well-known ip protocols as names (default)
port_nr         *bool*       Well-known TCP/UDP ports as numbers, True  - all tcp/udp ports as numbers, False - well-known tcp/udp ports as names (default)
group_by        *str*        Startswith in remark line. ACEs group, starting from the Remark, where line startswith `group_by`, will be applied to the same AceGroup, until next Remark that also startswith `group_by`
type            *str*        ACL type: "extended", "standard" (default "extended")
name            *str*        Name of AceGroup, usually Remark.text of 1st self.items
items           *List[Ace]*  An alternate way to create *AceGroup* object from a list of *Ace* objects (default from a line)
=============== ============ =======================================================================


Attributes
::::::::::

=============== ============ =======================================================================
Attributes      Type         Description
=============== ============ =======================================================================
items           *List[Ace]*  List of ACE items: *Ace*, *Remark*, *AceGroup*
line            *str*        ACE lines joined to ACL line
name            *str*        AceGroup name
note            *Any*        Object description
platform        *str*        Platform: "ios" Cisco IOS, "nxos" Cisco Nexus NX-OS
sequence        *int*        ACE sequence number
=============== ============ =======================================================================


Methods
:::::::


copy()
......
**AceGroup.copy()** - Copies the self object


data()
......
**AceGroup.data()** - Converts *AceGroup* object to *dict*


delete_note()
.............
**AceGroup.delete_note(item)** - Deletes note in all children self.items: Ace, AceGroup, Remark


resequence()
............
**AceGroup.resequence()** - Resequences all AceGroup.items and change sequence numbers

=============== ============ =======================================================================
Parameter       Type         Description
=============== ============ =======================================================================
start           *int*        Starting sequence number. start=0 - delete all sequence numbers
step            *int*        Step to increment the sequence number
items           *List[Ace]*  List of Ace objects.  (default self.items)
=============== ============ =======================================================================

Return
	Last sequence number


ungroup_ports()
...............
**Acl.ungroup_ports()** - Ungroups ACEs with multiple ports in single line ("eq" or "neq")
to multiple lines with single port


Generic List Methods
::::::::::::::::::::
`.list_methods__ace_group.rst`_


**Examples**

`./examples/examples_ace_group.py`_

`./examples/examples_acl_objects.py`_



Remark
------
Remark - comments in ACL

=============== ============ =======================================================================
Parameter       Type         Description
=============== ============ =======================================================================
line            *str*        string of ACEs
platform        *str*        Platform: "ios" (default), "nxos"
note            *Any*        Object description
=============== ============ =======================================================================


Attributes
::::::::::

=============== ============ =======================================================================
Attributes      Type         Description
=============== ============ =======================================================================
action          *str*        ACE remark action
line            *str*        ACE remark line
text            *str*        ACE remark text
=============== ============ =======================================================================


Methods
:::::::

copy()
......
**Remark.copy()** - Copies the self object


data()
......
**Remark.data()** - Converts *Remark* object to *dict*


**Examples**

`./examples/examples_remark.py`_



Address
-------
Address - Source or destination address in ACE

=============== ============ =======================================================================
Parameter       Type         Description
=============== ============ =======================================================================
line            *str*        Address line: "A.B.C.D A.B.C.D", "A.B.C.D/LEN", "any", "host A.B.C.D", "object-group NAME", "addrgroup NAME"
platform        *str*        Platform: "ios" (default), "nxos"
note            *Any*        Object description
items           *List[str]*  List of addresses for address group
=============== ============ =======================================================================

where line

=================== =========== ====================================================================
Line pattern        Platform    Description
=================== =========== ====================================================================
A.B.C.D A.B.C.D     ios, nxos   Address and wildcard bits
A.B.C.D/LEN         nxos        Network prefix
any                 ios, nxos   Any host
host A.B.C.D        ios         A single host
object-group NAME   ios         Network object group
addrgroup NAME      nxos        Network object group
=================== =========== ====================================================================


Attributes
::::::::::

=============== =============== ====================================================================
Attributes      Type            Description
=============== =============== ====================================================================
line            *str*           Address line: "A.B.C.D A.B.C.D", "A.B.C.D/LEN", "any", "host A.B.C.D", "object-group NAME", "addrgroup NAME"
type            *str*           Address type: "addrgroup", "prefix", "subnet", "wildcard"
addrgroup       *str*           Address group name, if type="addrgroup". Value of "object-group NAME", "addrgroup NAME"
ipnet           *IpNetwork*     Address IPv4Network object, None if type="addrgroup"
items           *List[Address]* List of *Address* objects for address group (type="addrgroup")
platform        *str*           Platform: "ios" Cisco IOS, "nxos" Cisco Nexus NX-OS
prefix          *str*           Address prefix, "" if type="addrgroup"
subnet          *str*           Address subnet, "" if type="addrgroup"
wildcard        *str*           Address wildcard, "" if type="addrgroup"
=============== =============== ====================================================================


Methods
:::::::


copy()
......
**Address.copy()** - Copies the self object


data()
......
**Address.data()** - Converts *Address* object to *dict*


ipnets()
........
**Address.ipnets()** - All IPv4Networks, including address group and wildcard items


prefixes()
..........
**Address.prefixes()** - All prefixes, including address group and wildcard items


subnets()
.........
**Address.subnets()** - All subnets, including address group and wildcard items


subnet_of()
...........
**Address.subnet_of(other)** - Checks is any of self ipnet as subnet of any 'other' ipnet

=============== ============ =======================================================================
Parameter       Type         Description
=============== ============ =======================================================================
other           *Address*    Other address object to check with self address
=============== ============ =======================================================================

Return
	True - if address is subnet of `other` address


wildcards()
...........
**Address.wildcards()** - All wildcards, including address group and wildcard items


Functions
:::::::::


collapse()
..........
**address.collapse(addresses)** - Collapses a list of *Address* objects and
deletes subnets in the shadow

=============== ====================== =============================================================
Parameter       Type                   Description
=============== ====================== =============================================================
addresses       *Iterable[Address]*    Iterable *Address* objects
=============== ====================== =============================================================

Return
	List of collapsed *Address* objects


**Examples**

`./examples/examples_address.py`_



AddressAg
---------
AddressAg - Address of AddrGroup. A "group-object" item of "object-group network " command

=============== ============ =======================================================================
Parameter       Type         Description
=============== ============ =======================================================================
line            *str*        Address line
platform        *str*        Platform: "ios" (default), "nxos"
note            *Any*        Object description
items           *List[str]*  List of addresses for address group
=============== ============ =======================================================================

where line

=================== =========== ====================================================================
Line pattern        Platform    Description
=================== =========== ====================================================================
description         ios         Address group description
A.B.C.D A.B.C.D     ios         Network subnet and mask bits
host A.B.C.D        ios, nxos   A single host
group-object        ios         Nested address group name
A.B.C.D A.B.C.D     nxos        Network subnet and wildcard bits
A.B.C.D/LEN         nxos        Network prefix and length
=================== =========== ====================================================================


Attributes
::::::::::

=============== =================== ================================================================
Attributes      Type                Description
=============== =================== ================================================================
line            *str*               Address line
addrgroup       *str*               Nested object-group name
ipnet           *IpNetwork*         Address IPv4Network object
items           *List[AddressAg]*   List of *AddressAg* objects for address group
platform        *str*               Platform: "ios" (default), "nxos"
prefix          *str*               Address prefix
subnet          *str*               Address subnet
wildcard        *str*               Address wildcard
sequence        *int*               Sequence number, only for platform "nxos"
=============== =================== ================================================================


Methods
:::::::


copy()
......
**AddressAg.copy()** - Copies the self object


data()
......
**AddressAg.data()** - Converts *AddressAg* object to *dict*


ipnets()
........
**AddressAg.ipnets()** - All IPv4Networks, including address group and wildcard items


prefixes()
..........
**AddressAg.prefixes()** - All prefixes, including address group and wildcard items


subnet_of()
...........
**AddressAg.subnet_of(other)** - Checks is any of self ipnet as subnet of any 'other' ipnet

=============== ============ =======================================================================
Parameter       Type         Description
=============== ============ =======================================================================
other           *AddressAg*  Other address object to check with self address
=============== ============ =======================================================================

Return
	True - if address is subnet of `other` address


subnets()
.........
**AddressAg.subnets()** - All subnets, including address group and wildcard items


wildcards()
...........
**AddressAg.wildcards()** - All wildcards, including address group and wildcard items


Functions
:::::::::


collapse()
..........
**address_ag.collapse(addresses)** - Collapses a list of *AddressAg* objects and
deletes subnets in the shadow

=============== ====================== =============================================================
Parameter       Type                   Description
=============== ====================== =============================================================
addresses       *Iterable[AddressAg]*  Iterable *AddressAg* objects
=============== ====================== =============================================================

Return
	List of collapsed *AddressAg* objects


**Examples**

`./examples/examples_address_ag.py`_



AddrGroup
---------
AddrGroup - Group of *AddressAg* addresses configured in "object-group network" (ios) or
"object-group ip address" (nxos)

=============== ============ =======================================================================
Parameter       Type         Description
=============== ============ =======================================================================
line            *str*        Address group config line
platform        *str*        Platform: "ios" (default), "nxos"
note            *Any*        Object description
indent          *str*        Address lines indentation (default "  ")
name            *str*        Address group name (default from `line`)
items           *List[str]*  List of addresses in group
=============== ============ =======================================================================


Attributes
::::::::::

=============== =================== ================================================================
Attributes      Type                Description
=============== =================== ================================================================
line            *str*               Address group config line
indent          *str*               Address lines indentation (default  "  ")
items           *List[AddressAg]*   List of *AddressAg* objects
name            *str*               Address group name
platform        *str*               Platform: "ios" (default), "nxos"
=============== =================== ================================================================


Methods
:::::::


copy()
......
**AddrGroup.copy()** - Copies the self object


data()
......
**AddrGroup.data()** - Converts *AddrGroup* object to *dict*


ipnets()
........
**AddrGroup.ipnets()** - List of *IPv4Network* from all addresses in address group


prefixes()
..............
**AddrGroup.prefixes()** - Prefixes from all addresses in address group


resequence()
............
**AddrGroup.resequence()** - Changes sequence numbers for all addresses in address group

=============== =================== ================================================================
Attributes      Type                Description
=============== =================== ================================================================
start           *int*               Starting sequence number. start=0 - delete all sequence numbers
step            *int*               Step to increment the sequence number
items           *List[AddressAg]*   List of *AddressAg* objects (default self.items)
=============== =================== ================================================================

Return
	Last sequence number


subnets()
.........
**AddrGroup.subnets()** - Subnets from all addresses in address group


wildcards()
...........
**AddrGroup.wildcards()** - Wildcards from all addresses in address group



Port
----
Port - ACE TCP/UDP source or destination port object

=============== ============ =======================================================================
Parameter       Type         Description
=============== ============ =======================================================================
line            *str*        TCP/UDP ports line
platform        *str*        Platform: "ios" (default), "nxos"
protocol        *str*        ACL protocol: "tcp", "udp", ""
note            *Any*        Object description
port_nr         *bool*       Well-known TCP/UDP ports as numbers, True  - all tcp/udp ports as numbers, False - well-known tcp/udp ports as names (default)
=============== ============ =======================================================================

where line

=================== =========== ====================================================================
Line pattern        Platform    Description
=================== =========== ====================================================================
eq www 443          ios         equal list of protocols
eq www              nxos        equal protocol
eq www 443          ios         not equal list of protocols
neq www             nxos        not equal protocol
range 1 3           ios         range of protocols
=================== =========== ====================================================================


Attributes
::::::::::

=============== ============ =======================================================================
Attributes      Type         Description
=============== ============ =======================================================================
line            *str*        ACE source or destination TCP/UDP ports
operator        *str*        ACE TCP/UDP port operator: "eq", "gt", "lt", "neq", "range"
ports           *List[int]*  ACE list of *int* TCP/UDP port numbers
sport           *str*        ACE TCP/UDP ports range
items           *List[int]*  ACE port items (first and last digits in range)
=============== ============ =======================================================================


Methods
:::::::


copy()
......
**Port.copy()** - Copies the self object


data()
......
**Port.data()** - Converts *Port* object to *dict*



**Examples**

`./examples/examples_port.py`_



Protocol
--------
ACE IP protocol object

=============== ============ =======================================================================
Parameter       Type         Description
=============== ============ =======================================================================
line            *str*        IP protocol line
platform        *str*        Platform: "ios" (default), "nxos"
note            *Any*        Object description
protocol_nr     *bool*       Well-known ip protocols as numbers, True  - all ip protocols as numbers, False - well-known ip protocols as names (default)
has_port        *bool*       ACL has tcp/udp src/dst ports True  - ACE has tcp/udp src/dst ports, False - ACL does not have tcp/udp src/dst ports (default)
=============== ============ =======================================================================


Attributes
::::::::::

=============== ============ =======================================================================
Attributes      Type         Description
=============== ============ =======================================================================
line            *str*        ACE protocol name: "ip", "icmp", "tcp", etc.
name            *str*        ACE protocol name: "ip", "icmp", "tcp", etc.
number          *int*        ACE protocol number: 0..255, where 0="ip", 1="icmp", etc.
platform        *str*        Platform: "ios" Cisco IOS, "nxos" Cisco Nexus NX-OS
=============== ============ =======================================================================


Methods
:::::::


copy()
......
**Protocol.copy()** - Copies the self object


data()
......
**Protocol.data()** - Converts *Protocol* object to *dict*



**Examples**

`./examples/examples_protocol.py`_



.. _`.list_methods__acl.rst` : .list_methods__acl.rst
.. _`.list_methods__ace_group.rst`: .list_methods__ace_group.rst
.. _`./examples/examples_ace.py`: ./examples/examples_ace.py
.. _`./examples/examples_ace_group.py`: ./examples/examples_ace_group.py
.. _`./examples/examples_acl.py`: ./examples/examples_acl.py
.. _`./examples/examples_acl_objects.py`: ./examples/examples_acl_objects.py
.. _`./examples/examples_address.py`: ./examples/examples_address.py
.. _`./examples/examples_address_ag.py`: ./examples/examples_address_ag.py
.. _`./examples/examples_port.py`: ./examples/examples_port.py
.. _`./examples/examples_protocol.py`: ./examples/examples_protocol.py
.. _`./examples/examples_remark.py`: ./examples/examples_remark.py