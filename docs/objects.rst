
cisco-acl Objects
=================

.. contents:: **Contents**
	:local:


Acl
---
ACL - Access Control List.
This class implements most of the Python list methods: append(), extend(), sort(), etc.

=============== ============ =======================================================================
Parameter       Type         Description
=============== ============ =======================================================================
line            *str*        ACL config, "show running-config" output
platform        *str*        Platform: "ios", "nxos" (default "ios")
input           *str*        Interfaces, where Acl is used on input
output          *str*        Interfaces, where Acl is used on output
note            *str*        Object description
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
note            *str*        Object description
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


delete_note()
.............
**Acl.delete_note(item)** - Deletes note in all children self.items: Ace, AceGroup, Remark


group()
.......
**Acl.group(group_by)** - Groups ACEs to *AceGroup* by `group_by` startswith in remarks


delete_shadowed()
.................
**Acl.remove_shadowed()** - Removes shadowed ACEs from ACL

Return
    *dict* Shadowing and shadowed ACEs



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


shadowed()
..........
**Acl.shadowed()** - Returns shadowed ACEs
NOTES:
- Method compare *Ace* with the same self.action and other.action. For example ACEs where self.action=="permit" and other.action=="deny" not taken into account (skip checking)
- Not supported: not contiguous wildcard (like "10.0.0.0 0.0.3.3")

Return
    *List[str]* shadowed ACEs


shadowing()
...........
**Acl.shadowing()** - Returns Shadowing and shadowed ACEs as *dict*,
where *key* is shadowing rule (in the top), *value* shadowed rules (in the bottom).
NOTES:
- Method compare *Ace* with the same self.action and other.action. For example ACEs where self.action=="permit" and other.action=="deny" not taken into account (skip checking)
- Not supported: not contiguous wildcard (like "10.0.0.0 0.0.3.3")

Return
    *dict* Shadowing and shadowed ACEs


ungroup_ports()
...............
**Acl.ungroup_ports()** - Ungroups ACEs with multiple ports in single line ("eq" or "neq")
to multiple lines with single port


ungroup()
.............
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
line            *str*        ACE config, "show running-config" output
platform        *str*        Platform: "ios", "nxos" (default "ios")
note            *str*        Object description
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
line            *str*        ACE config line
note            *str*        Object description
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


is_shadowed_by()
................
**Ace.is_shadowed_by(other)** - Checks is ACE shadowed by other ACE.
NOTES:
- Method compare *Ace* with the same self.action and other.action. For example ACEs where self.action=="permit" and other.action=="deny" not taken into account (skip checking)
- Not supported: not contiguous wildcard (like "10.0.0.0 0.0.3.3")

=============== ============ =======================================================================
Parameter       Type         Description
=============== ============ =======================================================================
other           *Ace*        Other *Ace* object
=============== ============ =======================================================================

Return
	True - self *Ace* is shadowed by other *Ace*

Raises
	ValueError if one of addresses is not contiguous wildcard


rule()
......
**Ace.rule(platform, action, srcaddrs, dstaddrs, protocols, tcp_srcports, tcp_dstports, udp_srcports, udp_dstports)**
- Converts data of Rule to Ace objects

=============== ============ =======================================================================
Parameter       Type         Description
=============== ============ =======================================================================
platform        *str*        Platform: "ios", "nxos" (default "ios")
action          *str*        ACE action: "permit", "deny"
srcaddrs        *List[str]*  Source addresses
dstaddrs        *List[str]*  Destination addresses
protocols       *List[str]*  Protocols
tcp_srcports    *List[str]*  TCP source ports
tcp_dstports    *List[str]*  TCP destination ports
udp_srcports    *List[str]*  UDP source ports
udp_dstports    *List[str]*  UDP destination ports
=============== ============ =======================================================================

Return
	List of *Ace* objects


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
the AceGroup behaves like a ACE item and order of ACE items inside AceGroup is not changed.
AceGroup is useful for freezing ACEs section, to hold "deny" after certain "permit".

=============== ============ =======================================================================
Parameter       Type         Description
=============== ============ =======================================================================
line            *str*        string of ACEs
platform        *str*        Platform: "ios", "nxos" (default "ios")
note            *str*        Object description
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
note            *str*        Object description
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
platform        *str*        Platform: "ios", "nxos" (default "ios")
note            *str*        Object description
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
line            *str*        Address line
platform        *str*        Platform: "ios", "nxos" (default "ios")
note            *str*        Object description
items           *List[str]*  List of *Address* objects for "object-group" (ios) or "addrgroup" (nxos), that are configured under "object-group network" (ios) or "object-group ip address" (nxos)
=============== ============ =======================================================================

where line

=================== =========== ====================================================================
Line pattern        Platform    Description
=================== =========== ====================================================================
A.B.C.D A.B.C.D                 Address and wildcard bits
A.B.C.D/LEN         nxos        Network prefix
any                             Any host
host A.B.C.D        ios         A single host
object-group NAME   ios         Network object group
addrgroup NAME      nxos        Network object group
=================== =========== ====================================================================


Attributes
::::::::::

=============== =============== ====================================================================
Attributes      Type            Description
=============== =============== ====================================================================
line            *str*           ACE source or destination address line
addrgroup       *str*           ACE address addrgroup
ipnet           *IpNetwork*     ACE address IPv4Network object
items           List[Address]   List of *Address* objects for "object-group" (ios) or "addrgroup" (nxos), that are configured under "object-group network" (ios) or "object-group ip address" (nxos)
platform        *str*           Platform: "ios" Cisco IOS, "nxos" Cisco Nexus NX-OS
prefix          *str*           ACE address prefix
subnet          *str*           ACE address subnet
wildcard        *str*           ACE address wildcard
=============== =============== ====================================================================


Methods
:::::::


copy()
......
**Address.copy()** - Copies the self object


data()
......
**Address.data()** - Converts *Address* object to *dict*



**Examples**

`./examples/examples_address.py`_



AddressAg
---------
AddressAg - Address of AddrGroup. A "group-object" item of "object-group network " command

=============== ============ =======================================================================
Parameter       Type         Description
=============== ============ =======================================================================
line            *str*        Address line
platform        *str*        Platform: "ios", "nxos" (default "ios")
note            *str*        Object description
items           *List[str]*  List of *AddressAg* objects for lines, that are configured under "object-group network" (ios) or "object-group ip address" (nxos)
=============== ============ =======================================================================

where line

=================== =========== ====================================================================
Line pattern        Platform    Description
=================== =========== ====================================================================
description         ios         Address-group description
A.B.C.D A.B.C.D     ios         Network subnet and mask bits
host A.B.C.D        ios, nxos   A single host
group-object        ios         Nested address-group name
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
items           List[AddressAg]     List of *AddressAg* objects for lines, that are configured under "object-group network" (ios) or "object-group ip address" (nxos)
platform        *str*               Platform: "ios", "nxos" (default "ios")
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



Port
----
Port - ACE TCP/UDP source or destination port object

=============== ============ =======================================================================
Parameter       Type         Description
=============== ============ =======================================================================
line            *str*        TCP/UDP ports line
platform        *str*        Platform: "ios", "nxos" (default "ios")
protocol        *str*        ACL protocol: "tcp", "udp", ""
note            *str*        Object description
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
platform        *str*        Platform: "ios", "nxos" (default "ios")
note            *str*        Object description
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
.. _`./examples/examples_port.py`: ./examples/examples_port.py
.. _`./examples/examples_protocol.py`: ./examples/examples_protocol.py
.. _`./examples/examples_remark.py`: ./examples/examples_remark.py