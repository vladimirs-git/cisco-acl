cisco-acl
=========

Python package to parse and manage Cisco extended ACLs (Access Control Lists).

Supported platforms:

- Cisco IOS (extended ACL)
- Cisco Nexus NX-OS

Main features:

- Parses ACLs from Cisco config
- Generates ACEs sequence numbers
- Prints TCP/UDP ports as numbers or as well-known names
- Changes the IOS syntax to NX-OS syntax and vice vera
- Groups and sorts ACEs. The order of ACEs within a group does not change

.. contents::

.. sectnum::


Acronyms
--------

==========  ========================================================================================
Acronym     Definition
==========  ========================================================================================
ACL         Access Control List.
ACE         Access Control Entry.
ACEs        Multiple Access Control Entries.
Acl.items   List of objects: Ace, AceGroup, Remark.
==========  ========================================================================================


Installation
------------

Install the package from pypi.org release

.. code:: bash

    pip install cisco-acl

or install the package from github.com release

.. code:: bash

    pip install https://github.com/vladimirs-git/cisco-acl/archive/refs/tags/1.0.0.tar.gz

or install the package from github.com repository

.. code:: bash

    pip install git+https://github.com/vladimirs-git/cisco-acl


config_to_ace()
---------------
**config_to_ace(config, platform)**
Creates *Acl* objects based on the "show running-config" output.
*Acl* contains *Ace* items, where each ACE line is treated as an independent element

=============== ============ =======================================================================
Parameter       Type         Description
=============== ============ =======================================================================
config          *str*        Config file, output of "show running-config" command
platform        *str*        Platform: "ios", "nxos" (default "ios")
=============== ============ =======================================================================

Return
	*Acl* objects

Examples - config_to_ace()
::::::::::::::::::::::::::
`./examples/examples_config_to_ace.py`_

.. code:: python

	from cisco_acl import config_to_ace, Ace, AceGroup

	config = """
	hostname ROUTER_IOS
	ip access-list extended ACL_NAME
	  5 permit tcp host 10.0.0.1 10.0.0.0 0.0.0.255 eq 21 22 23
	  10 deny tcp any any eq 53
	  15 permit ip any any
	"""

	# Create ACL
	# Note, ACL represented with TCP/UDP ports as well-known names
	acls = config_to_ace(config=config)
	acl = acls[0]
	print(acl)
	print()
	# ip access-list extended ACL_NAME
	#   5 permit tcp host 10.0.0.1 10.0.0.0 0.0.0.255 eq ftp 22 telnet
	#   10 deny tcp any any eq domain
	#   15 permit ip any any

	# TCP/UDP ports represented numerically
	acl.numerically = True
	print(acl)
	print()
	# ip access-list extended ACL_NAME
	#   5 permit tcp host 10.0.0.1 10.0.0.0 0.0.0.255 eq 21 22 23
	#   10 deny tcp any any eq 53
	#   15 permit ip any any

	# Insert new ACEs to ACL
	# Note, ACEs has invalid sequence numbers
	ace = Ace("deny ip object-group A object-group B log")
	aceg = AceGroup("remark ICMP\npermit icmp any any")
	acl.items.extend([ace, aceg])
	ace.sequence = 1
	aceg.sequence = 7
	acl.items.sort(key=lambda o: o.sequence)
	print(acl)
	print()
	# ip access-list extended ACL_NAME
	#   1 deny ip object-group A object-group B log
	#   5 permit tcp host 10.0.0.1 10.0.0.0 0.0.0.255 eq 21 22 23
	#   remark ICMP
	#   permit icmp any any
	#   10 deny tcp any any eq 53
	#   15 permit ip any any

	# Delete sequence numbers
	acl.resequence(start=0)
	print(acl)
	print()
	# ip access-list extended ACL_NAME
	#   deny ip object-group A object-group B log
	#   permit tcp host 10.0.0.1 10.0.0.0 0.0.0.255 eq 21 22 23
	#   remark ICMP
	#   permit icmp any any
	#   deny tcp any any eq 53
	#   permit ip any any

	# Set sequence numbers
	acl.resequence(start=20, step=2)
	print(acl)
	print()
	# ip access-list extended ACL_NAME
	#   20 deny ip object-group A object-group B log
	#   22 permit tcp host 10.0.0.1 10.0.0.0 0.0.0.255 eq 21
	#   24 remark ICMP
	#   26 permit icmp any any
	#   28 deny tcp any any eq 53
	#   30 permit ip any any


	# Change syntax from IOS to NX-OS.
	acl.platform = "nxos"
	acl.resequence(start=20, step=2)
	print(acl)
	print()
	# ip access-list ACL_NAME
	#   20 deny ip addrgroup A addrgroup B log
	#   22 permit tcp 10.0.0.1/32 10.0.0.0/24 eq ftp
	#   24 permit tcp 10.0.0.1/32 10.0.0.0/24 eq 22
	#   26 permit tcp 10.0.0.1/32 10.0.0.0/24 eq telnet
	#   28 remark ICMP
	#   30 permit icmp any any
	#   32 deny tcp any any eq domain
	#   34 permit ip any any


config_to_aceg()
----------------
**config_to_aceg(config, platform)**
Creates *Acl* objects based on the "show running-config" output.
*Acl* contains *AceGroup* items, where ACE lines grouped by remarks

=============== ============ =======================================================================
Parameter       Type         Description
=============== ============ =======================================================================
config          *str*        Config file, output of "show running-config" command
platform        *str*        Platform: "ios", "nxos" (default "ios")
=============== ============ =======================================================================

Return
	*Acl* objects

Examples - config_to_aceg()
:::::::::::::::::::::::::::
`./examples/examples_config_to_aceg.py`_

.. code:: python

	from cisco_acl import config_to_aceg, AceGroup

	config = """
	hostname ROUTER_IOS
	ip access-list extended ACL_NAME
	  remark ========== ACE_NAME1 ==========
	  permit tcp host 10.0.0.1 10.0.0.0 0.0.0.255 eq 21 22 23
	  deny tcp any any eq 53
	  remark ========== ACE_NAME2 ==========
	  permit ip any any
	"""

	# Create ACL
	acls = config_to_aceg(config=config)
	acl = acls[0]
	print(acl)
	print()
	# ip access-list extended ACL_NAME
	#   remark ========== ACE_NAME1 ==========
	#   permit tcp host 10.0.0.1 10.0.0.0 0.0.0.255 eq ftp 22 telnet
	#   deny tcp any any eq domain
	#   remark ========== ACE_NAME2 ==========
	#   permit ip any any


	# Insert new AceGroup to ACL
	aceg = AceGroup("remark ========== ACE_NAME3 ==========\npermit icmp any any")
	acl.items.insert(1, aceg)
	acl.resequence(start=20, step=1)
	print(acl)
	print()
	# ip access-list extended ACL_NAME
	#   20 remark ========== ACE_NAME1 ==========
	#   21 permit tcp host 10.0.0.1 10.0.0.0 0.0.0.255 eq ftp 22 telnet
	#   22 deny tcp any any eq domain
	#   23 remark ========== ACE_NAME3 ==========
	#   24 permit icmp any any
	#   25 remark ========== ACE_NAME2 ==========
	#   26 permit ip any any

	# Move ACE_NAME3 to top
	aceg.sequence = 1
	acl.items.sort(key=lambda o: o.sequence)
	acl.resequence(start=20, step=1)
	print(acl)
	print()
	# ip access-list extended ACL_NAME
	#   20 remark ========== ACE_NAME3 ==========
	#   21 permit icmp any any
	#   22 remark ========== ACE_NAME1 ==========
	#   23 permit tcp host 10.0.0.1 10.0.0.0 0.0.0.255 eq ftp 22 telnet
	#   24 deny tcp any any eq domain
	#   25 remark ========== ACE_NAME2 ==========
	#   26 permit ip any any

	# Ordering by notes
	acl.items[0].note = "B"
	acl.items[1].note = "A"
	acl.items[2].note = "C"
	acl.items.sort(key=lambda o: o.note)
	print(acl)
	print()
	# ip access-list extended ACL_NAME
	#   22 remark ========== ACE_NAME1 ==========
	#   23 permit tcp host 10.0.0.1 10.0.0.0 0.0.0.255 eq ftp 22 telnet
	#   24 deny tcp any any eq domain
	#   20 remark ========== ACE_NAME3 ==========
	#   21 permit icmp any any
	#   25 remark ========== ACE_NAME2 ==========
	#   26 permit ip any any


Acl
---
ACL - Access Control List. A class that has methods for working with Acl.items: `Ace`_, `Remark`_, `AceGroup`_.
This class implements most of the Python list methods: append(), extend(), pop(), sort(), etc.
Acl.items can be edited, sorted, indexed by sequence numbers or notes.

=============== ============ =======================================================================
Parameter       Type         Description
=============== ============ =======================================================================
line            *str*        ACL config (name and following remarks and access entries)
platform        *str*        Platform: "ios", "nxos" (default "ios")
numerically     *bool*       Cisco ACL outputs well-known tcp/udp ports as names, True  - all tcp/udp ports as numbers, False - well-known tcp/udp ports as names (default)
name            *str*        ACL name. By default, parsed from line
items           *List[str]*  List of ACE (strings or Ace, AceGroup, Remark objects). By default, parsed from line
input           *str*        Interfaces, where Acl is used on input
output          *str*        Interfaces, where Acl is used on output
indent          *str*        ACE lines indentation. By default, 2 spaces
note            *str*        Object description. Not part of the ACL configuration, can be used for ACEs sorting
=============== ============ =======================================================================


Attributes
::::::::::

=============== ============ =======================================================================
Attributes      Type         Description
=============== ============ =======================================================================
indent          *str*        ACE lines indentation
input           *List[str]*  Interfaces where Acl is used on input
ip_acl_name     *str*        Acl name line, with "ip access-list" keyword in line
items           *List[Ace]*  List of ACE items: *Ace*, *Remark*, *AceGroup*
line            *str*        ACE lines joined to ACL line
name            *str*        Acl name, without "ip access-list" prefix
note            *str*        Object description
numerically     *bool*       Cisco ACL outputs well-known tcp/udp ports as names
output          *List[str]*  Interfaces where Acl is used on output
platform        *str*        Platform: "ios" Cisco IOS (extended ACL), "nxos" Cisco Nexus NX-OS
=============== ============ =======================================================================


Methods
:::::::

add()
.....
**Acl.add()** - Adds new item to self.items list, if it is not in self.items


append()
........
**Acl.append()** - Appends item to the end of the self.items list


clear()
.......
**Acl.clear()** - Removes all items from the self.items list


copy()
......
**Acl.copy()** - Copies the self object with the Ace elements copied


count(item)
...........
**Acl.count()** - Returns number of occurrences of the self.items


delete(item)
............
**Acl.delete(item)** - Removes item from the self.items list


extend(items)
.............
**Acl.extend(items)** - Extends the self.items list by appending items


index(item)
...........
**Acl.index(item)** - Returns first index of item. Raises ValueError if the value is not present


insert(index, item)
...................
**Acl.insert(index, item)** - Inserts item before index


pop(index)
..........
**Acl.pop(index)** - Removes and return item at index (default last) Raises IndexError if list is empty or index is out of range


remove(item)
............
**Acl.remove(item)** - Removes first occurrence of items in the self.items. Raises ValueError if the item is not present


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


reverse()
.........
**Acl.reverse()** - Reverses order of items in the self.items list


sort()
......
**Acl.sort()** - Sorts the self.items list in ascending order


update(items)
.............
**Acl.update(items)** - Extends list by adding items to self.items list, if it is not in the self.items


Examples - Acl
::::::::::::::
`./examples/examples_acl.py`_


**Acl(line=lines)**
The following example creates Acl with default parameters where data is parsed from the configuration lines.

.. code:: python

	from cisco_acl import Acl, Remark, Ace

	lines = """
	ip access-list extended ACL1
	  remark TEXT
	  permit icmp host 10.0.0.1 object-group NAME
	"""
	acl = Acl(line=lines)
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


**Acl(line="")**
The following example creates Acl with optional parameters, where data is taken from params.
Note, line is empty.

.. code:: python

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

**Acl.copy()**
The following example creates an Ace object `ace`.
Adds it to 2 Acl objects and then changes source address in the `ace`.
The print shows that in the `acl1` source address will be changed,
but in the copied `acl2` source address will remain unchanged.

.. code:: python

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


**Acl.resequence(start=10, step=10)**
The following example creates Acl with not ordered groups and sorts and resequences by notes.

.. code:: python

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


**Acl change platform**

- Create ACL
- Generate sequence numbers
- Moved up ACE "deny tcp any any eq 53"
- Resequence numbers
- Delete sequences
- Change syntax from Cisco IOS platform to Cisco Nexus NX-OS
- Change syntax from Cisco Nexus NX-OS platform to Cisco IOS

.. code:: python

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
	#   deny tcp any any eq domain

	# TCP/UDP ports represented numerically.
	acl1.numerically = True
	print(acl1.line)
	acl1.numerically = False
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
	#   40 deny tcp any any eq domain

	# Moved up ACE "deny tcp any any eq 53".
	# Note that the ACE have been moved up with the same sequence numbers.
	# Note, Ace class has list methods pop(), insert().
	rule1 = acl1.pop(3)
	acl1.insert(0, rule1)
	print(acl1)
	print()
	# ip access-list extended ACL1
	#   40 deny tcp any any eq domain
	#   10 permit icmp any any
	#   20 permit ip object-group A object-group B log
	#   30 permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4

	# Resequence numbers with custom start and step.
	acl1.resequence(start=100, step=1)
	print(acl1)
	print()
	# ip access-list extended ACL1
	#   100 deny tcp any any eq domain
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
	#   deny tcp any any eq domain
	#   permit icmp any any
	#   permit ip object-group A object-group B log
	#   permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4

	# Change syntax from Cisco IOS platform to Cisco Nexus NX-OS.
	acl1.platform = "nxos"
	print(f"{acl1.platform=}")
	print(acl1)
	print()
	# acl1.platform='nxos'
	# ip access-list ACL1
	#   deny tcp any any eq domain
	#   permit icmp any any
	#   permit ip addrgroup A addrgroup B log
	#   permit tcp 1.1.1.1/32 eq 1 2.2.2.0/24 eq 3
	#   permit tcp 1.1.1.1/32 eq 1 2.2.2.0/24 eq 4
	#   permit tcp 1.1.1.1/32 eq 2 2.2.2.0/24 eq 3
	#   permit tcp 1.1.1.1/32 eq 2 2.2.2.0/24 eq 4

	# Change syntax from Cisco Nexus NX-OS platform to Cisco IOS
	acl1.platform = "ios"
	print(f"{acl1.platform=}")
	print(acl1)
	print()
	# acl1.platform='ios'
	# ip access-list extended ACL1
	#   deny tcp any any eq domain
	#   permit icmp any any
	#   permit ip object-group A object-group B log
	#   permit tcp host 1.1.1.1 eq 1 2.2.2.0 0.0.0.255 eq 3
	#   permit tcp host 1.1.1.1 eq 1 2.2.2.0 0.0.0.255 eq 4
	#   permit tcp host 1.1.1.1 eq 2 2.2.2.0 0.0.0.255 eq 3
	#   permit tcp host 1.1.1.1 eq 2 2.2.2.0 0.0.0.255 eq 4




Ace
---
ACE - Access Control Entry. Each entry statement permit or deny in the `Acl`_.

=============== ============ =======================================================================
Parameter       Type         Description
=============== ============ =======================================================================
line            *str*        ACE config line
platform        *str*        Platform: "ios", "nxos" (default "ios")
numerically     *bool*       Cisco ACL outputs well-known tcp/udp ports as names, True  - all tcp/udp ports as numbers, False - well-known tcp/udp ports as names (default)
note            *str*        Object description. Not part of the ACE configuration, can be used for ACEs sorting
=============== ============ =======================================================================


Attributes
::::::::::

=============== ============ =======================================================================
Attributes      Type         Description
=============== ============ =======================================================================
action          *str*        ACE action: "permit", "deny"
dstaddr         *Address*    ACE destination Address object
dstport         *Port*       ACE destination Port object
line            *str*        ACE config line
note            *str*        Object description
numerically     *bool*       Cisco ACL outputs well-known tcp/udp ports as names
platform        *str*        Platform: "ios" Cisco IOS (extended ACL), "nxos" Cisco Nexus NX-OS
protocol        *Protocol*   ACE Protocol object
sequence        *Sequence*   Sequence object. ACE sequence number in ACL
srcaddr         *Address*    ACE source Address object
srcport         *Port*       ACE source Port object
=============== ============ =======================================================================


Methods
:::::::

copy()
......
**Ace.copy** - Copies the self object


rule(platform, action, srcaddrs, dstaddrs, protocols, tcp_srcports, tcp_dstports, udp_srcports, udp_dstports)
.............................................................................................................
**Ace.rule()** - Converts data of Rule to Ace objects

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
	List of Ace objects


Examples - Ace
::::::::::::::
`./examples/examples_ace.py`_


**Ace(line)**
The following example creates an Ace object and demonstrate various manipulation approaches.

.. code:: python

	from cisco_acl import Ace
	from ipaddress import ip_network

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
	assert ace.srcaddr.ipnet == ip_network("10.0.0.1/32")
	assert ace.srcaddr.prefix == "10.0.0.1/32"
	assert ace.srcaddr.subnet == "10.0.0.1 255.255.255.255"
	assert ace.srcaddr.wildcard == "10.0.0.1 0.0.0.0"
	assert ace.srcport.line == "range ftp telnet"
	assert ace.srcport.operator == "range"
	assert ace.srcport.ports == [21, 22, 23]
	assert ace.srcport.sport == "21-23"
	assert ace.dstaddr.line == "10.0.0.0 0.0.0.3"
	assert ace.dstaddr.addrgroup == ""
	assert ace.dstaddr.ipnet == ip_network("10.0.0.0/30")
	assert ace.dstaddr.prefix == "10.0.0.0/30"
	assert ace.dstaddr.subnet == "10.0.0.0 255.255.255.252"
	assert ace.dstaddr.wildcard == "10.0.0.0 0.0.0.3"
	assert ace.dstport.line == "eq www 443"
	assert ace.dstport.operator == "eq"
	assert ace.dstport.ports == [80, 443]
	assert ace.dstport.sport == "80,443"
	assert ace.option == "log"

	print(ace.line)
	# 10 permit tcp host 10.0.0.1 range ftp telnet 10.0.0.0 0.0.0.3 eq www 443 log
	ace.numerically = True
	print(ace.line)
	# 10 permit tcp host 10.0.0.1 range 21 23 10.0.0.0 0.0.0.3 eq 80 443 log

	ace.numerically = False
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
	print()
	# 10 permit tcp any any

	# copy
	ace1 = Ace("permit ip any any")
	ace2 = ace1.copy()
	ace1.srcaddr.prefix = "10.0.0.0/24"
	print(ace1)
	print(ace2)
	print()
	# permit ip 10.0.0.0 0.0.0.255 any
	# permit ip any any


**Ace.copy()**
The following example creates Ace object, copies them and changes prefix in `ace1`.
The print shows that in the `ace1` prefix will be changed,
but in the copied `ace2` prefix will remain unchanged.

.. code:: python

	from cisco_acl import Ace

	ace1 = Ace("permit ip any any")
	ace2 = ace1.copy()
	ace1.srcaddr.prefix = "10.0.0.0/24"
	print(ace1)
	print(ace2)
	print()
	# permit ip 10.0.0.0 0.0.0.255 any
	# permit ip any any


AceGroup
--------
AceGroup - Group of ACEs.
Useful for sorting ACL entries with frozen sections within which the sequence does not change.

=============== ============ =======================================================================
Parameter       Type         Description
=============== ============ =======================================================================
line            *str*        string of ACEs
platform        *str*        Platform: "ios", "nxos" (default "ios")
numerically     *bool*       Cisco ACL outputs well-known tcp/udp ports as names, True  - all tcp/udp ports as numbers, False - well-known tcp/udp ports as names (default)
note            *str*        Object description. Not part of the ACE configuration, can be used for ACEs sorting
items           *List[Ace]*  An alternate way to create *AceGroup* object from a list of *Ace* objects. By default, an object is created from a line
data            *dict*       An alternate way to create *AceGroup* object from a *dict*. By default, an object is created from a line
=============== ============ =======================================================================


Attributes
::::::::::

=============== ============ =======================================================================
Attributes      Type         Description
=============== ============ =======================================================================
items           *List[Ace]*  List of ACE items: *Ace*, *Remark*, *AceGroup*
line            *str*        ACE lines joined to ACL line
note            *str*        Object description
numerically     *bool*       Cisco ACL outputs well-known tcp/udp ports as names
platform        *str*        Platform: "ios" Cisco IOS (extended ACL), "nxos" Cisco Nexus NX-OS
sequence        *Sequence*   ACE sequence (sequence object of the first Ace in group)
=============== ============ =======================================================================


Methods
:::::::

add()
.....
**AceGroup.add()** - Adds new item to self.items list, if it is not in self.items


append()
........
**AceGroup.append()** - Appends item to the end of the self.items list


clear()
.......
**AceGroup.clear()** - Removes all items from the self.items list


copy()
......
**AceGroup.copy()** - Copies the self object with the Ace elements copied


count(item)
...........
**AceGroup.count()** - Returns number of occurrences of the self.items


data()
......
**AceGroup.data(()** - Converts self object to dictionary


delete(item)
............
**AceGroup.delete(item)** - Removes item from the self.items list


extend(items)
.............
**AceGroup.extend(items)** - Extends the self.items list by appending items


index(item)
...........
**AceGroup.index(item)** - Returns first index of item. Raises ValueError if the value is not present


insert(index, item)
...................
**AceGroup.insert(index, item)** - Inserts item before index


pop(index)
..........
**AceGroup.pop(index)** - Removes and return item at index (default last) Raises IndexError if list is empty or index is out of range


remove(item)
............
**AceGroup.remove(item)** - Removes first occurrence of items in the self.items. Raises ValueError if the item is not present


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


reverse()
.........
**AceGroup.reverse()** - Reverses order of items in the self.items list


sort()
......
**AceGroup.sort()** - Sorts the self.items list in ascending order


update(items)
.............
**AceGroup.update(items)** - Extends list by adding items to self.items list, if it is not in the self.items


Examples - AceGroup
:::::::::::::::::::
`./examples/examples_ace_group.py`_
`./examples/examples_acl_objects.py`_


**AceGroup(line)**
The following example creates AceGroup object.

.. code:: python

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


**AceGroup.copy()**
The following example creates AceGroup object, copies them and changes prefix in `aceg1`.
The print shows that in the `aceg1` prefix will be changed,
but in the copied `aceg2` prefix will remain unchanged.

.. code:: python

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


**AceGroup.data()**
The following example returns a data of objects in dict format.

.. code:: python

	from cisco_acl import AceGroup

	aceg = AceGroup("permit icmp any any\npermit ip any any")
	print(aceg.data())
	print()
	# {'platform': 'ios',
	#  'note': '',
	#  'sequence': 0,
	#  'items': ['permit icmp any any', 'permit ip any any']}


**AceGroup sequence numbers and sorting**

- Create ACL with groups
- Generate sequence numbers
- Sort rules by comment
- Resequence numbers

.. code:: python

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
	# permit tcp any any eq www

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
	#   permit udp any any eq domain
	#   permit tcp any any eq domain

	# Convert Acl object to AceGroup.
	group2 = AceGroup(str(acl2))
	print(str(group2))
	print()
	# remark ===== dns =====
	# permit udp any any eq domain
	# permit tcp any any eq domain

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
	#   permit tcp any any eq www
	#   remark ===== dns =====
	#   permit udp any any eq domain
	#   permit tcp any any eq domain

	# Generate sequence numbers.
	acl1.resequence()
	print(acl1.line)
	print()
	# ip access-list extended ACL1
	#   10 permit icmp any any
	#   20 permit ip object-group A object-group B log
	#   30 permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4
	#   40 remark ===== web =====
	#   50 permit tcp any any eq www
	#   60 remark ===== dns =====
	#   70 permit udp any any eq domain
	#   80 permit tcp any any eq domain

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
	# AceGroup('40 remark ===== web =====\n50 permit tcp any any eq www', note='web')
	# AceGroup('60 remark ===== dns =====\n
	#           70 permit udp any any eq domain\n
	#           80 permit tcp any any eq domain', note='dns')

	# Sorting rules by notes.
	# Note that ACE has been moved up with the same sequence numbers.
	acl1.sort(key=lambda o: o.note)
	print(acl1)
	print()
	# ip access-list extended ACL1
	#   60 remark ===== dns =====
	#   70 permit udp any any eq domain
	#   80 permit tcp any any eq domain
	#   30 permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4
	#   10 permit icmp any any
	#   20 permit ip object-group A object-group B log
	#   40 remark ===== web =====
	#   50 permit tcp any any eq www

	# Re-sequence numbers with custom start and step.
	acl1.resequence(start=100, step=1)
	print(acl1)
	print()
	# ip access-list extended ACL1
	#   100 remark ===== dns =====
	#   101 permit udp any any eq domain
	#   102 permit tcp any any eq domain
	#   103 permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 eq 3 4
	#   104 permit icmp any any
	#   105 permit ip object-group A object-group B log
	#   106 remark ===== web =====
	#   107 permit tcp any any eq www


**AceGroup.data()**
The following example creates ACL from objects, with groups


.. code:: python

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
	#   permit tcp any any eq www
	#   remark ===== dns =====
	#   permit udp any any eq domain
	#   permit tcp any any eq domain

	for item in acl1:
		print(repr(item))
	print()
	# Remark('remark text')
	# Ace('permit tcp host 1.1.1.1 eq 1 2 2.2.2.0 0.0.0.255 range 3 4')
	# Ace('deny ip any any')
	# AceGroup('remark ===== web =====\npermit tcp any any eq www')
	# AceGroup('remark ===== dns =====\npermit udp any any eq domain\npermit tcp any any eq domain')


Remark
------
Remark - comments ACE in ACL.

=============== ============ =======================================================================
Parameter       Type         Description
=============== ============ =======================================================================
line            *str*        string of ACEs
platform        *str*        Platform: "ios", "nxos" (default "ios")
note            *str*        Object description. Not part of the ACE configuration, can be used for ACEs sorting
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
**Remark.copy** - Copies the self object


Examples - Remark
:::::::::::::::::

**Remark(line)**
The following example creates Remark object.

.. code:: python

	from cisco_acl import Remark

	remark = Remark(line="10 remark text", note="description")

	assert remark.line == "10 remark text"
	assert remark.sequence == 10
	assert remark.action == "remark"
	assert remark.text == "text"
	assert remark.note == "description"


Address
-------
Address - Source or destination address object

=============== ============ =======================================================================
Parameter       Type         Description
=============== ============ =======================================================================
line            *str*        Address line
platform        *str*        Platform: "ios", "nxos" (default "ios")
note            *str*        Object description. Not part of the ACE configuration, can be used for ACEs sorting
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

=============== ============ =======================================================================
Attributes      Type         Description
=============== ============ =======================================================================
line            *str*        ACE source or destination address line
addrgroup       *str*        ACE address addrgroup
ipnet           *IpNetwork*  ACE address IPv4Network object
platform        *str*        Platform: "ios" Cisco IOS (extended ACL), "nxos" Cisco Nexus NX-OS
prefix          *str*        ACE address prefix
subnet          *str*        ACE address subnet
wildcard        *str*        ACE address wildcard
=============== ============ =======================================================================


Examples - Address
::::::::::::::::::
`./examples/examples_address.py`_


**Address(line)**
The following example demonstrates Address object.

.. code:: python

	from cisco_acl import Address
	from ipaddress import ip_network

	addr = Address("10.0.0.0 0.0.0.3", platform="ios")
	assert addr.line == "10.0.0.0 0.0.0.3"
	assert addr.platform == "ios"
	assert addr.addrgroup == ""
	assert addr.prefix == "10.0.0.0/30"
	assert addr.subnet == "10.0.0.0 255.255.255.252"
	assert addr.wildcard == "10.0.0.0 0.0.0.3"
	assert addr.ipnet == ip_network("10.0.0.0/30")

	# Change syntax from Cisco IOS platform to Cisco Nexus NX-OS.
	addr = Address("10.0.0.0 0.0.0.3", platform="ios")
	assert addr.line == "10.0.0.0 0.0.0.3"
	addr.platform = "nxos"
	assert addr.line == "10.0.0.0/30"

	addr = Address("host 10.0.0.1", platform="ios")
	assert addr.line == "host 10.0.0.1"
	addr.platform = "nxos"
	assert addr.line == "10.0.0.1/32"

	addr = Address("object-group NAME", platform="ios")
	assert addr.line == "object-group NAME"
	addr.platform = "nxos"
	assert addr.line == "addrgroup NAME"


Port
----
Port - Source or destination port object

=============== ============ =======================================================================
Parameter       Type         Description
=============== ============ =======================================================================
line            *str*        TCP/UDP ports line
platform        *str*        Platform: "ios", "nxos" (default "ios")
numerically     *bool*       Cisco ACL outputs well-known tcp/udp ports as names, True  - all tcp/udp ports as numbers, False - well-known tcp/udp ports as names (default)
note            *str*        Object description. Not part of the ACE configuration, can be used for ACEs sorting
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


Examples - Port
:::::::::::::::
`./examples/examples_port.py`_

**Port(line)**
The following example demonstrates Port object.

.. code:: python

	from cisco_acl import Port

	port = Port("eq 20 21 22 23", platform="ios", protocol="tcp", numerically=False)
	assert port.line == "eq ftp-data ftp 22 telnet"
	assert port.platform == "ios"
	assert port.operator == "eq"
	assert port.items == [20, 21, 22, 23]
	assert port.ports == [20, 21, 22, 23]
	assert port.sport == "20-23"
	print(port.line)
	# eq ftp-data ftp 22 telnet
	port.numerically = True
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


Protocol
--------
Protocol - IP protocol object

=============== ============ =======================================================================
Parameter       Type         Description
=============== ============ =======================================================================
line            *str*        IP protocol line
platform        *str*        Platform: "ios", "nxos" (default "ios")
note            *str*        Object description. Not part of the ACE configuration, can be used for ACEs sorting
=============== ============ =======================================================================


Attributes
::::::::::

=============== ============ =======================================================================
Attributes      Type         Description
=============== ============ =======================================================================
line            *str*        ACE protocol name: "ip", "icmp", "tcp", etc.
name            *str*        ACE protocol name: "ip", "icmp", "tcp", etc.
number          *int*        ACE protocol number: 0..255, where 0="ip", 1="icmp", etc.
platform        *str*        Platform: "ios" Cisco IOS (extended ACL), "nxos" Cisco Nexus NX-OS
=============== ============ =======================================================================


Examples - Protocol
:::::::::::::::::::
`./examples/examples_protocol.py`_

**Protocol(line)**
The following example demonstrates Protocol object.

.. code:: python

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


.. _`./examples/examples_ace.py`: ./examples/examples_ace.py
.. _`./examples/examples_ace_group.py`: ./examples/examples_ace_group.py
.. _`./examples/examples_acl.py`: ./examples/examples_acl.py
.. _`./examples/examples_acl_objects.py`: ./examples/examples_acl_objects.py
.. _`./examples/examples_address.py`: ./examples/examples_address.py
.. _`./examples/examples_config_to_ace.py` : ./examples/examples_config_to_ace.py
.. _`./examples/examples_config_to_aceg.py` : ./examples/examples_config_to_aceg.py
.. _`./examples/examples_port.py`: ./examples/examples_port.py
.. _`./examples/examples_protocol.py`: ./examples/examples_protocol.py