cisco-acl
=========

Python package to parse and manage Cisco ACLs (Access Control Lists).

Supported platforms:

- Cisco IOS
- Cisco Nexus NX-OS

Main features:

- Changes the IOS syntax to NX-OS syntax and vice vera
- Represents TCP/UDP ports and IP protocols as numbers or as well-known names
- Represents addresses in multiple formats: subnet, wildcard, prefix, IPv4Network
- Add and remove sequence numbers
- Support address group objects
- Search and remove shadowed ACEs (rules without hits)
- Groups ACEs to blocks. After sorting, the order of ACEs within a group does not change

.. contents:: **Contents**
	:local:



Acronyms
--------

==========  ========================================================================================
Acronym     Definition
==========  ========================================================================================
ACL         Access Control List
ACE         Access Control Entry
ACEs        Multiple Access Control Entries
Acl.items   List of objects: Ace, AceGroup, Remark
==========  ========================================================================================



Installation
------------

Install the package from pypi.org release

.. code:: bash

    pip install cisco-acl

or install the package from github.com repository

.. code:: bash

    pip install git+https://github.com/vladimirs-git/cisco-acl

or install the package from github.com release

.. code:: bash

    pip install https://github.com/vladimirs-git/cisco-acl/archive/refs/tags/2.0.1.tar.gz



acls()
------
**cisco_acl.acls(config, platform, group_by)**
Creates *Acl* objects based on the "show running-config" output.
Support address-group objects.
Each ACE line is treated as an independent *Ace* element (default) or ACE lines can be
grouped to *AceGroup* by text in remarks (param `group_by`)

=============== ============ =======================================================================
Parameter       Type         Description
=============== ============ =======================================================================
config          *str*        Cisco config, "show running-config" output
platform        *str*        Platform: "ios", "nxos" (default "ios")
group_by        *str*        Startswith in remark line. ACEs group, starting from the Remark, where line startswith `group_by`, will be applied to the same AceGroup, until next Remark that also startswith `group_by`
=============== ============ =======================================================================

Return
    List of *Acl* objects

**Examples**

`./examples/examples_acls.py`_


.. code:: python

	from pprint import pprint
	import cisco_acl

	config = """
	hostname HOSTNAME

	ip access-list extended ACL_NAME
	  permit tcp 10.0.0.0 0.0.0.255 any eq 21 22 23
	  permit tcp host 10.0.0.1 any eq 21
	  deny tcp object-group ADDR_GROUP any eq 53
	  permit icmp any any

	object-group network ADDR_GROUP
	 10.1.1.0 255.255.255.252
	 host 10.1.1.4

	interface Ethernet1
	  ip access-group ACL_NAME in
	  ip access-group ACL_NAME out
	"""

.. code:: python

	# Create ACL, TCP/UDP ports and IP protocols as well-known names
	acls = cisco_acl.acls(config=config, platform="ios")
	acl = acls[0]
	print(acl.line, "\n")
	# ip access-list extended ACL_NAME
	#   permit tcp 10.0.0.0 0.0.0.255 any eq ftp 22 telnet
	#   permit tcp host 10.0.0.1 any eq ftp
	#   deny tcp object-group ADDR_GROUP any eq domain
	#   permit icmp any any

.. code:: python

	# Convert well-known TCP/UDP ports and IP protocols to numbers
	# Note, ftp -> 21, telnet -> 23, icmp -> 1
	acl.protocol_nr = True
	acl.port_nr = True
	print(acl.line, "\n")
	# ip access-list extended ACL_NAME
	#   permit tcp 10.0.0.0 0.0.0.255 any eq 21 22 23
	#   permit tcp host 10.0.0.1 any eq 21
	#   deny tcp object-group ADDR_GROUP any eq 53
	#   permit 1 any any

.. code:: python

	# *Acl* some attributes demonstration
	# Note, "object-group ADDR_GROUP" includes addresses from "object-group network ADDR_GROUP"
	print(f"{acl.line=}")
	print(f"{acl.platform=}")
	print(f"{acl.type=}")
	print(f"{acl.indent=}")
	print(f"{acl.input=}")
	print(f"{acl.output=}")
	print(f"{acl.items=}")
	print()
	# acl.line='ip access-list extended ACL_NAME\n  permit tcp 10.0.0.0 0.0.0.255 any ...
	# acl.platform='ios'
	# acl.type='extended'
	# acl.indent='  '
	# acl.input=['interface Ethernet1']
	# acl.output=['interface Ethernet1']
	# acl.items=[Ace('permit tcp 10.0.0.0 0.0.0.255 any eq ftp 22 telnet'), Ace('perm ...

.. code:: python

	# Convert well-known TCP/UDP ports and IP protocols to numbers
	acl.protocol_nr = True
	acl.port_nr = True
	print(acl.line, "\n")
	# ip access-list extended ACL_NAME
	#   permit tcp 10.0.0.0 0.0.0.255 any eq 21 22 23
	#   permit tcp host 10.0.0.1 any eq 21
	#   deny tcp object-group ADDR_GROUP any eq 53
	#   permit 1 any any

.. code:: python

	# Add sequence numbers
	acl.resequence(start=5, step=5)
	print(acl.line, "\n")
	# ip access-list extended ACL_NAME
	#   5 permit tcp 10.0.0.0 0.0.0.255 any eq 21 22 23
	#   10 permit tcp host 10.0.0.1 any eq 21
	#   15 deny tcp object-group ADDR_GROUP any eq 53
	#   20 permit 1 any any

.. code:: python

	# Delete sequence numbers
	acl.resequence(start=0)
	print(acl.line, "\n")
	# ip access-list extended ACL_NAME
	#   permit tcp 10.0.0.0 0.0.0.255 any eq 21 22 23
	#   permit tcp host 10.0.0.1 any eq 21
	#   deny tcp object-group ADDR_GROUP any eq 53
	#   permit 1 any any

.. code:: python

	# Change syntax from IOS to NX-OS
	# Note, "extended" removed from output, range of ports split to multiple lines
	acl.platform = "nxos"
	print(acl.line, "\n")
	# ip access-list ACL_NAME
	#   permit tcp 10.0.0.0 0.0.0.255 any eq 21
	#   permit tcp 10.0.0.0 0.0.0.255 any eq 22
	#   permit tcp 10.0.0.0 0.0.0.255 any eq 23
	#   permit tcp host 10.0.0.1 any eq 21
	#   deny tcp addrgroup ADDR_GROUP any eq 53
	#   permit 1 any any

.. code:: python

	# Get shadowed ACEs (in the bottom, without hits)
	shadowed = acl.shadowed()
	print(shadowed, "\n")
	# ['permit tcp host 10.0.0.1 any eq 21']

.. code:: python

	# Get shadowing ACEs (in the top)
	shadowing = acl.shadowing()
	print(shadowing, "\n")
	# {'permit tcp 10.0.0.0 0.0.0.255 any eq 21': ['permit tcp host 10.0.0.1 any eq 21']}

.. code:: python

	# Delete shadowed ACEs (from the bottom)
	shadowing = acl.delete_shadowed()
	print(shadowing)
	print(acl.line, "\n")
	# {'permit tcp 10.0.0.0/24 any eq 21': ['permit tcp 10.0.0.1/32 any eq 21']}
	# ip access-list ACL_NAME
	#   permit tcp 10.0.0.0/24 any eq 21
	#   permit tcp 10.0.0.0/24 any eq 22
	#   permit tcp 10.0.0.0/24 any eq 23
	#   deny tcp addrgroup ADDR_GROUP any eq 53
	#   permit 1 any any

.. code:: python

	# Convert object to dictionary
	data = acl.data()
	pprint(data)
	print()
	# 'line': 'ip access-list ACL_NAME\n'
	#          '  permit tcp 10.0.0.0 0.0.0.255 any eq 21\n'
	#          '  permit tcp 10.0.0.0 0.0.0.255 any eq 22\n'
	#          '  permit tcp 10.0.0.0 0.0.0.255 any eq 23\n'
	#          '  permit tcp host 10.0.0.1 any eq 21\n'
	#          '  deny tcp addrgroup ADDR_GROUP any eq 53\n'
	#          '  permit 1 any any',
	#  'name': 'ACL_NAME',
	#  'input': ['interface Ethernet1'],
	#  'output': ['interface Ethernet1'],
	# 'items': [{'action': 'permit',
	#             'dstaddr': {'addrgroup': '',
	#                         'ipnet': IPv4Network('0.0.0.0/0'),
	#                         'line': 'any',
	#                         'prefix': '0.0.0.0/0',
	#                         'subnet': '0.0.0.0 0.0.0.0',
	#                         'type': 'any',
	#                         'wildcard': '0.0.0.0 255.255.255.255'},
	# ...

.. code:: python

	# Crate *Acl* object based on *dict* data
	acl = cisco_acl.Acl(**data)
	print(acl.line, "\n")
	# ip access-list ACL_NAME
	#   permit tcp 10.0.0.0/24 any eq 21
	#   permit tcp 10.0.0.0/24 any eq 22
	#   permit tcp 10.0.0.0/24 any eq 23
	#   permit tcp 10.0.0.1/32 any eq 21
	#   deny tcp addrgroup ADDR_GROUP any eq 53
	#   permit 1 any any

.. code:: python

	# Copy *Acl* object
	acl2 = acl.copy()
	print(acl2.line, "\n")
	# ip access-list ACL_NAME
	#   permit tcp 10.0.0.0/24 any eq 21
	#   permit tcp 10.0.0.0/24 any eq 22
	#   permit tcp 10.0.0.0/24 any eq 23
	#   deny tcp addrgroup ADDR_GROUP any eq 53
	#   permit 1 any any

.. code:: python

	# Update some data in *Ace* objects
	# Note, when iterating *acl2* object, you are iterating list of *Ace* objects in *acl2.items*
	acl2.items = [o for o in acl2 if o.srcaddr.line == "10.0.0.0/24"]
	for port, ace in enumerate(acl2, start=53):
	    ace.protocol.line = "udp"
	    ace.dstport.line = f"eq {port}"
	acl2.items[1].srcaddr.line = "10.0.1.0/24"
	acl2.items[2].srcaddr.line = "10.0.2.0/24"
	print(acl2.line, "\n")
	# ip access-list ACL_NAME
	#   permit udp 10.0.0.0/24 any eq 53
	#   permit udp 10.0.1.0/24 any eq 54
	#   permit udp 10.0.2.0/24 any eq 55

.. code:: python

	# Convert from NX-OS extended ACL syntax to IOS standard ACL syntax
	acl2.protocol_nr = False
	acl2.platform = "ios"
	acl2.type = "standard"
	print(acl2.line, "\n")
	# ip access-list standard ACL_NAME
	#   permit 10.0.0.0 0.0.0.255
	#   permit 10.0.1.0 0.0.0.255
	#   permit 10.0.2.0 0.0.0.255



aces()
------
**cisco_acl.aces(config, platform, group_by)**
Creates *Ace* objects based on the "show running-config" output

=============== ============ =======================================================================
Parameter       Type         Description
=============== ============ =======================================================================
config          *str*        Cisco config, "show running-config" output
platform        *str*        Platform: "ios", "nxos" (default "ios")
group_by        *str*        Startswith in remark line. ACEs group, starting from the Remark, where line startswith `group_by`, will be applied to the same AceGroup, until next Remark that also startswith `group_by`
=============== ============ =======================================================================

Return
    List of *Ace* objects

**Examples**

`./examples/examples_aces.py`_


.. code:: python

	from pprint import pprint
	import cisco_acl

	config = """
	permit tcp 10.0.0.0 0.0.0.255 range 1 4 any eq 21 22 23 syn ack log
	permit tcp host 10.0.0.1 any eq 21
	deny tcp object-group ADDR_GROUP any eq 53
	permit icmp any any
	"""


.. code:: python

	# Create list of ACEs
	aces = cisco_acl.aces(config=config, platform="ios")
	for ace in aces:
	    print(f"{ace.line=}")
	print()
	# ace.line='permit tcp 10.0.0.0 0.0.0.255 range 1 4 any eq ftp 22 telnet syn ack log'
	# ace.line='permit tcp host 10.0.0.1 any eq ftp'
	# ace.line='deny tcp object-group ADDR_GROUP any eq domain'
	# ace.line='permit icmp any any'

.. code:: python

	# *Ace* some attributes demonstration
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
	# ace.line='permit tcp 10.0.0.0 0.0.0.255 range 1 4 any eq ftp 22 telnet syn ack log'
	# ace.platform='ios'
	# ace.type='extended'
	# ace.sequence=0
	# ace.action='permit'
	# ace.protocol.name='tcp'
	# ace.protocol.number=6
	#
	# ace.srcaddr.line='10.0.0.0 0.0.0.255'
	# ace.srcaddr.addrgroup=''
	# ace.srcaddr.ipnet=IPv4Network('10.0.0.0/24')
	# ace.srcaddr.prefix='10.0.0.0/24'
	# ace.srcaddr.subnet='10.0.0.0 255.255.255.0'
	# ace.srcaddr.wildcard='10.0.0.0 0.0.0.255'
	#
	# ace.srcport.line='range 1 4'
	# ace.srcport.protocol='tcp'
	# ace.srcport.items=[1, 4]
	# ace.srcport.operator='range'
	# ace.srcport.ports=[1, 2, 3, 4]
	# ace.srcport.sport='1-4'
	#
	# ace.dstaddr.line='any'
	# ace.dstaddr.addrgroup=''
	# ace.dstaddr.ipnet=IPv4Network('0.0.0.0/0')
	# ace.dstaddr.prefix='0.0.0.0/0'
	# ace.dstaddr.subnet='0.0.0.0 0.0.0.0'
	# ace.dstaddr.wildcard='0.0.0.0 255.255.255.255'
	#
	# ace.dstport.line='eq ftp 22 telnet'
	# ace.dstport.protocol='tcp'
	# ace.dstport.items=[21, 22, 23]
	# ace.dstport.operator='eq'
	# ace.dstport.ports=[21, 22, 23]
	# ace.dstport.sport='21-23'
	#
	# ace.option.line='syn ack log'
	# ace.option.flags=['syn', 'ack']
	# ace.option.logs=['log']

.. code:: python

	# Convert object to dictionary
	data = ace.data()
	pprint(data)
	print()
	# {'line': 'permit tcp 10.0.0.0 0.0.0.255 range 1 4 any eq ftp 22 telnet syn ack log'
	#  'platform': 'ios',
	#  'action': 'permit',
	#  'srcaddr': {'addrgroup': '',
	#              'ipnet': IPv4Network('10.0.0.0/24'),
	#              'line': '10.0.0.0 0.0.0.255',
	#              'prefix': '10.0.0.0/24',
	#              'subnet': '10.0.0.0 255.255.255.0',
	#              'type': 'wildcard',
	#              'wildcard': '10.0.0.0 0.0.0.255'},
	#  'srcport': {'items': [1, 4],
	#              'line': 'range 1 4',
	#              'operator': 'range',
	#              'ports': [1, 2, 3, 4],
	#              'protocol': 'tcp',
	#              'sport': '1-4'},
	# ...

.. code:: python

	# Copy *Ace* object
	ace2 = ace.copy()
	print(f"{ace2.line=}", "\n")
	# ace2.line='permit tcp 10.0.0.0 0.0.0.255 range 1 4 any eq ftp 22 telnet syn ack log'



addrgroups()
------------
**cisco_acl.addrgroups(config, platform)**
Creates *AddrGroup* objects based on the "show running-config" output

=============== ============ =======================================================================
Parameter       Type         Description
=============== ============ =======================================================================
config          *str*        Cisco config, "show running-config" output
platform        *str*        Platform: "ios", "nxos" (default "ios")
=============== ============ =======================================================================

Return
    List of *AddrGroup* objects



range_ports()
-------------
**cisco_acl.range_ports(srcports, dstports, line, platform, port_nr)**
Generates ACEs in required range of TCP/UDP source/destination ports

=============== ============ =======================================================================
Parameter       Type         Description
=============== ============ =======================================================================
srcports        *str*        Range of TCP/UDP source ports
dstports        *str*        Range of TCP/UDP destination ports
line            *str*        ACE pattern, on whose basis new ACEs will be generated (default "permit tcp any any", operator "eq")
platform        *str*        Platform: "ios", "nxos" (default "ios")
port_nr         *bool*       Well-known TCP/UDP ports as numbers, True  - all tcp/udp ports as numbers, False - well-known tcp/udp ports as names (default)
=============== ============ =======================================================================

Return
    List of Newly generated ACE lines

**Examples**

`./examples/examples_range_ports.py`_


.. code:: python

	from pprint import pprint
	import cisco_acl

	# Generate range of source TCP ports
	aces = cisco_acl.range_ports(srcports="21-23,80")
	pprint(aces)
	print()
	# ['permit tcp any eq ftp any',
	#  'permit tcp any eq 22 any',
	#  'permit tcp any eq telnet any',
	#  'permit tcp any eq www any']

.. code:: python

	# Generate range of destination TCP ports
	aces = cisco_acl.range_ports(dstports="21-23,80")
	pprint(aces)
	print()
	# ['permit tcp any any eq ftp',
	#  'permit tcp any any eq 22',
	#  'permit tcp any any eq telnet',
	#  'permit tcp any any eq www']

.. code:: python

	# Generate range where well-known TCP ports represented as numbers
	aces = cisco_acl.range_ports(dstports="21-23,80", port_nr=True)
	pprint(aces)
	print()
	# ['permit tcp any any eq 21',
	#  'permit tcp any any eq 22',
	#  'permit tcp any any eq 23',
	#  'permit tcp any any eq 80']

.. code:: python

	# Generate range of UDP ports based on the template with specified address
	aces = cisco_acl.range_ports(dstports="53,67-68,123", line="deny udp host 10.0.0.1 any eq 1")
	pprint(aces)
	print()
	# ['deny udp host 10.0.0.1 any eq domain',
	#  'deny udp host 10.0.0.1 any eq bootps',
	#  'deny udp host 10.0.0.1 any eq bootpc',
	#  'deny udp host 10.0.0.1 any eq ntp']



range_protocols()
-----------------
**cisco_acl.range_protocols(protocols, line, platform, protocol_nr)**
Generates ACEs in required range of IP protocols

=============== ============ =======================================================================
Parameter       Type         Description
=============== ============ =======================================================================
protocols       *str*        Range of IP protocols
line            *str*        ACE pattern, on whose basis new ACEs will be generated (default "permit ip any any")
platform        *str*        Platform: "ios", "nxos" (default "ios")
protocol_nr     *bool*       Well-known ip protocols as numbers, True  - all ip protocols as numbers, False - well-known ip protocols as names (default)
=============== ============ =======================================================================

Return
    List of Newly generated ACE lines

**Examples**

`./examples/examples_range_protocols.py`_


.. code:: python

	from pprint import pprint
	import cisco_acl

	# Generate range of IP protocols
	aces = cisco_acl.range_protocols(protocols="1-3,6,17")
	pprint(aces)
	print()
	# ['permit icmp any any',
	#  'permit igmp any any',
	#  'permit 3 any any',
	#  'permit tcp any any',
	#  'permit udp any any']

.. code:: python

	# Generate range where well-known IP protocols represented as numbers
	aces = cisco_acl.range_protocols(protocols="1-3,6,17", protocol_nr=True)
	pprint(aces)
	print()
	# ['permit 1 any any',
	#  'permit 2 any any',
	#  'permit 3 any any',
	#  'permit 6 any any',
	#  'permit 17 any any']



Objects
-------
Additional documentation for deep divers

`./docs/objects.rst`_





.. _`./examples/examples_acls.py` : ./examples/examples_acls.py
.. _`./examples/examples_aces.py` : ./examples/examples_aces.py
.. _`./examples/examples_addrgroups.py` : ./examples/examples_addrgroups.py
.. _`./examples/examples_range_protocols.py` : ./examples/examples_range_protocols.py
.. _`./examples/examples_range_ports.py` : ./examples/examples_range_ports.py

.. _`./docs/acl_list_methods.rst` : ./docs/acl_list_methods.rst
.. _`./docs/objects.rst` : ./docs/objects.rst
