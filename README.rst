
.. image:: https://img.shields.io/pypi/v/cisco-acl.svg
   :target: https://pypi.python.org/pypi/cisco-acl
.. image:: https://img.shields.io/pypi/pyversions/cisco-acl.svg
   :target: https://pypi.python.org/pypi/cisco-acl


cisco-acl
=========

Python package to parse and manage Cisco ACL (Access Control List).

Supported platforms:

- Cisco IOS
- Cisco Nexus NX-OS

Main features:

- Supports wildcards, converts wildcards to prefixes
- Supports address groups
- Represents TCP/UDP ports and IP protocols as numbers or well-known names
- Converts IOS syntax to NX-OS and vice vera
- Generates sequence numbers for ACEs
- Looks for and removes ACEs in the shadow (rules without hits)
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
==========  ========================================================================================


Requirements
------------

Python >=3.8


Installation
------------

Install the package from pypi.org release

.. code:: bash

    pip install cisco-acl

or install the package from github.com release

.. code:: bash

    pip install https://github.com/vladimirs-git/cisco-acl/archive/refs/tags/3.0.2.tar.gz

or install the package from github.com repository

.. code:: bash

    pip install git+https://github.com/vladimirs-git/cisco-acl


acls()
------
**cisco_acl.acls(config, kwargs)**
Creates *Acl* objects based on the "show running-config" output.
Support address group objects.
Each ACE line is treated as an independent *Ace* (default) or ACE lines can be
grouped to *AceGroup* by text in remarks (param `group_by`)

=============== ============ =======================================================================
Parameter       Type         Description
=============== ============ =======================================================================
config          *str*        Cisco config, "show running-config" output
platform        *str*        Platform: "ios" (default), "nxos"
names           *List[str]*  Parses only ACLs with specified names, skips any other
max_ncwb        *int*        Max count of non-contiguous wildcard bits
indent          *str*        ACE lines indentation (default "  ")
protocol_nr     *bool*       Well-known ip protocols as numbers, True  - all ip protocols as numbers, False - well-known ip protocols as names (default)
port_nr         *bool*       Well-known TCP/UDP ports as numbers, True  - all tcp/udp ports as numbers, False - well-known tcp/udp ports as names (default)
group_by        *str*        Startswith in remark line. ACEs group, starting from the Remark, where line startswith `group_by`, will be applied to the same AceGroup, until next Remark that also startswith `group_by`
=============== ============ =======================================================================

Return
    List of *Acl* objects

**Examples**

`./examples/functions_acls.py`_


aces()
------
**cisco_acl.aces(config, kwargs)**
Creates *Ace* objects based on the "show running-config" output

=============== ============ =======================================================================
Parameter       Type         Description
=============== ============ =======================================================================
config          *str*        Cisco config, "show running-config" output
platform        *str*        Platform: "ios" (default), "nxos"
max_ncwb        *int*        Max count of non-contiguous wildcard bits
protocol_nr     *bool*       Well-known ip protocols as numbers, True  - all ip protocols as numbers, False - well-known ip protocols as names (default)
port_nr         *bool*       Well-known TCP/UDP ports as numbers, True  - all tcp/udp ports as numbers, False - well-known tcp/udp ports as names (default)
group_by        *str*        Startswith in remark line. ACEs group, starting from the Remark, where line startswith `group_by`, will be applied to the same AceGroup, until next Remark that also startswith `group_by`
=============== ============ =======================================================================

Return
    List of *Ace* objects

**Examples**

`./examples/functions_aces.py`_


addrgroups()
------------
**cisco_acl.addrgroups(config, kwargs)**
Creates *AddrGroup* objects based on the "show running-config" output

=============== ============ =======================================================================
Parameter       Type         Description
=============== ============ =======================================================================
config          *str*        Cisco config, "show running-config" output
platform        *str*        Platform: "ios" (default), "nxos"
max_ncwb        *int*        Max count of non-contiguous wildcard bits
indent          *str*        ACE lines indentation (default "  ")
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
platform        *str*        Platform: "ios" (default), "nxos"
port_nr         *bool*       Well-known TCP/UDP ports as numbers, True  - all tcp/udp ports as numbers, False - well-known tcp/udp ports as names (default)
=============== ============ =======================================================================

Return
    List of newly generated ACE lines

**Examples**

`./examples/functions_range_ports.py`_


range_protocols()
-----------------
**cisco_acl.range_protocols(protocols, line, platform, protocol_nr)**
Generates ACEs in required range of IP protocols

=============== ============ =======================================================================
Parameter       Type         Description
=============== ============ =======================================================================
protocols       *str*        Range of IP protocols
line            *str*        ACE pattern, on whose basis new ACEs will be generated (default "permit ip any any")
platform        *str*        Platform: "ios" (default), "nxos"
protocol_nr     *bool*       Well-known ip protocols as numbers, True  - all ip protocols as numbers, False - well-known ip protocols as names (default)
=============== ============ =======================================================================

Return
    List of newly generated ACE lines

**Examples**

`./examples/functions_range_protocols.py`_



Objects
-------
Documentation of objects for deep-code divers

`./docs/objects.rst`_



.. _`./examples/functions_acls.py` : ./examples/functions_acls.py
.. _`./examples/functions_aces.py` : ./examples/functions_aces.py
.. _`./examples/examples_addrgroups.py` : ./examples/examples_addrgroups.py
.. _`./examples/functions_range_protocols.py` : ./examples/functions_range_protocols.py
.. _`./examples/functions_range_ports.py` : ./examples/functions_range_ports.py

.. _`./docs/acl_list_methods.rst` : ./docs/acl_list_methods.rst
.. _`./docs/objects.rst` : ./docs/objects.rst
