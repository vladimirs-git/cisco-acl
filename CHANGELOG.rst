
.. :changelog:

CHANGELOG
=========

2.0.2 (2022-10-10)
------------------
* [fix] README.rst
* [fix] Address("10.0.0.1/30") with invalid mask,
	WARNING:root:ValueError: 10.0.0.1/30 has host bits set, fixed to prefix 10.0.0.0/30

2.0.1 (2022-10-06)
------------------
* [fix] Ace.is_shadowed_by() for addrgroup


2.0.0 (2022-10-06)
------------------
* [change] AceGroup.resequence()
* [change] ConfigParser._make_ace_group()
* [change] config_to_ace(), config_to_aceg() merged to config_to_acl()
* [change] property Acl.ip_acl_name > method Acl.ip_acl_name()
* [delete] deleter
* [new] Ace.is_shadowed_by()
* [new] Ace.option: Option
* [new] AceGroup.name
* [new] Acl.delete_notes()
* [new] Acl.shadowed()
* [new] Acl.shadowed()
* [new] Acl.split_ports()
* [new] Acl.type = "extended", "standard"
* [new] Acl.ungroup()
* [new] AddrGroup.__contains__()
* [new] AddrGroup.resequence()
* [new] Address.cmd_addgr()
* [new] Address.sequence
* [new] AddressAg
* [new] ConfigParser._init_platform()
* [new] functions.py parse_address_group(), parse_ace(), parse_acl()
* [new] h.init_platform()
* [new] in Address, AddressGr, AddrGroup methods: ipnets(), subnets(), prefixes(), wildcards()


1.2.2 (2022-09-08)
------------------
* [new] platform="cnx"


1.2.1 (2022-07-30)
------------------
* [new] Ace.range()
* [fix] protocol_nr in Ace.copy() Acl.copy()
* [fix] README.rst protocol_nr


1.2.0 (2022-07-30)
------------------
* [delete] Ace.numerically
* [delete] Acl.numerically
* [delete] Protocol._line, Protocol._name
* [new] Ace.numerically_protocol, Ace.numerically_port
* [new] Acl.numerically_protocol, Ace.numerically_port
* [new] Protocol.numerically


1.1.0 (2022-07-17)
------------------
* [new] cisco_acl.config_to_ace() cisco_acl.config_to_aceg()
* [delete] Interface


1.0.0 (2022-07-16)
------------------
* [new] numerically: Cisco ACL outputs some tcp/udp ports as numbers
* [change] "cnx" to "nxos"


0.1.1 (2022-06-13)
------------------
* [change] Pipfile packages versions
* [change] README.md to README.rst
* [change] address.py Address.ipnet, type IPNetwork changed to IPv4Network
* [fix] __init__.py
* [fix] ace.py Ace.option *str*
* [fix] address.py Address._line__prefix()
* [fix] sequence, *int* changed to *object*
* [fix] test__package.py
* [new] unittest examples


0.1.0 (2022-04-26)
------------------
* [new] convert dict to object and vice versa
	acl = Acl(data=dict(...))
	data = acl.data
* [fix] setup.py package_data={PACKAGE: ["py.typed"]}


0.0.5 (2022-04-19)
------------------
* [new] cisco-acl
