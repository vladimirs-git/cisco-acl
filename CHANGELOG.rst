
.. :changelog:

CHANGELOG
=========

3.0.2 (2022-11-01)
------------------
* [fix] py.typed


3.0.1 (2022-10-31)
------------------
* [rename] AceBase, AddressBase
* [fix] AddressBase._is_address_prefix()


3.0.0 (2022-10-30)
------------------
* [new] kwargs for cisco_acl.acls() cisco_acl.aces() cisco_acl.addrgroups()
* [change] Address "nxos" + "0.0.0.0/0" = "any"
* [change] Address "nxos" + "0.0.0.0/32" = "host 0.0.0.0"
* [fix] AceGroup._line_to_oace(), known_skip = ["statistics ", "description ", "ignore "]


2.1.0 (2022-10-25)
------------------
* [change] Ace.data(uuid=True)
* [fix] Ace.shadow_of() performance improvement
* [fix] Acl.delete_shadow()
* [fix] Address.platform = "nxos", lost addrgroup items
* [fix] uuid the same after platform change
* [new] Address.subnet_of() AddressAg.subnet_of()
* [new] address.collapse() address_ag.collapse()
* [new] skip: "addrgroup", "nc_wildcard" in Ace.is_shadow_by(skip) Acl.shading()


2.0.3 (2022-10-11)
------------------
* [fix] disabled 100 chars check_line_length() for init_line()


2.0.2 (2022-10-10)
------------------
* [fix] README.rst
* [fix] Address("10.0.0.1/30") with invalid mask,
	WARNING:root:ValueError: 10.0.0.1/30 has host bits set, fixed to prefix 10.0.0.0/30

2.0.1 (2022-10-06)
------------------
* [fix] Ace.is_shadow_by() for addrgroup


2.0.0 (2022-10-06)
------------------
* [change] AceGroup.resequence()
* [change] ConfigParser._make_ace_group()
* [change] config_to_ace(), config_to_aceg() merged to config_to_acl()
* [change] property Acl.ip_acl_name > method Acl.ip_acl_name()
* [delete] deleter
* [new] Ace.is_shadow_by()
* [new] Ace.option: Option
* [new] AceGroup.name
* [new] Acl.delete_notes()
* [new] Acl.shadow()
* [new] Acl.shadow()
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
