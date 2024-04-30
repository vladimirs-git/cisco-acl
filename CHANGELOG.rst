
.. :changelog:

CHANGELOG
=========

Unreleased
----------

**Add:**  IOS Remark without sequence number

**Add:**  Recursive AddrGroup in other AddrGroup items


3.3.2 (2024-04-30)
------------------
**Added:** SwVersion, different tcp/udp well-known ports names.

**Added:** range_ports(port_range, port_count)


3.2.4 (2024-04-01)
------------------
**Fixed:** Acl.group() transform LINE_DUPLICATE_REMARKS_UNGROUPED to LINE_DUPLICATE_REMARKS_GROUPED


3.2.3 (2024-02-01)
------------------
**Fixed:** ip access-list standard, permit A.B.C.D (without host keyword)


3.2.1 (2023-12-05)
------------------
**Fixed:** netports = "^0.12.1"


3.2.0 (2023-12-04)
------------------
**Changed:** poetry


3.1.0 (2023-11-22)
------------------
**Added:** asa


3.0.4 (2022-11-02)
------------------
**Added:** Acl.tcam_count()


3.0.3 (2022-11-01)
------------------
**Changed:** netports==0.6.1


3.0.2 (2022-11-01)
------------------
**Fixed:** py.typed


3.0.1 (2022-10-31)
------------------
**Removed:** AceBase, AddressBase

**Fixed:** AddressBase._is_address_prefix()


3.0.0 (2022-10-30)
------------------
**Added:** kwargs for cisco_acl.acls() cisco_acl.aces() cisco_acl.addrgroups()

**Changed:** Address "nxos" + "0.0.0.0/0" = "any"

**Changed:** Address "nxos" + "0.0.0.0/32" = "host 0.0.0.0"

**Fixed:** AceGroup._line_to_oace(), known_skip = ["statistics ", "description ", "ignore"]


2.1.0 (2022-10-25)
------------------
**Changed:** Ace.data(uuid=True)

**Fixed:** Ace.shadow_of() performance improvement

**Fixed:** Acl.delete_shadow()

**Fixed:** Address.platform = "nxos", lost addrgroup items

**Fixed:** uuid the same after platform change

**Added:** Address.subnet_of() AddressAg.subnet_of()

**Added:** address.collapse() address_ag.collapse()

**Added:** skip: "addrgroup", "nc_wildcard" in Ace.is_shadow_by(skip) Acl.shading()


2.0.3 (2022-10-11)
------------------
**Fixed:** disabled 100 chars check_line_length() for init_line()


2.0.2 (2022-10-10)
------------------
**Fixed:** README.rst

**Fixed:** Address("10.0.0.1/30") with invalid mask,
WARNING:root:ValueError: 10.0.0.1/30 has host bits set, fixed to prefix 10.0.0.0/30

2.0.1 (2022-10-06)
------------------
**Fixed:** Ace.is_shadow_by() for addrgroup


2.0.0 (2022-10-06)
------------------
**Changed:** AceGroup.resequence()

**Changed:** ConfigParser._make_ace_group()

**Changed:** config_to_ace(), config_to_aceg() merged to config_to_acl()

**Changed:** property Acl.ip_acl_name > method Acl.ip_acl_name()

**Removed:** deleter

**Added:** Ace.is_shadow_by()

**Added:** Ace.option: Option

**Added:** AceGroup.name

**Added:** Acl.delete_notes()

**Added:** Acl.shadow()

**Added:** Acl.shadow()

**Added:** Acl.split_ports()

**Added:** Acl.type = "extended", "standard"

**Added:** Acl.ungroup()

**Added:** AddrGroup.__contains__()

**Added:** AddrGroup.resequence()

**Added:** Address.cmd_addgr()

**Added:** Address.sequence

**Added:** AddressAg

**Added:** ConfigParser._init_platform()

**Added:** functions.py parse_address_group(), parse_ace(), parse_acl()

**Added:** h.init_platform()

**Added:** in Address, AddressGr, AddrGroup methods: ipnets(), subnets(), prefixes(), wildcards()


1.2.2 (2022-09-08)
------------------
**Added:** platform="cnx"


1.2.1 (2022-07-30)
------------------
**Added:** Ace.range()

**Fixed:** protocol_nr in Ace.copy() Acl.copy()

**Fixed:** README.rst protocol_nr


1.2.0 (2022-07-30)
------------------
**Removed:** Ace.numerically

**Removed:** Acl.numerically

**Removed:** Protocol._line, Protocol._name

**Added:** Ace.numerically_protocol, Ace.numerically_port

**Added:** Acl.numerically_protocol, Ace.numerically_port

**Added:** Protocol.numerically


1.1.0 (2022-07-17)
------------------
**Added:** cisco_acl.config_to_ace() cisco_acl.config_to_aceg()

**Removed:** Interface


1.0.0 (2022-07-16)
------------------
**Added:** numerically: Cisco ACL outputs some tcp/udp ports as numbers

**Changed:** "cnx" to "nxos"


0.1.1 (2022-06-13)
------------------
**Changed:** Pipfile packages versions

**Changed:** README.md to README.rst

**Changed:** address.py Address.ipnet, type IPNetwork changed to IPv4Network

**Fixed:** __init__.py

**Fixed:** ace.py Ace.option *str*

**Fixed:** address.py Address._line__prefix()

**Fixed:** sequence, *int* changed to *object*

**Fixed:** test__package.py

**Added:** unittest examples


0.1.0 (2022-04-26)
------------------
**Added:** convert dict to object and vice versa
	acl = Acl(data=dict(...))
	data = acl.data

**Fixed:** setup.py package_data={PACKAGE: ["py.typed"]}


0.0.5 (2022-04-19)
------------------
**Added:** cisco-acl
