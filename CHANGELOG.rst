.. :changelog:

CHANGELOG
=========

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
