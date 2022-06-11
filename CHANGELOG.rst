.. :changelog:

CHANGELOG
=========


0.1.1 (2022-06-12)
------------------
* [change] Pipfile packages versions
* [change] address.py Address.ipnet, type IPNetwork changed to IPv4Network
* [fix] __init__.py
* [fix] address.py Address._line__prefix()
* [fix] test__package.py
* [fix] sequence, *int* changed to *object*
* [fix] ace.py Ace.option *str*


0.1.0 (2022-04-26)
------------------
* [new] convert dict to object and vice versa
	acl = Acl(data=dict(...))
	data = acl.data
* [fix] setup.py package_data={PACKAGE: ["py.typed"]}


0.0.5 (2022-04-19)
------------------
* [new] cisco-acl
