# cisco-acl
Python package to parse and manage Cisco ACL (Access Control List).
Supported platforms: IOS, NX-OS.

Main features:
- Parse ACL from Cisco config file
- Grouping and sorting ACE (Access Control Entry)
- Generate ACL config commands (ready for ssh console)


## Installation
To install by pip
```bash
pip install cisco-acl
```

## Objects/methods documentation
todo


## Examples
[examples/examples_acl.py](examples/examples_acl.py) 
- Create flat ACL.
- Generate sequences for ACEs.
- Move one ACE.
- Resequence ACEs.

[examples/examples_acl.py](examples/examples_acl_objects.py) 
- Create ACL from strings.
- Create ACL from objects.
- Create ACL with groups (rules). 
- Generate sequences for ACEs.
- Move group and resequence ACEs.
