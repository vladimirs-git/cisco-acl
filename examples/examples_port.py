from cisco_acl import Port

port = Port("eq www 443 444 445", platform="ios")
assert port.line == "eq www 443 444 445"
assert port.platform == "ios"
assert port.operator == "eq"
assert port.items == [80, 443, 444, 445]
assert port.ports == [80, 443, 444, 445]
assert port.sport == "80,443-445"

port = Port("range 1 5", platform="ios")
assert port.line == "range 1 5"
assert port.platform == "ios"
assert port.operator == "range"
assert port.items == [1, 5]
assert port.ports == [1, 2, 3, 4, 5]
assert port.sport == "1-5"
