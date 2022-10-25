"""Port - ACE TCP/UDP source or destination port object"""
from __future__ import annotations

from functools import total_ordering
from typing import List

from cisco_acl import helpers as h
from cisco_acl.base import Base
from cisco_acl.port_name import PortName
from cisco_acl.static import OPERATORS
from cisco_acl.types_ import LInt, LStr, IInt, DAny, StrInt


@total_ordering
class Port(Base):
    """Port - ACE TCP/UDP source or destination port object"""

    def __init__(self, line: str = "", **kwargs):
        """ACE. TCP/UDP Port
        :param line: TCP/UDP ports line
        :type line: str

        :param platform: Platform: "ios", "nxos" (default "ios")
        :type platform: str

        :param protocol: ACL protocol: "tcp", "udp", ""
        :type protocol: str

        Helpers
        :param note: Object description
        :type note: Any

        :param port_nr: Well-known TCP/UDP ports as numbers
            True  - all tcp/udp ports as numbers
            False - well-known tcp/udp ports as names (default)
        :type port_nr: bool

        :example: ios, "eq" (can match multiple ports in single line)
            port = Port("eq www 443", platform="ios", protocol="tcp")
            result:
                port.line == "eq www 443"
                port.operator == "eq"
                port.items == [80, 443]
                port.ports == [80, 443]
                port.sport == "80,443"

        :example: nxos, "neq" (can match only one port in single line)
            port = Port("neq www", platform="nxos", protocol="tcp")
            result:
                port.line == "neq www"
                port.operator == "neq"
                port.items == [80]
                port.ports == [1, 2, ..., 79, 81, ..., 65534, 65535]
                port.sport == "1-79,81-65535"

        :example: range
            port = Port("range 1 3", platform="ios", protocol="tcp")
            result:
                port.line == "range 1 3"
                port.operator == "range"
                port.ports == [1, 2, 3]
                port.sport == "1-3"
        """
        super().__init__(**kwargs)  # platform, note
        self._protocol = h.init_protocol(line=line, **kwargs)
        self._port_nr = bool(kwargs.get("port_nr") or False)
        self.line = line

    def __repr__(self):
        params = self._repr__params()
        params = self._repr__add_param("protocol", params)
        kwargs = ", ".join(params)
        name = self.__class__.__name__
        return f"{name}({kwargs})"

    # ========================== redefined ===========================

    def __hash__(self) -> int:
        return self.line.__hash__()

    def __eq__(self, other) -> bool:
        """== equality"""
        return self.__hash__() == other.__hash__()

    def __lt__(self, other) -> bool:
        """< less than"""
        if self.__class__ == other.__class__:
            if self._operator and other.operator:
                if self._operator != other.operator:
                    return self._operator < other.operator
                if self._items[0] != other.items[0]:
                    return self._items[0] < other.items[0]
                if self._items[-1] != other.items[-1]:
                    return self._items[-1] < other.items[-1]
        return False

    # =========================== property ===========================

    @property
    def items(self) -> LInt:
        """ACE TCP/UDP list of *int* protocol numbers
        :return: List of ports

        :example:
            self: Port("eq www 443")
            return: [80, 443]

        :example:
            self: Port("neq www")
            return: [80]
        """
        return self._items

    @items.setter
    def items(self, items: IInt) -> None:
        if not isinstance(items, (set, list, tuple)):
            raise TypeError(f"{items=} {list} expected")
        items_ = [str(i) for i in list(items)]
        items_.insert(0, self._operator)
        self.line = " ".join(items_)

    @property
    def line(self) -> str:
        """ACE source or destination TCP/UDP ports"""
        if not (self._operator and self._items and self._protocol in ["tcp", "udp"]):
            return ""
        if self._port_nr:
            items_s = " ".join([str(i) for i in self._items])
            return f"{self._operator} {items_s}"
        port_name = PortName(protocol=self._protocol, platform=self._platform)
        data = port_name.ports()
        items_s = " ".join([str(data.get(i) or i) for i in self._items])
        return f"{self._operator} {items_s}"

    @line.setter
    def line(self, line: str) -> None:
        line = h.init_line(line)
        items = line.split()
        if not items:
            self._operator = ""
            self._items = []
            self._ports = []
            self._sport = ""
            return

        self._operator = self._line__operator(items)
        items = items[1:]
        _items: LInt = self._line__items_to_ints(items)
        ports: LInt = self._items_to_ports(_items)
        self._items = _items
        self._ports = ports
        self._sport = h.ports_to_string(ports)

    @property
    def operator(self) -> str:
        """ACE TCP/UDP port operator: "eq", "gt", "lt", "neq", "range"

        :example:
            self: Port("eq www 443")
            return: "eq"
        """
        return self._operator

    @property
    def port_nr(self) -> bool:
        """Well-known TCP/UDP ports as numbers
            True  - all tcp/udp ports as numbers
            False - well-known tcp/udp ports as names (default)
        """
        return self._port_nr

    @port_nr.setter
    def port_nr(self, port_nr: bool) -> None:
        self._port_nr = bool(port_nr)

    @property
    def ports(self) -> LInt:
        """ACE list of *int* TCP/UDP port numbers

        :example:
            self: Port("eq www 443")
            return: [80, 443]

        :example:
            self: Port("neq www")
            return: [1, 2, ..., 79, 81, ..., 65534, 65535]
        """
        return self._ports

    @ports.setter
    def ports(self, ports: IInt) -> None:
        if not isinstance(ports, (set, list, tuple)):
            raise TypeError(f"{ports=} {list} expected")
        ports = list(ports)
        items_ = self._ports_to_items(ports)
        items = [str(i) for i in items_]
        items.insert(0, self.operator)
        self.line = " ".join(items)

    @property
    def protocol(self) -> str:
        """Protocol name: "tcp", "udp", "" """
        return self._protocol

    @protocol.setter
    def protocol(self, protocol: StrInt) -> None:
        if not isinstance(protocol, (int, str)):
            raise TypeError(f"{protocol=} {int} {str} expected")
        self._protocol = h.init_protocol(line=self.line, protocol=protocol)
        uuid = self.uuid
        self.line = self.line
        self.uuid = uuid

    @property
    def sport(self) -> str:
        """ACE *str* of TCP/UDP ports range

        :example:
            self: Port("eq 1 3 4 5")
            return: "1,3-5"
        """
        return self._sport

    @sport.setter
    def sport(self, sport: str) -> None:
        if not isinstance(sport, str):
            raise TypeError(f"{sport=} {str} expected")
        self.ports = h.string_to_ports(sport)

    # =========================== methods ============================

    def data(self, uuid: bool = False) -> DAny:
        """Converts *Port* object to *dict*
        :param uuid: Returns self.uuid in data
        :type uuid: bool

        :return: Port data

        :example:
            address = Address("10.0.0.0/24", platform="nxos")
            address.data() ->
                {"line": "10.0.0.0/24",
                "platform": "nxos",
                "items": [],
                "note": "",
                "addrgroup": "",
                "ipnet": IPv4Network("10.0.0.0/24"),
                "prefix": "10.0.0.0/24",
                "subnet": "10.0.0.0 255.255.255.0",
                "wildcard": "10.0.0.0 0.0.0.255"}
        """
        data = dict(
            # init
            line=self.line,
            platform=self._platform,
            note=self.note,
            protocol=self._protocol,
            port_nr=self._port_nr,
            # property
            items=self._items,
            operator=self._operator,
            ports=self._ports,
            sport=self._sport,
        )
        if uuid:
            data["uuid"] = self.uuid
        return data

    # =========================== helpers ============================

    @staticmethod
    def _line__operator(items: LStr) -> str:
        """Gets operator from items

        :example:
            items: ["eq", "www"]
            return: ["eq"]
        """
        operator, *items = items
        expected: LStr = list(OPERATORS)
        if operator not in expected:
            raise ValueError(f"invalid port {operator=}, {expected=}")
        return operator

    def _line__items_to_ints(self, items: LStr) -> LInt:
        """Converts named and digit items to int items

        :example:
            items: ["www", "443"]
            return: [80, 443]
        """
        if not items:
            raise ValueError(f"absent ports={items}")

        # convert to int
        ports: LInt = []  # result
        for item in items:
            if item.isdigit():
                ports.append(int(item))
                continue
            port_name = PortName(protocol=self._protocol, platform=self._platform)
            data = port_name.names()
            if port_nr := data.get(item):
                ports.append(port_nr)
                continue
            msg = f"invalid {item=}"
            if expected := sorted(data):
                msg = f"{msg}, {expected=}"
            raise ValueError(msg)

        # validation
        platform = self._platform
        operator = self._operator
        if operator in ["lt", "gt"] and len(ports) != 1:
            raise ValueError(f"invalid {operator=} with {ports=}")
        if operator == "range" and len(ports) != 2:
            raise ValueError(f"invalid {operator=} with {ports=} expected 2 ports")
        if self._operator in ["eq", "neq"]:
            if platform == "nxos" and len(ports) != 1:
                raise ValueError(f"invalid count of {ports=}, for {platform=} expected 1 port")

        return sorted(ports)

    def _items_to_ports(self, items: LInt) -> LInt:
        """Transforms line items to ports

        :example:
            items: [1, 4]
            self.operator: "range"
            return: [1, 2, 3, 4]

        :example:
            items: [4]
            self.operator: "ge"
            return: [4, 5, 6, ..., 65535]
        """
        operator = self._operator
        if operator == "eq":
            return items
        if operator == "range":
            items = list(range(items[0], items[-1] + 1))
            return items

        all_ports = list(range(1, 65535 + 1))
        if operator == "neq":
            items = [i for i in all_ports if i not in items]
            return items
        if operator == "gt":
            items = [i for i in all_ports if i > items[0]]
            return items
        if operator == "lt":
            items = [i for i in all_ports if i < items[0]]
            return items
        raise ValueError(f"invalid port {operator=}")

    def _ports_to_items(self, ports: LInt) -> LInt:
        """Transforms ports to line items

        :example:
            ports: [1, 2, 3, 4]
            self.operator: "range"
            return: [1, 4]

        :example:
            ports: [4, 5, 6, ..., 65535]
            self.operator: "ge"
            return: [4]
        """
        operator = self._operator
        if operator == "eq":
            return ports
        if operator == "range":
            return [ports[0], ports[-1]]
        if operator == "neq":
            items: LInt = list(range(1, 65535 + 1))
            for port in ports:
                items.remove(port)
            return items
        if operator == "gt":
            return [ports[0] - 1]
        if operator == "lt":
            return [ports[1] + 1]
        raise ValueError(f"invalid port {operator=}")


LPort = List[Port]
