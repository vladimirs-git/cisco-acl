"""ACE. TCP/UDP Port"""

from functools import total_ordering
from typing import List

from cisco_acl import helpers as h
from cisco_acl.base import Base
from cisco_acl.port_name import PortName
from cisco_acl.static import OPERATORS
from cisco_acl.types_ import LInt, LStr, IInt


@total_ordering
class Port(Base):
    """ACE. TCP/UDP Port"""

    __slots__ = ("_platform", "_note", "_line",
                 "_port_nr", "protocol", "_items", "_operator", "_ports", "_sport")

    def __init__(self, line: str = "", **kwargs):
        """ACE. TCP/UDP Port
        :param str line: TCP/UDP ports line
        :param str platform: Platform: "ios", "nxos" (default "ios")
        :param protocol: ACL protocol: "tcp", "udp"
        :param bool port_nr: Well-known TCP/UDP ports as numbers
            True  - all tcp/udp ports as numbers
            False - well-known tcp/udp ports as names (default)
        :param str note: Object description. Not part of the ACE configuration,
            can be used for ACEs sorting

        :example: ios, "eq" (can match multiple ports in single line)
            line: "eq www 443"
            platform: "ios"
            result:
                self.line = "eq www 443"
                self.operator = "eq"
                self.items = [80, 443]
                self.ports = [80, 443]
                self.sport = "80,443"

        :example: nxos, "neq" (can match only one port in single line)
            line: "neq www"
            platform: "nxos"
            result:
                self.line = "neq www"
                self.operator = "neq"
                self.items = [80]
                self.ports = [1, 2, ..., 79, 81, ..., 65534, 65535]
                self.sport = "1-79,81-65535"

        :example: range
            line: "range 1 3"
            platform: "ios"
            result:
                self.line = "range 1 3"
                self.operator = "range"
                self.ports = [1, 2, 3]
                self.sport = "1-3"
        """
        super().__init__(**kwargs)
        self.protocol = self._init_protocol(**kwargs)
        self._port_nr = bool(kwargs.get("port_nr"))
        self.line = line

    # ========================== redefined ===========================

    def __hash__(self) -> int:
        return self.line.__hash__()

    def __eq__(self, other) -> bool:
        """== equality"""
        return self.__hash__() == other.__hash__()

    def __lt__(self, other) -> bool:
        """< less than"""
        if self.__class__ == other.__class__:
            if self.operator and other.operator:
                if self.operator != other.operator:
                    return self.operator < other.operator
                if self.items[0] != other.items[0]:
                    return self.items[0] < other.items[0]
                if self.items[-1] != other.items[-1]:
                    return self.items[-1] < other.items[-1]
        return False

    # ============================= init =============================

    @staticmethod
    def _init_protocol(**kwargs) -> str:
        """Init protocol, converts tcp, udp numbers to names"""
        protocol = str(kwargs.get("protocol") or "")
        expected = ["tcp", "udp", ""]
        if protocol in expected:
            return protocol
        if protocol == "6":
            return "tcp"
        if protocol == "17":
            return "udp"
        return ""

    # =========================== property ===========================

    @property
    def line(self) -> str:
        """ACE source or destination TCP/UDP ports"""
        if not (self.operator and self._items and self.protocol in ["tcp", "udp"]):
            return ""
        if self.port_nr:
            items_s = " ".join([str(i) for i in self._items])
            return f"{self._operator} {items_s}"
        port_name = PortName(protocol=self.protocol, platform=self.platform)
        data = port_name.ports()
        items_s = " ".join([str(data.get(i) or i) for i in self._items])
        return f"{self._operator} {items_s}"

    @line.setter
    def line(self, line: str) -> None:
        line = self._init_line(line)
        items = line.split()
        if not items:
            self._delete_port()
            return
        self._operator = self._line__operator(items)
        items = items[1:]
        items_: LInt = self._line__items_to_ints(items)
        ports: LInt = self._items_to_ports(items_)
        self._items = items_
        self._ports = ports
        self._sport = h.ports_to_string(ports)

    @line.deleter
    def line(self) -> None:
        self._delete_port()

    @property
    def items(self) -> LInt:
        """ACE TCP/UDP list of *int* protocol numbers
        :return: List of ports

        :example:
            Port("eq www 443")
            return: [80, 443]

        :example:
            Port("neq www")
            return: [80]
        """
        return self._items

    @items.setter
    def items(self, items: IInt) -> None:
        items_ = [str(i) for i in list(items)]
        items_.insert(0, self.operator)
        self.line = " ".join(items_)

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
    def operator(self) -> str:
        """ACE TCP/UDP port operator: "eq", "gt", "lt", "neq", "range"

        :example:
            Port("eq www 443")
            return: "eq"
        """
        return self._operator

    @operator.setter
    def operator(self, operator: str) -> None:
        if not (self.operator and self._items and self.protocol in ["tcp", "udp"]):
            line = self.line
            raise ValueError(f"invalid {operator=} for {line=}")
        if operator != self.operator and "range" in [operator, self.operator]:
            expected = [s for s in OPERATORS if s != "range"]
            raise ValueError(f"invalid {operator=}, {expected=}")
        items = self.line.split()
        items[0] = operator
        self.line = " ".join(items)

    @operator.deleter
    def operator(self) -> None:
        self._delete_port()

    @property
    def ports(self) -> LInt:
        """ACE list of *int* TCP/UDP port numbers

        :example:
            Port("eq www 443")
            return: [80, 443]

        :example:
            Port("neq www")
            return: [1, 2, ..., 79, 81, ..., 65534, 65535]
        """
        return self._ports

    @ports.setter
    def ports(self, ports: IInt) -> None:
        ports = list(ports)
        items_ = self._ports_to_items(ports)
        items = [str(i) for i in items_]
        items.insert(0, self.operator)
        self.line = " ".join(items)

    @property
    def sport(self) -> str:
        """ACE *str* of TCP/UDP ports range

        :example:
            Port("eq 1 3 4 5")
            return: "1,3-5"
        """
        return self._sport

    @sport.setter
    def sport(self, sport: str) -> None:
        ports: LInt = h.string_to_ports(sport)
        self.ports = ports

    # =========================== helpers ============================

    def _delete_port(self) -> None:
        """Clears port data"""
        self._operator = ""
        self._items = []
        self._ports = []
        self._sport = ""

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
        ports: LInt = []  # return
        for item in items:
            if item.isdigit():
                ports.append(int(item))
                continue
            port_name = PortName(protocol=self.protocol, platform=self.platform)
            data = port_name.names()
            if port_nr := data.get(item):
                ports.append(port_nr)
                continue
            msg = f"invalid {item=}"
            if expected := sorted(data):
                msg = f"{msg}, {expected=}"
            raise ValueError(msg)

        # validation
        platform = self.platform
        operator = self.operator
        if operator in ["lt", "gt"] and len(ports) != 1:
            raise ValueError(f"invalid {operator=} with {ports=}")
        if operator == "range" and len(ports) != 2:
            raise ValueError(f"invalid {operator=} with {ports=} expected 2 ports")
        if self.operator in ["eq", "neq"]:
            if platform == "nxos" and len(ports) != 1:
                raise ValueError(f"invalid count of {ports=}, for {platform=} expected 1 port")

        return sorted(ports)

    def _items_to_ports(self, items: LInt) -> LInt:
        """Transforms line items to ports

        :example:
            items: [1, 4]
            self.operator="range"
            return: [1, 2, 3, 4]

        :example:
            items: [4]
            self.operator="ge"
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
            self.operator="range"
            return: [1, 4]

        :example:
            ports: [4, 5, 6, ..., 65535]
            self.operator="ge"
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
