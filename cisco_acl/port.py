"""ACE. TCP/UDP Port."""

from typing import List

from cisco_acl import helpers as h
from cisco_acl.base import Base
from cisco_acl.static import OPERATORS, PORTS
from cisco_acl.types_ import LInt, LStr, IInt


class Port(Base):
    """ACE. TCP/UDP Port."""

    __slots__ = ("_platform", "_note", "_line", "_items", "_operator", "_ports", "_sport")

    def __init__(self, line: str = "", **kwargs):
        """ACE. TCP/UDP Port.
        :param line: TCP/UDP ports line.
        :param kwargs: Params.
            platform: Supported platforms: "ios", "cnx". By default: "ios".
            note: Object description (used only in object).

        Example1: ios, "eq" (can match multiple ports in single line)
            line: "eq www 443"
            platform: "ios"
                self.line = "eq www 443"
                self.operator = "eq"
                self.items = [80, 443]
                self.ports = [80, 443]
                self.sport = "80,443"

        Example2: cnx, "neq" (can match only one port in single line)
        line: "neq www"
        platform: "cnx"
            self.line = "neq www"
            self.operator = "neq"
            self.items = [80]
            self.ports = [1, 2, ..., 79, 81, ..., 65534, 65535]
            self.sport = "1-79,81-65535"

        Example3: range
        line: "range 1 3"
        platform: "ios"
            self.line = "range 1 3"
            self.operator = "range"
            self.ports = [1, 2, 3]
            self.sport = "1-3"
        """
        super().__init__(**kwargs)
        self.line = line

    # =========================== property ===========================

    @property
    def line(self) -> str:
        """ACE TCP/UDP ports."""
        return self._line

    @line.setter
    def line(self, line: str) -> None:
        line = self._init_line(line)
        items = line.split()
        if not items:
            self._delete_port()
            return
        self._line = line
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
        """ACE TCP/UDP list of items as int.
        Example1:
            Port("eq www 443")
            :return: [80, 443]
        Example2:
            Port("neq www")
            :return: [80]
        """
        return self._items

    @items.setter
    def items(self, items: IInt) -> None:
        items_ = [str(i) for i in list(items)]
        items_.insert(0, self.operator)
        self.line = " ".join(items_)

    @property
    def operator(self) -> str:
        """ACE TCP/UDP port operator: "eq", "gt", "lt", "neq", "range".
        Example:
            Port("eq www 443")
            :return: "eq"
        """
        return self._operator

    @operator.setter
    def operator(self, operator: str) -> None:
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
        """ACE TCP/UDP list of ports.
        Example1:
            Port("eq www 443")
            :return: [80, 443]
        Example2:
            Port("neq www")
            :return: [1, 2, ..., 79, 81, ..., 65534, 65535]
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
        """ACE TCP/UDP string ports (range).
        Example:
            Port("eq 1 3 4 5")
            :return: "1,3-5"
        """
        return self._sport

    @sport.setter
    def sport(self, sport: str) -> None:
        ports: LInt = h.string_to_ports(sport)
        self.ports = ports

    # =========================== helpers ============================

    def _delete_port(self) -> None:
        """clear port data"""
        self._line = ""
        self._operator = ""
        self._items = []
        self._ports = []
        self._sport = ""

    @staticmethod
    def _line__operator(items: LStr) -> str:
        """Get operator from items.
        Example:
            :param items: ["eq", "www"]
            :return: ["eq"]
        """
        operator, *items = items
        expected: LStr = list(OPERATORS)
        if operator not in expected:
            raise ValueError(f"invalid port {operator=}, {expected=}")
        return operator

    def _line__items_to_ints(self, items: LStr) -> LInt:
        """Convert named and digit items to int items
        Example:
            :param items: ["www", "443"]
            :return: [80, 443]
        """
        if not items:
            raise ValueError(f"absent ports={items}")

        # convert to int
        ports: LInt = []  # return
        for item in items:
            if item.isdigit():
                port = int(item)
            elif port_nr := PORTS.get(item):
                port = port_nr
            else:
                expected = sorted(PORTS)
                raise ValueError(f"invalid {item=}, {expected=}")
            ports.append(port)

        # validation
        platform = self.platform
        operator = self.operator
        if operator in ["lt", "gt"] and len(ports) != 1:
            raise ValueError(f"invalid {operator=} with {ports=}")
        if operator == "range" and len(ports) != 2:
            raise ValueError(f"invalid {operator=} with {ports=} expected 2 ports")
        if self.operator in ["eq", "neq"]:
            if platform == "cnx" and len(ports) != 1:
                raise ValueError(f"invalid count of {ports=}, for {platform=} expected 1 port")

        return sorted(ports)

    def _items_to_ports(self, items: LInt) -> LInt:
        """Transform line items to ports.

        Example1:
            :param items: [1, 4]
                self.operator="range"
            :return: [1, 2, 3, 4]

        Example2:
            :param items: [4]
                self.operator="ge"
            :return: [4, 5, 6, ..., 65535]
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
        """Transform ports to line items.

        Example1:
            :param ports: [1, 2, 3, 4]
                self.operator="range"
            :return: [1, 4]

        Example2:
            :param ports: [4, 5, 6, ..., 65535]
                self.operator="ge"
            :return: [4]
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
