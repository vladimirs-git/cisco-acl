"""ACE. TCP/UDP Port."""

from typing import List

from cisco_acl.base import Base
from cisco_acl.static import OPERATORS, PORTS
from cisco_acl.types_ import LInt, LStr, OInt


# todo setters: _operator, _port, _sport
class Port(Base):
    """ACE. TCP/UDP Port."""

    __slots__ = ("_platform", "_note", "_line", "_operator", "_ports", "_sport")

    def __init__(self, line: str, **kwargs):
        """ACE. TCP/UDP Port.
        :param line: TCP/UDP ports line.
        :param kwargs: Params.
            platform: Platform. By default: "ios".
            note: Object description (not used in ACE).

        Example1: ios, "eq" match multiple ports
            line: "eq www 443"
            platform: "ios"
                self.line = "eq www 443"
                self.operator = "eq"
                self.ports = [80, 443]
                self.sport = "80,443"

        Example2: cnx, "eq" match only one port
        line: "eq www"
        platform: "cnx"
            self.line = "eq www"
            self.operator = "eq"
            self.ports = [80]
            self.sport = "80"

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
        ports: LInt = self._line__ports(items[1:])
        ports = self._port_by_operator(ports)
        self._ports = ports
        self._sport = self._line__sport(ports)

    @property
    def operator(self) -> str:
        """ACE TCP/UDP port operator: "eq", "gt", "lt", "neq", "range".
        Example:
            Port("eq www 443")
            :return: "eq"
        """
        return self._operator

    @property
    def ports(self) -> LInt:
        """ACE TCP/UDP list of ports as int.
        Example:
            Port("eq www 443")
            :return: [80, 443]
        """
        return self._ports

    @property
    def sport(self) -> str:
        """ACE TCP/UDP line of ports.
        Example1:
            Port("eq www 443")
            return: "80,443"
        Example2:
            Port("range www 82")
            return: "80-82"
        """
        return self._sport

    # =========================== helpers ============================

    def _delete_port(self) -> None:
        """clear port data"""
        self._line = ""
        self._operator = ""
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

    def _line__ports(self, items: LStr) -> LInt:
        """Convert items to ports
        Example:
            :param items: ["www", "443"]
            :return: [80, 443]
        """
        if not items:
            raise ValueError(f"absent ports={items}")
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

    def _port_by_operator(self, ports: LInt) -> LInt:
        """Transform ports by operator.
        Example:
            :param ports: [1, 4]
                self.operator="range"
            :return: [1, 2, 3, 4]
        """
        operator = self._operator
        if operator == "eq":
            return ports
        if operator == "range":
            ports = list(range(ports[0], ports[-1] + 1))
            return ports

        all_ports = list(range(1, 65535 + 1))
        if operator == "neq":
            ports = [i for i in all_ports if i not in ports]
            return ports
        if operator == "gt":
            ports = [i for i in all_ports if i > ports[0]]
            return ports
        if operator == "lt":
            ports = [i for i in all_ports if i < ports[0]]
            return ports
        raise ValueError(f"invalid port {operator=}")

    @staticmethod
    def _line__sport(items: LInt) -> str:
        """Convert list of ports to string.
        Example:
            :param items: [1,3,4,5]
            :return: "1,3-5"
        """
        if not items:
            return ""
        items = sorted(items)
        ranges: LStr = []  # return
        item_1st: OInt = None
        for idx, item in enumerate(items, start=1):
            # not last iteration
            if idx < len(items):
                item_next = items[idx]
                if item_next - item <= 1:  # range
                    if item_1st is None:  # start new range
                        item_1st = item
                else:  # int or end of range
                    ranges.append(str(item) if item_1st is None else f"{item_1st}-{item}")
                    item_1st = None
            # last iteration
            else:
                item_ = str(item) if item_1st is None else f"{item_1st}-{item}"
                ranges.append(item_)
        return ",".join(ranges)


LPort = List[Port]
