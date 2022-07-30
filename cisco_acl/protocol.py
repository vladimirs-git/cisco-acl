"""ACE. IP protocol object"""

from functools import total_ordering
from typing import List

from cisco_acl.base import Base
from cisco_acl.static import NR_TO_PROTOCOL, ANY_PROTOCOLS
from cisco_acl.types_ import StrInt


@total_ordering
class Protocol(Base):
    """ACE. IP protocol object"""

    _default: int = 0  # ip="0"

    __slots__ = ("_platform", "_note", "_line", "_name", "_number", "_protocol_nr")

    def __init__(self, line: str = "", **kwargs):
        """ACE. IP protocol object
        :param line: IP protocol line
        :param str platform: Platform: "ios", "nxos" (default "ios")
        :param bool protocol_nr: Cisco ACL outputs well-known ip protocols as numbers
            True  - all ip protocols as numbers
            False - well-known ip protocols as names (default)
        :param bool has_port: ACL has tcp/udp src/dst ports
            True  - ACL has tcp/udp src/dst ports
            False - ACL does not have tcp/udp src/dst ports (default)
        :param note: Object description (can be used for ACEs sorting)

        :example:
            line: ["tcp"]
            result:
                self.line = "tcp"
                self.name = "tcp"
                self.number = 6
        :example:
            line: ["255"]
            result:
                self.line = "255"
                self.name = ""
                self.number = 255
        """
        super().__init__(**kwargs)
        self._protocol_nr = bool(kwargs.get("protocol_nr"))
        self.has_port = bool(kwargs.get("has_port"))
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
            if self.number != other.number:
                return self.number < other.number
        return False

    # =========================== property ===========================

    @property
    def line(self) -> str:
        """ACE protocol name: "ip", "icmp", "tcp", etc."""
        number = self._number
        if self.protocol_nr and not self.has_port:
            return str(number)
        if name := NR_TO_PROTOCOL[self.platform].get(number):
            return str(name)
        return str(number)

    @line.setter
    def line(self, line: str) -> None:
        line = self._init_line_int(line)
        if not line:
            self._set_default()
            return
        if isinstance(line, int):
            line = str(line)
        if not isinstance(line, str):
            raise TypeError(f"protocol {line=} {str} expected")

        # permit 255 any any
        if line.isdigit():
            number: int = int(line)
            if not 0 <= number <= 255:
                raise ValueError(f"invalid protocol {number=}, expected 0..255")

        # permit ip any any
        else:
            number_ = ANY_PROTOCOLS.get(line)
            if number_ is None:
                raise ValueError(f"invalid protocol {line=}, expected={list(ANY_PROTOCOLS)}")
            number = int(number_)

        self._number = number

    @line.deleter
    def line(self) -> None:
        self._set_default()

    @property
    def name(self) -> str:
        """ACE protocol name: "ip", "icmp", "tcp", etc."""
        number = self._number
        if name := NR_TO_PROTOCOL[self.platform].get(number):
            return str(name)
        return ""

    @name.setter
    def name(self, name: str) -> None:
        if not isinstance(name, str):
            raise TypeError(f"protocol {name=} {str} expected")
        self.line = name

    @property
    def number(self) -> int:
        """ACE protocol number: 0..255, where 0="ip", 1="icmp", etc."""
        return self._number

    @number.setter
    def number(self, number: StrInt) -> None:
        if isinstance(number, str) and number.isdigit():
            number = int(number)
        if not isinstance(number, int):
            raise TypeError(f"protocol {number=} {int} expected")
        self.line = str(number)

    @property
    def platform(self) -> str:
        """Platforms: "ios", "nxos" """
        return self._platform

    @platform.setter
    def platform(self, platform: str):
        self._platform = self._init_platform(platform=platform)
        self.line = self.line

    @property
    def protocol_nr(self) -> bool:
        """Cisco ACL outputs well-known ip protocols as numbers
            True  - all ip protocols as numbers
            False - well-known ip protocols as names (default)
        """
        return self._protocol_nr

    @protocol_nr.setter
    def protocol_nr(self, protocol_nr: bool) -> None:
        self._protocol_nr = bool(protocol_nr)

    # =========================== helpers ============================

    def _set_default(self) -> None:
        """Sets protocol="ip" (default value)"""
        self._number = self._default


LProtocol = List[Protocol]
