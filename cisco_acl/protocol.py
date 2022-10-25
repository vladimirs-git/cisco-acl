"""ACE IP protocol object"""
from __future__ import annotations

from functools import total_ordering
from typing import List

from cisco_acl import helpers as h
from cisco_acl.base import Base
from cisco_acl.static import NR_TO_PROTOCOL, ANY_PROTOCOLS
from cisco_acl.types_ import StrInt, DAny

PROTOCOL_IP = 0


@total_ordering
class Protocol(Base):
    """ACE IP protocol object"""

    def __init__(self, line: str = "", **kwargs):
        """ACE. IP protocol object
        :param line: IP protocol line
        :type line: str

        :param platform: Platform: "ios", "nxos" (default "ios")
        :type platform: str

        Helpers
        :param note: Object description
        :type note: Any

        :param protocol_nr: Well-known ip protocols as numbers
            True  - all ip protocols as numbers
            False - well-known ip protocols as names (default)
        :type protocol_nr: bool

        :param has_port: ACE has tcp/udp src/dst ports
            True  - ACL has tcp/udp src/dst ports
            False - ACL does not have tcp/udp src/dst ports (default)
        :type port_nr: bool

        :example:
            protocol = Protocol("tcp", platform="ios")
            result:
                protocol.line == "tcp"
                protocol.name == "tcp"
                protocol.number == 6
        :example:
        protocol = Protocol("255", platform="ios")
            result:
                protocol.line == "255"
                protocol.name == ""
                protocol.number == 255
        """
        self._number = PROTOCOL_IP
        self._protocol_nr = bool(kwargs.get("protocol_nr") or False)
        self._has_port = bool(kwargs.get("has_port") or False)
        super().__init__(**kwargs)
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

    def __repr__(self):
        params = super()._repr__params()
        params = self._repr__add_param("protocol_nr", params)
        params = self._repr__add_param("has_port", params)
        kwargs = ", ".join(params)
        name = self.__class__.__name__
        return f"{name}({kwargs})"

    # =========================== property ===========================

    @property
    def has_port(self) -> bool:
        """True if protocol is "tcp" or "udp" with specified port"""
        return self._has_port

    @has_port.setter
    def has_port(self, has_port: bool) -> None:
        self._has_port = bool(has_port)

    @property
    def line(self) -> str:
        """ACE protocol name: "ip", "icmp", "tcp", etc."""
        number = self._number
        if self._protocol_nr and not self._has_port:
            return str(number)
        if name := NR_TO_PROTOCOL[self._platform].get(number):
            return str(name)
        return str(number)

    @line.setter
    def line(self, line: str) -> None:
        line = h.int_to_str(line)
        if not line:
            self._number = PROTOCOL_IP
            return

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

    @property
    def name(self) -> str:
        """ACE protocol name: "ip", "icmp", "tcp", etc."""
        number = self._number
        if name := NR_TO_PROTOCOL[self._platform].get(number):
            return str(name)
        return ""

    @name.setter
    def name(self, name: str) -> None:
        if not isinstance(name, str):
            raise TypeError(f"{name=} {str} expected")
        self.line = name

    @property
    def number(self) -> int:
        """ACE protocol number: 0..255, where 0="ip", 1="icmp", etc."""
        return self._number

    @number.setter
    def number(self, number: StrInt) -> None:
        self.line = h.init_number(number)

    @property
    def protocol_nr(self) -> bool:
        """Well-known ip protocols as numbers
            True  - all ip protocols as numbers
            False - well-known ip protocols as names (default)
        """
        return self._protocol_nr

    @protocol_nr.setter
    def protocol_nr(self, protocol_nr: bool) -> None:
        self._protocol_nr = bool(protocol_nr)

    # =========================== methods ============================

    def data(self, uuid: bool = False) -> DAny:
        """Converts *Protocol* object to *dict*
        :param uuid: Returns self.uuid in data
        :type uuid: bool

        :return: Protocol data

        :example:
            address = Protocol(line="tcp")
            address.data() -> {"line": "tcp",
                              "platform": "ios",
                              "note": "",
                              "protocol_nr": False,
                              "has_port": False,
                              "name": "tcp",
                              "number": 6}
        """
        data = dict(
            # init
            line=self.line,
            platform=self._platform,
            note=self.note,
            protocol_nr=self._protocol_nr,
            has_port=self._has_port,
            # property
            name=self.name,
            number=self._number,
        )
        if uuid:
            data["uuid"] = self.uuid
        return data


LProtocol = List[Protocol]
