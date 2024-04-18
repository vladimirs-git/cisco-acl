"""ACE IP protocol object."""

from __future__ import annotations

from functools import total_ordering
from typing import List

from cisco_acl import helpers as h
from cisco_acl.base import Base
from cisco_acl.types_ import StrInt, DAny

PROTOCOL_IP = 0

OPTIONS = (
    "ack",
    "dscp",
    "fin",
    "log",
    "log-input",
    "match-all",
    "match-any",
    "precedence",
    "psh",
    "rst",
    "time-range",
    "tos",
    "ttl",
    "urg",
)
PROTOCOLS_IOS = {
    "ip": 0,
    "icmp": 1,
    "igmp": 2,
    "ipip": 4,
    "tcp": 6,
    "egp": 8,
    "udp": 17,
    "ipv6": 41,
    "gre": 47,
    "esp": 50,
    "ah": 51,
    "ahp": 51,
    "eigrp": 88,
    "ospf": 89,
    "nos": 94,
    "pim": 103,
    "pcp": 108,
}
PROTOCOLS_NXOS = {
    "ip": 0,
    "icmp": 1,
    "igmp": 2,
    "tcp": 6,
    "udp": 17,
    "gre": 47,
    "esp": 50,
    "ahp": 51,
    "eigrp": 88,
    "ospf": 89,
    "nos": 94,
    "pim": 103,
    "pcp": 108,
}
PROTOCOLS_ASA = {
    "ip": 0,
    "icmp": 1,
    "igmp": 2,
    "ipinip": 4,
    "tcp": 6,
    "igrp": 9,
    "udp": 17,
    "gre": 47,
    "esp": 50,
    "ah": 51,
    "icmp6": 58,
    "eigrp": 88,
    "ospf": 89,
    "nos": 94,
    "pim": 103,
    "pcp": 108,
    "snp": 109,
    "sctp": 132,
}
PROTOCOLS_ANY = {**PROTOCOLS_ASA, **PROTOCOLS_IOS, **PROTOCOLS_NXOS}
PROTOCOL_TO_NR = dict(
    asa=PROTOCOLS_ASA,
    ios=PROTOCOLS_IOS,
    nxos=PROTOCOLS_NXOS,
)
NR_TO_PROTOCOL = dict(
    asa={i: s for s, i in PROTOCOLS_ASA.items()},
    ios={i: s for s, i in PROTOCOLS_IOS.items()},
    nxos={i: s for s, i in PROTOCOLS_NXOS.items()},
)


@total_ordering
class Protocol(Base):
    """ACE IP protocol object."""

    def __init__(self, line: str = "", **kwargs):
        """Init Protocol.

        :param line: IP protocol line.
        :type line: str

        :param platform: Platform: "asa", "ios", "nxos". Default "ios".
        :type platform: str

        :param version: Software version, default is "0".
        :type version: str

        Helpers
        :param note: Object description.
        :type note: Any

        :param protocol_nr: Well-known ip protocols as numbers.
            True  - all ip protocols as numbers,
            False - well-known ip protocols as names (default).
        :type protocol_nr: bool

        :param has_port: ACE has tcp/udp src/dst ports.
            True  - ACL has tcp/udp src/dst ports,
            False - ACL does not have tcp/udp src/dst ports (default).
        :type port_nr: bool

        :example:
            protocol = Protocol("tcp", platform="ios")
            protocol.line -> "tcp"
            protocol.name -> "tcp"
            protocol.number -> 6

            protocol = Protocol("255", platform="ios")
            protocol.line -> "255"
            protocol.name == ""
            protocol.number == 255
        """
        self._number = PROTOCOL_IP
        self._protocol_nr = bool(kwargs.get("protocol_nr"))
        self._has_port = bool(kwargs.get("has_port"))
        super().__init__(**kwargs)
        self.line = line

    # ========================== redefined ===========================

    def __hash__(self) -> int:
        """__hash__."""
        return self.line.__hash__()

    def __eq__(self, other) -> bool:
        """== equality."""
        return self.__hash__() == other.__hash__()

    def __lt__(self, other) -> bool:
        """< less than."""
        if self.__class__ == other.__class__:
            if self.number != other.number:
                return self.number < other.number
        return False

    def __repr__(self):
        """__repr__."""
        params = super()._repr__params()
        params = self._repr__add_param("protocol_nr", params)
        params = self._repr__add_param("has_port", params)
        kwargs = ", ".join(params)
        name = self.__class__.__name__
        return f"{name}({kwargs})"

    # =========================== property ===========================

    @property
    def has_port(self) -> bool:
        """Return True if protocol is "tcp" or "udp" with specified port."""
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
            number_ = PROTOCOLS_ANY.get(line)
            if number_ is None:
                raise ValueError(f"invalid protocol {line=}, expected={list(PROTOCOLS_ANY)}")
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
        """Well-known ip protocols as numbers.

        True  - all ip protocols as numbers,
        False - well-known ip protocols as names (default).
        """
        return self._protocol_nr

    @protocol_nr.setter
    def protocol_nr(self, protocol_nr: bool) -> None:
        self._protocol_nr = bool(protocol_nr)

    # =========================== method =============================

    def data(self, uuid: bool = False) -> DAny:
        """Convert Protocol object to the dictionary.

        :param uuid: Return self.uuid in data.
        :return: Protocol data.

        :example:
            address = Protocol(line="tcp")
            address.data() -> {
                "line": "tcp",
                "platform": "ios",
                "version": "0",
                "note": "",
                "protocol_nr": False,
                "has_port": False,
                "name": "tcp",
                "number": 6,
            }
        """
        data = dict(
            # init
            line=self.line,
            platform=self._platform,
            version=str(self.version),
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
