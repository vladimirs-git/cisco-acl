"""ACE. Protocol."""

from typing import List

from cisco_acl.base import Base
from cisco_acl.static_ import PROTOCOL_TO_NR, NR_TO_PROTOCOL
from cisco_acl.types_ import StrInt


class Protocol(Base):
    """ACE. Protocol."""

    _default: int = 0  # ip="0"

    __slots__ = ("_platform", "_note", "_line", "_name", "_number")

    def __init__(self, line: str, **kwargs):
        """ACE. Protocol.
        :param line: Protocol line.
        :param kwargs: Params.
            platform: Platform. By default: "ios".
            note: Object description (not used in ACE).

        Example1:
            line: ["tcp"]
                self.line = "tcp"
                self.name = "tcp"
                self.number = 6
        Example2:
            line: ["255"]
                self.line = "255"
                self.name = ""
                self.number = 255
        """
        super().__init__(**kwargs)
        self.line = line

    # =========================== property ===========================

    @property
    def line(self) -> str:
        """ACE protocol name: "ip", "icmp", "tcp", etc."""
        return self._line

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
            name: str = NR_TO_PROTOCOL[self.platform].get(number) or ""

        # permit icmp any any
        else:
            expected = list(PROTOCOL_TO_NR[self.platform])
            if line not in expected:
                raise ValueError(f"invalid protocol {line=}, {expected=}")
            name = line
            number = PROTOCOL_TO_NR[self.platform][name]

        self._line = name or str(number)
        self._name = name
        self._number = number

    @line.deleter
    def line(self) -> None:
        self._set_default()

    @property
    def name(self) -> str:
        """ACE protocol name: "ip", "icmp", "tcp", etc."""
        return self._name

    @name.setter
    def name(self, name: str) -> None:
        if not isinstance(name, str):
            raise TypeError(f"protocol {name=} {str} expected")
        if not name:
            self._set_default()
            return
        expected = list(PROTOCOL_TO_NR[self.platform])
        if name not in expected:
            raise ValueError(f"invalid protocol {name=}, {expected=}")
        number = PROTOCOL_TO_NR[self.platform][name]

        self._line = name
        self._name = name
        self._number = number

    @name.deleter
    def name(self) -> None:
        self._set_default()

    @property
    def number(self) -> int:
        """ACE protocol number: 0..255, where 0="ip", 1="icmp", etc. """
        return self._number

    @number.setter
    def number(self, number: StrInt) -> None:
        if isinstance(number, int):
            number_: int = number
        elif isinstance(number, str) and number.isdigit():
            number_ = int(number)
        else:
            raise TypeError(f"protocol {number=} {int} expected")
        if not number_:
            self._set_default()
            return
        if not 0 <= number_ <= 255:
            raise ValueError(f"invalid protocol {number_=}, expected 0..255")
        name: str = str(NR_TO_PROTOCOL[self.platform].get(number_) or "")

        self._line = name or str(number_)
        self._name = name
        self._number = number_

    @number.deleter
    def number(self) -> None:
        self._set_default()

    # =========================== helpers ============================

    def _set_default(self) -> None:
        """set protocol="ip" (default value)"""
        number: int = self._default
        name: str = NR_TO_PROTOCOL[self.platform][number]
        self._line = name
        self._name = name
        self._number = number


LProtocol = List[Protocol]
