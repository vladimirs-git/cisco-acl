"""Base - Parent of: AceBase, Address, Port, Protocol
BaseAce - Parent of: Ace, Remark"""

from cisco_acl.base import Base
from cisco_acl.sequence import Sequence
from cisco_acl.types_ import StrInt


class BaseAce(Base):
    """BaseAce - Parent of: Ace, Remark"""

    __slots__ = ("_platform", "_note", "_line", "_sequence", "_protocol_nr", "_port_nr")

    def __init__(self, line, **kwargs):
        """BaseAce - Parent of: Ace, Remark
        :param line: ACE line, can contain index
        :param platform: Platform: "ios", "nxos" (default "ios")
        :param bool protocol_nr: Well-known ip protocols as numbers
            True  - all ip protocols as numbers
            False - well-known ip protocols as names (default)
        :param bool port_nr: Well-known TCP/UDP ports as numbers
            True  - all tcp/udp ports as numbers
            False - well-known tcp/udp ports as names (default)
        :param note: Object description (can be used for ACEs sorting)
        """
        super().__init__(**kwargs)
        self._protocol_nr = bool(kwargs.get("protocol_nr"))
        self._port_nr = bool(kwargs.get("port_nr"))
        self.sequence = 0
        self.line = line

    # =========================== property ===========================

    @property
    def line(self) -> str:
        """Dummy"""
        return ""

    @line.setter
    def line(self, line: str):
        """Dummy"""
        return

    @property
    def port_nr(self) -> bool:
        """Well-known TCP/UDP ports as numbers"""
        return self._port_nr

    @port_nr.setter
    def port_nr(self, port_nr: bool):
        self._port_nr = bool(port_nr)
        self.line = self.line

    @property
    def protocol_nr(self) -> bool:
        """Well-known ip protocols as numbers"""
        return self._protocol_nr

    @protocol_nr.setter
    def protocol_nr(self, protocol_nr: bool):
        self._protocol_nr = bool(protocol_nr)
        self.line = self.line

    @property
    def sequence(self) -> Sequence:
        """Sequence object. ACE sequence number in ACL
        :return: Sequence number

        :example: Ace without sequence number
            Ace("permit ip any any")
            return: Sequence("0")

        :example: Ace with sequence number
            Ace("10 permit ip any any")
            return: Sequence("10")
        """
        return self._sequence

    @sequence.setter
    def sequence(self, sequence: StrInt) -> None:
        self._sequence = Sequence(sequence)

    @sequence.deleter
    def sequence(self) -> None:
        self._sequence = Sequence()
