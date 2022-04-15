"""Base - Parent of: AceBase, Address, Port, Protocol.
BaseAce - Parent of: Ace, Remark."""

from cisco_acl import helpers as h
from cisco_acl.base import Base
from cisco_acl.types_ import StrInt


class BaseAce(Base):
    """BaseAce - Parent of: Ace, Remark."""

    __slots__ = ("_platform", "_note", "_line", "_sequence", "_ssequence")

    def __init__(self, line, **kwargs):
        """BaseAce - Parent of: Ace, Remark.
        :param line: ACE line, can contain index.
        :param kwargs: Params.
            platform: Supported platforms: "ios", "cnx". By default: "ios".
            note: Object description (used only in object).
        """
        super().__init__(**kwargs)
        self._sequence: int = 0
        self.line = line

    # =========================== property ===========================

    @property
    def line(self) -> str:
        """dummy"""
        return ""

    @line.setter
    def line(self, line: str):
        """dummy"""
        return

    @property
    def sequence(self) -> int:  # TODO object
        """ACE sequence number <int>.

        Example1:
            Ace("permit any any")
            :return: 0

        Example2:
            Ace("10 permit any any")
            :return: 10
        """
        return self._sequence

    @sequence.setter
    def sequence(self, sequence: StrInt) -> None:
        self._sequence = h.str_to_positive_int(sequence)

    @sequence.deleter
    def sequence(self) -> None:
        self._sequence = 0

    @property
    def ssequence(self) -> str:  # TODO object
        """ACE sequence number <str>.

        Example1:
            Ace("permit any any")
            :return: ""

        Example2:
            Ace("10 permit any any")
            :return: "10"
        """
        return str(self.sequence) if self.sequence else ""
