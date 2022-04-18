"""Base - Parent of: AceBase, Address, Port, Protocol.
BaseAce - Parent of: Ace, Remark."""

from cisco_acl.base import Base
from cisco_acl.sequence import Sequence
from cisco_acl.types_ import StrInt


class BaseAce(Base):
    """BaseAce - Parent of: Ace, Remark."""

    __slots__ = ("_platform", "_note", "_line", "_sequence")

    def __init__(self, line, **kwargs):
        """BaseAce - Parent of: Ace, Remark.
        :param line: ACE line, can contain index.
        :param kwargs: Params.
            platform: Supported platforms: "ios", "cnx". By default: "ios".
            note: Object description (can be used for ACEs sorting).
        """
        super().__init__(**kwargs)
        self.sequence = 0
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
    def sequence(self) -> Sequence:
        """ACE sequence.

        Example1:
            Ace("permit ip any any")
            :return: Sequence("0")

        Example2:
            Ace("10 permit ip any any")
            :return: Sequence("10")
        """
        return self._sequence

    @sequence.setter
    def sequence(self, sequence: StrInt) -> None:
        self._sequence = Sequence(sequence)

    @sequence.deleter
    def sequence(self) -> None:
        del self.sequence.number
