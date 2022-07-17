"""Base - Parent of: AceBase, Address, Port, Protocol
BaseAce - Parent of: Ace, Remark"""

from cisco_acl.base import Base
from cisco_acl.sequence import Sequence
from cisco_acl.types_ import StrInt


class BaseAce(Base):
    """BaseAce - Parent of: Ace, Remark"""

    __slots__ = ("_platform", "_note", "_line", "_sequence", "_numerically")

    def __init__(self, line, **kwargs):
        """BaseAce - Parent of: Ace, Remark
        :param line: ACE line, can contain index
        :param platform: Platform: "ios", "nxos" (default "ios")
        :param note: Object description (can be used for ACEs sorting)
        """
        super().__init__(**kwargs)
        self._numerically = bool(kwargs.get("numerically"))
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
    def numerically(self) -> bool:
        """Cisco ACL outputs well-known tcp/udp ports as names"""
        return self._numerically

    @numerically.setter
    def numerically(self, numerically: bool):
        self._numerically = bool(numerically)
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
