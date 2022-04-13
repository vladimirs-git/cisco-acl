"""Base - Parent of: AceBase, Address, Port, Protocol.
BaseAce - Parent of: Ace, Remark."""

from cisco_acl import helpers as h
from cisco_acl.base import Base
from cisco_acl.static import MAX_LINE_LENGTH
from cisco_acl.types_ import StrInt


class BaseAce(Base):
    """BaseAce - Parent of: Ace, Remark."""

    __slots__ = ("_platform", "_note", "_line", "_idx", "_sidx")

    def __init__(self, line, **kwargs):
        """BaseAce - Parent of: Ace, Remark.
        :param line: ACE line, can contain index.
        :param kwargs: Params.
            platform: Platform. By default: "ios".
            note: Object description (not used in ACE).
            line_length: ACE line max length.
        """
        super().__init__(**kwargs)
        self.line_length = int(kwargs.get("line_length") or MAX_LINE_LENGTH)
        self._idx: int = 0
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
    def idx(self) -> int:
        """ACE index, int.

        Example1:
            Ace("permit any any")
            :return: 0

        Example2:
            Ace("10 permit any any")
            :return: 10
        """
        return self._idx

    @idx.setter
    def idx(self, idx: StrInt) -> None:
        self._idx = h.str_to_positive_int(idx)

    @idx.deleter
    def idx(self) -> None:
        self._idx = 0

    @property
    def sidx(self) -> str:
        """ACE index, string.

        Example1:
            Ace("permit any any")
            :return: ""

        Example2:
            Ace("10 permit any any")
            :return: "10"
        """
        return str(self.idx) if self.idx else ""

    # =========================== helpers ============================

    def _check_line_length(self, line) -> bool:
        line_length = len(line)
        if line_length > self.line_length:
            raise ValueError(f"{line_length=}, expected={self.line_length}")
        return True
