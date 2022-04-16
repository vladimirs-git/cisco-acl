"""ACE Sequence number"""
from __future__ import annotations

from functools import total_ordering

from cisco_acl import helpers as h
from cisco_acl.types_ import StrInt


@total_ordering
class Sequence:
    """ACE Sequence number"""

    __slots__ = ("_line", "_number")

    def __init__(self, line: StrInt = ""):
        """ACE Sequence number.
        :param line: ACE sequence number.

        Example:
            line: "10"
        result:
            self.line = "10"
            self.number = 10
        """
        self.line = str(line)

    def __repr__(self):
        return f"{self.__class__.__name__}({self.line!r})"

    def __str__(self):
        return self.line

    def __int__(self):
        return self.number

    def __hash__(self) -> int:
        return self.number.__hash__()

    def __eq__(self, other) -> bool:
        """== equality"""
        if self.__class__ == other.__class__:
            return self.__hash__() == other.__hash__()
        if isinstance(other, int):
            return self.__hash__() == other.__hash__()
        if isinstance(other, str):
            if other.isdigit():
                return str(self.number).__hash__() == other.__hash__()
            if not other:
                return self.line.__hash__() == other.__hash__()
        return False

    def __lt__(self, other) -> bool:
        """< less than"""
        if isinstance(other, Sequence):
            return self.number < other.number
        if isinstance(other, int):
            return self.number < other
        if isinstance(other, str):
            if other.isdigit():
                return str(self.number) < other
            if not other:
                return self.line < other
        return True

    # =========================== property ===========================

    @property
    def line(self) -> str:
        """ACE sequence number <str>.
        Example1:
            Sequence("10")
            :return: "10"
        Example1:
            Sequence("0")
            :return: ""
        """
        if not self._number:
            return ""
        return str(self._number)

    @line.setter
    def line(self, line: StrInt) -> None:
        self._number = h.str_to_positive_int(line)

    @line.deleter
    def line(self) -> None:
        self._number = 0

    @property
    def number(self) -> int:
        """ACE sequence number <int>.
        Example:
            Sequence("10")
            :return: 10
        """
        return self._number

    @number.setter
    def number(self, number: int) -> None:
        if not isinstance(number, int):
            raise TypeError(f"{number=} {int} expected")
        self._number = h.str_to_positive_int(number)

    @number.deleter
    def number(self) -> None:
        self._number = 0
