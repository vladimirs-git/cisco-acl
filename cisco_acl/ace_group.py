"""Group of ACE (Access Control Entry)"""
from __future__ import annotations

from functools import total_ordering
from typing import List, Optional, Union

from cisco_acl import helpers as h
from cisco_acl.ace import Ace, LAce
from cisco_acl.base_ace import BaseAce
from cisco_acl.group import Group
from cisco_acl.remark import Remark, LRemark
from cisco_acl.sequence import Sequence
from cisco_acl.types_ import StrInt

UAce = Union[Ace, Remark]
OUAce = Optional[UAce]
LUAce = List[UAce]

ULAce = Union[LAce, LRemark, LUAce]


@total_ordering
class AceGroup(Group, BaseAce):
    """Group of ACE (Access Control Entry)"""

    def __init__(self, line: str = "", **kwargs):
        """Group of ACE (Access Control Entry).
        :param line: string of ACEs.
        :param kwargs:
            platform: Supported platforms: "ios", "cnx". By default: "ios".
            note: Object description (can be used for ACEs sorting).
            items: List of ACE (strings or Ace objects). By default parsed from line.

        Example:
        line: "10 permit icmp any any\n  20 deny ip any any"
        platform: "ios"
        note: "description"

        result:
            self.line = "10 permit icmp any any\n20 deny ip any any"
            self.platform = "ios"
            self.note = "description"
            self.sequence = 10  # Taking from the first ACE in items.
            self.items = [Ace("10 permit icmp any any"), Ace("20 deny ip any any")]
        """
        BaseAce.__init__(self, "", **kwargs)
        Group.__init__(self)
        self.line = line
        if not line:
            self._init_items(**kwargs)

    def __hash__(self) -> int:
        return self.line.__hash__()

    def __eq__(self, other) -> bool:
        """== equality"""
        if self.__class__ == other.__class__:
            if self.__hash__() == other.__hash__():
                return True
        return False

    def __lt__(self, other) -> bool:
        """< less than"""
        if hasattr(other, "sequence"):
            if self.sequence == other.sequence:
                if other.__class__.__name__ == "Remark":
                    return False
                if isinstance(other, Ace):
                    return False
                if isinstance(other, AceGroup):
                    return str(self) < str(other)
                raise TypeError(f"{other=} {AceGroup} expected")
            return self.sequence < other.sequence
        return False

    # ============================= init =============================

    def _init_items(self, **kwargs) -> None:
        """Init items"""
        items = kwargs.get("items") or []
        if not isinstance(items, list):
            raise TypeError(f"{items=} {list} expected")
        self.items = items
        sequence = int(self.items[0].sequence) if self.items else 0
        self.sequence.number = sequence

    # =========================== property ===========================

    @property
    def line(self) -> str:
        """ACEs in string format"""
        return "\n".join([o.line for o in self.items])

    @line.setter
    def line(self, line: str) -> None:
        lines = line.split("\n")
        lines = [self._init_line(s) for s in lines]
        items_ = [self._line_to_ace(s) for s in lines]
        items: LUAcl = [o for o in items_ if isinstance(o, (Ace, Remark))]
        self.items = items
        sequence = int(self.items[0].sequence) if self.items else 0
        self.sequence.number = sequence

    @line.deleter
    def line(self) -> None:
        self.items = []
        self.sequence.number = 0

    @property
    def items(self) -> LUAcl:
        """List of Ace, Remark objects"""
        return self._items

    @items.setter
    def items(self, items: LUAce) -> None:
        items_: LUAcl = []
        for item in items:
            if isinstance(item, (Ace, Remark)):
                items_.append(item)
            else:
                raise TypeError(f"{item=} {Ace} {Remark} expected")
        self._items = items_

    @items.deleter
    def items(self) -> None:
        self._items = []

    @property
    def sequence(self) -> Sequence:
        """ACE group sequence."""
        return self._sequence

    @sequence.setter
    def sequence(self, sequence: StrInt) -> None:
        self._sequence = Sequence(sequence)

    @sequence.deleter
    def sequence(self) -> None:
        del self.sequence.number

    # methods

    def copy(self) -> AceGroup:
        """Return a shallow copy of self."""

        """Group of ACE (Access Control Entry).
        :param line: string of ACEs.
        :param kwargs:
            platform: Supported platforms: "ios", "cnx". By default: "ios".
            note: Object description (can be used for ACEs sorting).
            items: List of ACE (strings or Ace objects).

        Example:
        line: "10 permit icmp any any\n  20 deny ip any any"
        platform: "ios"
        note: "description"

        result:
            self.line = "10 permit icmp any any\n20 deny ip any any"
            self.platform = "ios"
            self.note = "description"
            self.sequence = 10  # Taking from the first ACE in items.
            self.items = [Ace("10 permit icmp any any"), Ace("20 deny ip any any")]
        """

        aceg = AceGroup(
            items=[o.copy() for o in self.items],
            platform=self.platform,
            note=self.note,
        )
        return aceg

    # =========================== helpers ============================

    def _line_to_ace(self, line: str) -> OUAce:
        """Convert config line to Ace or Remark object.
        Example1:
            :param line: "permit ip any any"
            :return: Ace("permit ip any any")

        Example2:
            :param line: "remark text"
            :return: Remark("text")

        Example3:
            :param line: "text"
            :return: None
        """
        try:
            action = h.parse_action(line)["action"]
        except ValueError:
            return None
        if action in ["permit", "deny"]:
            return Ace(line, platform=self.platform)
        if action in ["remark"]:
            return Remark(line, platform=self.platform)
        return None

    def _check_platform(self, ace: UAcl) -> bool:
        """Check is Ace platform == AceGroup platform"""
        acl_platform: str = self.platform
        ace_platform = ace.platform
        if ace_platform != acl_platform:
            raise ValueError(f"{ace=} {ace_platform=}, expected {acl_platform=}")
        return True


UAcl = Union[Ace, Remark, AceGroup]
LUAcl = List[UAcl]
