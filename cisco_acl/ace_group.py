"""Group of ACE (Access Control Entry)"""
from __future__ import annotations

from functools import total_ordering
from typing import List, Union

from cisco_acl import helpers as h
from cisco_acl.ace import Ace, LAce
from cisco_acl.base_ace import BaseAce
from cisco_acl.group import Group
from cisco_acl.remark import Remark, LRemark
from cisco_acl.static import ACTIONS
from cisco_acl.types_ import LStr

UAce = Union[Ace, Remark]
LUAce = List[UAce]

ULAce = Union[str, Ace, Remark, LStr, LAce, LRemark, UAce]


@total_ordering
class AceGroup(Group, BaseAce):
    """Group of ACE (Access Control Entry)"""

    def __init__(self, items: ULAce = None, **kwargs):
        """Group of ACE (Access Control Entry).
        Taking AceGroup index (self.sequence) from the first ACE in items.
        :param items: List of ACE (strings or Ace objects).
        :param kwargs:
            platform: Supported platforms: "ios", "cnx". By default: "ios".
            note: Object description (used only in object).

        Example:
        line: "10 permit tcp host 10.0.0.1 eq 179 10.0.0.0 0.0.0.3 eq 80 443 log"
        platform: "ios"
        note: "description"

        result:
            self.line = "10 permit tcp host 10.0.0.1 10.0.0.0 0.0.0.3 eq www 443 log"
            self.platform = "ios"
            self.sequence = 10
            self.action = "permit"
            self.protocol = Protocol("tcp")
            self.srcaddr = Address("host 10.0.0.1")
            self.srcport = Port("eq bgp")
            self.dstaddr = Address("10.0.0.0 0.0.0.3")
            self.dstport = Port("eq www 443")
            self.option = "log"
            self.note = "description"

        """
        BaseAce.__init__(self, "", **kwargs)
        Group.__init__(self)
        self.items = self._convert_any_to_aces(items or [])  # type:ignore
        self.sequence.number = self._init_sequence()

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

    def _init_sequence(self) -> int:
        """Init Acl sequence. Index of 1st item in self.items."""
        if self.items:
            return int(self.items[0].sequence)
        return 0

    # =========================== property ===========================

    @property
    def items(self) -> LUAcl:
        """List of Ace objects"""
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
    def line(self) -> str:
        """ACEs in string format"""
        return "\n".join([o.line for o in self.items])

    @line.setter
    def line(self, line: str) -> None:
        items = line.split("\n")
        items = [self._init_line(s) for s in items]
        items = [s for s in items if s]
        aces: LUAcl = [self._convert_str_to_ace(s) for s in items]
        self.items = aces

    @line.deleter
    def line(self) -> None:
        self.items = []

    # =========================== helpers ============================

    def _convert_any_to_aces(self, items: ULAce) -> LUAce:
        """Convert str, Ace, Remark, List[str], List[Ace]  to objects.
        Example1:
            :param items: ["remark text",
                           "permit ip any any"]
            :return: [Remark("remark text"),
                      Ace("permit ip any any")]
        Example2:
            :param items: [Remark("remark text"),
                           Ace("permit ip any any")]
            :return: [Remark("remark text"),
                      Ace("permit ip any any")]
        """
        if isinstance(items, (str, Ace, Remark)):
            items = [items]  # type:ignore
        if not isinstance(items, list):
            raise TypeError(f"{items=} {list} expected")

        items_: LUAce = []  # return
        for item in items:
            if isinstance(item, str):
                item = self._convert_str_to_ace(item)
            if isinstance(item, (Ace, AceGroup, Remark)):
                self._check_platform(item)
            else:
                raise TypeError(f"{item=} {str}, {Ace}, {AceGroup}, {Remark} expected")
            items_.append(item)
        return items_

    def _convert_str_to_ace(self, line: str) -> UAce:
        """Convert ACE line to Ace or Remark object.
        Example:
            :param line: "permit ip any any"
            :return: Ace("permit ip any any")
        """
        action = h.parse_action(line)["action"]
        if action in ["permit", "deny"]:
            return Ace(line, platform=self.platform)
        if action in ["remark"]:
            return Remark(line, platform=self.platform)
        expected_actions = list(ACTIONS)
        raise ValueError(f"{line=} {expected_actions=}")

    def _check_platform(self, ace: UAcl) -> bool:
        """Check is Ace platform == AceGroup platform"""
        acl_platform: str = self.platform
        ace_platform = ace.platform
        if ace_platform != acl_platform:
            raise ValueError(f"{ace=} {ace_platform=}, expected {acl_platform=}")
        return True



UAcl = Union[Ace, Remark, AceGroup]
LUAcl = List[UAcl]
