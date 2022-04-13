"""ACL (Access Control List)"""
from __future__ import annotations

import re
from functools import total_ordering
from string import ascii_letters, digits, punctuation
from typing import Any, List

from cisco_acl import helpers as h
from cisco_acl.ace import Ace
from cisco_acl.ace_group import AceGroup, LUAcl
from cisco_acl.interface import Interface
from cisco_acl.remark import Remark
from cisco_acl.static_ import IDX_MAX, DEFAULT_PLATFORM, MAX_LINE_LENGTH, INDENTATION


@total_ordering
class Acl(AceGroup):
    """ACL (Access Control List)"""

    def __init__(self, line: str = "", items: Any = None, **kwargs):
        """ACL (Access Control List).
        ACL index (self.idx) is taken from the first ACE in items.
        :param name: ACL name.
        :param items: List of ACE (strings or Ace objects).
        :param kwargs:
            platform: Platform. By default: "ios".
            note: Object description (not used in ACE).
            line_length: ACE line max length.
            indent: ACE lines indentation. By default 2 spaces.
            name: ACL name.
            input: Interfaces, where Acl is used on input.
            output: Interfaces, where Acl is used on output.
        """
        super().__init__(**kwargs)
        self.line = line
        if not line:
            self.name = kwargs.get("name") or ""
            self.items = self._convert_any_to_acl(items or [])
        self.indent = kwargs.get("indent", INDENTATION)
        self.interface = Interface(**kwargs)

    def __repr__(self):
        params = [f"{self.line!r}"]
        if self._platform != DEFAULT_PLATFORM:
            params.append(f"platform={self._platform!r}")
        if self.note:
            params.append(f"note={self.note!r}")
        if self.name:
            params.append(f"name={self.name!r}")
        if self.line_length != MAX_LINE_LENGTH:
            params.append(f"line_length={self.line_length!r}")
        if self.interface.input:
            params.append(f"input={self.interface.input!r}")
        if self.interface.output:
            params.append(f"output={self.interface.output!r}")
        kwargs = ", ".join(params)
        return f"{self.__class__.__name__}({kwargs})"

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
        if hasattr(other, "idx"):
            if self.idx == other.idx:
                if isinstance(other, (Acl, Ace)):
                    return str(self) < str(other)
                return False
            return self.idx < other.idx
        return False

    # ============================= init =============================

    def _convert_any_to_acl(self, items: Any) -> LUAcl:
        """Convert str, Ace, Remark, List[str], List[Ace], List[AceGroup]  to objects.
        Example1:
            :param items: ["remark text",
                           "permit icmp any any",
                           "deny ip any any"]
            :return: [Remark("remark text"),
                      Ace("permit ip any any"),
                      Ace("deny ip any any")]
        Example2:
            :param items: [AceGroup("remark text\npermit icmp any any"),
                           Ace("deny ip any any")]
            :return: [AceGroup("remark text\npermit icmp any any"),
                      Ace("deny ip any any")]
        """
        if isinstance(items, (str, Ace, Remark, AceGroup)):
            items = [items]
        if not isinstance(items, list):
            raise TypeError(f"{items=} {list} expected")

        items_: LUAcl = []  # return
        for item in items:
            if isinstance(item, str):
                item = self._convert_str_to_ace(item)
            if isinstance(item, (Ace, Remark, AceGroup)):
                self._check_platform(item)
                self._check_line_length(item)
            else:
                raise TypeError(f"{item=} {str} {Ace} {Remark} {AceGroup} expected")
            items_.append(item)
        return items_

    # =========================== property ===========================

    @property
    def name(self) -> str:
        """ACL name"""
        return self._name

    @name.setter
    def name(self, name: str) -> None:
        """ACL name.
        - length <= 100 chars,
        - first char is ascii_letters,
        - other chars are ascii_letters and punctuation,
        """
        if name is None:
            name = ""
        if not isinstance(name, str):
            raise TypeError(f"acl {name=} {str} expected")
        name = name.strip()
        if not 0 <= len(name) <= self.line_length:
            raise ValueError(f"acl name length={len(name)}, expected < {self.line_length}")
        if not name:
            self._name = ""
            return
        first_char = name[0]
        if first_char not in ascii_letters:
            raise ValueError(f"acl name {first_char=}, expected={ascii_letters}")
        skip_chas = {"?"}
        valid_chars = set(ascii_letters + digits + punctuation).difference(skip_chas)
        if invalid_chars := set(name).difference(valid_chars):
            raise ValueError(f"acl name {invalid_chars=}")
        self._name = name

    @name.deleter
    def name(self) -> None:
        self._name = ""

    @property
    def indent(self) -> str:
        """ACL indent"""
        return self._indent

    @indent.setter
    def indent(self, indent: int) -> None:
        """ACE lines indentation, Be default 2 spaces"""
        if indent is None:
            indent = INDENTATION
        if not isinstance(indent, int):
            raise TypeError(f"acl {indent=} {int} expected")
        if indent < 0:
            raise ValueError(f"invalid {indent=}")
        self._indent = " " * indent

    @indent.deleter
    def indent(self) -> None:
        self._indent = " " * INDENTATION

    @property
    def ip_acl_name(self) -> str:
        """Return platform depended ip access-list name line.
        Example1:
            self.platform: "ios"
            :return: "ip access-list extended NAME"
        Example2:
            self.platform: "cnx"
            :return: "ip access-list NAME"
        """
        items = ["ip access-list"]
        if self.platform == "ios":
            items.append("extended")
        items.append(self.name)
        return " ".join(items)

    @property  # type:ignore
    def items(self) -> LUAcl:
        """List of Acl objects"""
        return self._items

    @items.setter
    def items(self, items: LUAcl) -> None:
        items_: LUAcl = []
        for item in items:
            if isinstance(item, (Ace, Remark, AceGroup)):
                items_.append(item)
                continue
            raise TypeError(f"{item=} {Ace} {Remark} {AceGroup} expected")
        self._items = items_

    @items.deleter
    def items(self) -> None:
        self._items = []

    @property
    def line(self) -> str:
        """ACEs in string format"""
        items = []
        for item in self.items:
            if isinstance(item, AceGroup):
                for item_ in item:
                    items.append(item_)
                continue
            items.append(item)
        ace = "\n".join([f"{self.indent}{o}" for o in items])
        return "\n".join([self.ip_acl_name, ace])

    @line.setter
    def line(self, line: str) -> None:
        items = h.lines_wo_spaces(line)
        if not items:
            self.name = ""
            self.items = []
            return

        name = ""
        first_line = items[0]
        if re.match("ip access-list", first_line):
            ip_acl_name, *items = items
            regex = r"^ip access-list (\S+)"
            if self.platform == "ios":
                regex = r"^ip access-list extended (\S+)"
            name = h.re_find_s(regex, ip_acl_name)

        aces: LUAcl = [self._convert_str_to_ace(s) for s in items]
        self.name = name
        self.items = aces

    @line.deleter
    def line(self) -> None:
        self.name = ""
        self.items = []

    # =========================== methods ============================

    def copy(self) -> Acl:
        """Copy Acl"""
        acl = Acl(
            name=self.name,
            items=self.items.copy(),
            platform=self.platform,
            note=self.note,
            line_length=self.line_length,
            input=self.interface.input.copy(),
            output=self.interface.output.copy(),
        )
        return acl

    def resequence(self, start: int = 10, step: int = 10, **kwargs) -> int:
        """Resequence all entries in an ACL.
        :param start: Starting sequence number.
        :param step: Step to increment the sequence number.
        :param kwargs:
            items: List of Ace objects. By default self.items.
        :return: Last sequence number.
        """
        if not 1 <= start <= IDX_MAX:
            raise ValueError(f"{start=} expected=1..{IDX_MAX}")
        if step < 1:
            raise ValueError(f"{step=} expected >= 1")
        items: LUAcl = kwargs.get("items") or self.items
        idx = start
        count = len(items)
        for id_, item in enumerate(items, start=1):
            if isinstance(item, AceGroup):
                idx = self.resequence(start=idx, step=step, items=item)
            item.idx = idx
            if id_ < count:
                idx += step
        if idx > IDX_MAX:
            raise ValueError(f"last {idx=} expected=1..{IDX_MAX}")
        return idx

    def sort(self) -> None:
        """Sort Ace objects in self.items"""
        self.items = sorted(self.items)


LAcl = List[Acl]
