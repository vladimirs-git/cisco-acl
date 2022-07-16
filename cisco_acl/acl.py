"""ACL (Access Control List)"""
from __future__ import annotations

import re
from functools import total_ordering
from typing import List

from cisco_acl import helpers as h
from cisco_acl.ace import Ace
from cisco_acl.ace_group import AceGroup, LUAcl
from cisco_acl.interface import Interface
from cisco_acl.port import Port
from cisco_acl.remark import Remark
from cisco_acl.static import (
    SEQUENCE_MAX,
    DEFAULT_PLATFORM,
    INDENTATION,
)


@total_ordering
class Acl(AceGroup):
    """ACL (Access Control List)"""

    def __init__(self, line: str = "", **kwargs):
        """ACL (Access Control List)
        :param str line: ACL config (name and following remarks and access entries)
        :param str platform: Supported platforms: "ios", "nxos" (default "ios")
        :param bool numerically: Cisco ACL outputs well-known tcp/udp ports as names
            True  - all tcp/udp ports as numbers
            False - well-known tcp/udp ports as names (default)
        :param str name: ACL name. By default, parsed from line
        :param items: List of ACE (strings or Ace, AceGroup, Remark objects)
                By default, parsed from line
        :param str input: Interfaces, where Acl is used on input
        :param str output: Interfaces, where Acl is used on output
        :param str indent: ACE lines indentation. By default, 2 spaces
        :param str note: Object description. Not part of the ACL configuration,
            can be used for ACEs sorting

        :example:
            line: "ip access-list extended NAME
                     remark TEXT
                     permit icmp any any"
            platform: "ios"
            input: "interface FastEthernet1"
            indent: 4
            note: "allow icmp"
            result:
                self.line = "ip access-list extended NAME\n  remark TEXT\n  permit icmp any any"
                self.platform = "ios"
                self.name = "NAME"
                self.items = [Remark("remark TEXT"), Ace("permit icmp any any")]
                self.ip_acl_name = "ip access-list NAME"
                self.interface.input = ["interface FastEthernet1"]
                self.interface.output = []
                self.indent = "    "
                self.note = "allow icmp"
        """
        super().__init__(**kwargs)
        self.line = line
        if not line:
            self.name = kwargs.get("name") or ""
            self.items = kwargs.get("items") or []
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
        if hasattr(other, "sequence"):
            if self.sequence == other.sequence:
                if isinstance(other, (Acl, Ace)):
                    return str(self) < str(other)
                return False
            return self.sequence < other.sequence
        return False

    # =========================== property ===========================

    @property
    def line(self) -> str:
        """ACE lines in string format"""
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

        aces_ = [self._line_to_ace(s) for s in items]
        aces: LUAcl = [o for o in aces_ if isinstance(o, (Ace, Remark))]
        self.name = name
        self.items = aces

    @line.deleter
    def line(self) -> None:
        self.name = ""
        self.items = []

    @property
    def indent(self) -> str:
        """ACE lines indentation"""
        return self._indent

    @indent.setter
    def indent(self, indent: int) -> None:
        """ACE lines indentation, By default 2 spaces"""
        if indent is None:
            indent = INDENTATION
        if not isinstance(indent, int):
            raise TypeError(f"acl {indent=} {int} expected")
        if indent < 0:
            raise ValueError(f"invalid {indent=}")
        self._indent = " " * indent

    @indent.deleter
    def indent(self) -> None:
        self._indent = ""

    @property
    def ip_acl_name(self) -> str:
        """Platform dependent Acl line with name
        :return: Acl line with name

        :example:
            self.platform: "ios"
            return: "ip access-list extended NAME"

        :example:
            self.platform: "nxos"
            return: "ip access-list NAME"
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
                if self.platform != item.platform:
                    platform = item.platform
                    expected = self.platform
                    raise ValueError(f"invalid {platform=} in {item=}, {expected=}")
                items_.append(item)
                continue
            raise TypeError(f"{item=} {Ace} {Remark} {AceGroup} expected")
        self._items = items_

    @items.deleter
    def items(self) -> None:
        self._items = []

    @property
    def name(self) -> str:
        """ACL name"""
        return self._name

    @name.setter
    def name(self, name: str) -> None:
        """ACL name. Requirements:
        - length <= 100 chars
        - first char is ascii_letters
        - other chars are ascii_letters and punctuation
        """
        if name is None:
            name = ""
        if not isinstance(name, str):
            raise TypeError(f"acl {name=} {str} expected")
        name = name.strip()
        if not name:
            self._name = ""
            return
        h.check_line_length(name)
        h.check_name(name)
        self._name = name

    @name.deleter
    def name(self) -> None:
        self._name = ""

    @property
    def platform(self) -> str:
        """Platform
        - "ios" - Cisco IOS (extended ACL)
        - "nxos" Cisco Nexus NX-OS
        """
        return self._platform

    @platform.setter
    def platform(self, platform: str):
        platform = self._init_platform(platform=platform)
        if platform == self.platform:
            return

        if platform == "nxos":
            self._split_aces_by_ports(attr="srcport")
            self._split_aces_by_ports(attr="dstport")
        self._platform = platform
        for item in self.items:
            item.platform = platform

    def _split_aces_by_ports(self, attr: str) -> None:
        """NXOS. Split Aces with multiple ports in single line to multiple lines
        :param attr: "srcport", "dstport"

        :example:
            self.items = [Ace("permit tcp any eq 1 2 any eq 3 4")]
            result:
                self.items = [Ace("permit tcp any eq 1 any eq 3"),
                              Ace("permit tcp any eq 1 any eq 3"),
                              Ace("permit tcp any eq 2 any eq 4"),
                              Ace("permit tcp any eq 2 any eq 4")]
        """
        items_: LUAcl = []  # return
        for ace_o in self.items:
            if isinstance(ace_o, Ace):
                port_o: Port = getattr(ace_o, attr)
                if port_o.operator in ["eq", "neq"]:
                    for port in port_o.items:
                        ace_o_ = ace_o.copy()
                        port_o_: Port = getattr(ace_o_, attr)
                        port_o_.items = [port]
                        items_.append(ace_o_)
                    continue
            items_.append(ace_o)
        self.items = items_

    # =========================== methods ============================

    def copy(self) -> Acl:
        """Copies the self object with the Ace elements copied
        :return: A shallow copy of self
        """
        acl = Acl(
            name=self.name,
            items=[o.copy() for o in self.items],
            platform=self.platform,
            note=self.note,
            input=self.interface.input.copy(),
            output=self.interface.output.copy(),
        )
        return acl

    # noinspection PyIncorrectDocstring
    def resequence(self, start: int = 10, step: int = 10, **kwargs) -> int:
        """Resequences all Acl.items and change sequence numbers
        :param start: Starting sequence number. start=0 - delete all sequence numbers
        :param step: Step to increment the sequence number
        :param items: List of Ace objects. By default, self.items
        :return: Last sequence number
        """
        if not 0 <= start <= SEQUENCE_MAX:
            raise ValueError(f"{start=} expected=0..{SEQUENCE_MAX}")
        if start and step < 1:
            raise ValueError(f"{step=} expected >= 1")
        if not start:
            step = 0
        items: LUAcl = kwargs.get("items") or self.items
        sequence: int = int(start)
        count = len(items)

        for id_, item in enumerate(items, start=1):
            if isinstance(item, AceGroup):
                sequence = self.resequence(start=sequence, step=step, items=item)
            item.sequence.number = sequence
            if id_ < count:
                sequence += step
        if sequence > SEQUENCE_MAX:
            raise ValueError(f"last {sequence=} expected=1..{SEQUENCE_MAX}")
        return sequence


LAcl = List[Acl]
