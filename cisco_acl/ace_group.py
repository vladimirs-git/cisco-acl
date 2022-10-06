"""Group of ACE (Access Control Entry).
These are multiple ACEe items, which must be in a certain order.
If you are changing *Ace* items order (sequence numbers) inside *Acl*,
the AceGroup behaves like a ACE item and order of ACE items inside AceGroup is not changed.
AceGroup is useful for freezing ACEs section, to hold "deny" after certain "permit".
"""
from __future__ import annotations

import logging
from functools import total_ordering
from typing import List, Optional, Union

from cisco_acl import helpers as h
from cisco_acl.ace import Ace, LAce
from cisco_acl.base_ace import BaseAce
from cisco_acl.group import Group
from cisco_acl.remark import Remark, LRemark
from cisco_acl.static import ACTIONS
from cisco_acl.types_ import DAny

UAce = Union[Ace, Remark]
USAce = Union[Ace, Remark, str]

OUAce = Optional[UAce]
LUAce = List[UAce]
LUSAce = List[USAce]

ULAce = Union[LAce, LRemark, LUAce]


@total_ordering
class AceGroup(Group, BaseAce):
    """Group of ACE (Access Control Entry)"""

    def __init__(self, line: str = "", **kwargs):
        """Group of ACE (Access Control Entry)
        :param str line: string of ACEs
        :param str platform: Platform: "ios", "nxos" (default "ios")

        Helpers
        :param str note: Object description
        :param bool protocol_nr: Well-known ip protocols as numbers
            True  - all ip protocols as numbers
            False - well-known ip protocols as names (default)
        :param bool port_nr: Well-known TCP/UDP ports as numbers
            True  - all tcp/udp ports as numbers
            False - well-known tcp/udp ports as names (default)
        :param str group_by: Startswith in remark line. ACEs group, starting from the Remark,
            where line startswith `group_by`, will be applied to the same AceGroup,
            until next Remark that also startswith `group_by`

        Alternate way to get `name` and ACEs `items`, if `line` absent
        :param str type: ACL type: "extended", "standard" (default "extended")
        :param str name: Name of AceGroup, usually Remark.text of 1st self.items
        :param List[Ace] items: An alternate way to create *AceGroup* object from a list of *Ace*
            (default from `line`)

        :example:
            aceg = AceGroup("10 permit icmp any any\n  20 deny ip any any")
            result:
                aceg.line == "10 permit icmp any any\n20 deny ip any any"
                aceg.platform == "ios"
                aceg.note == "description"
                aceg.sequence == 20  # Taking from the first ACE in items.
                aceg.items == [Ace("10 permit icmp any any"), Ace("20 deny ip any any")]
        """
        self._name = ""
        self._group_by = ""
        self._items: LUAce = []
        Group.__init__(self)
        BaseAce.__init__(self, **kwargs)  # platform, type, note, sequence, protocol_nr, port_nr
        if name := kwargs.get("name"):
            self._name = h.init_name(name)
        if group_by := str(kwargs.get("group_by") or ""):
            self._group_by = group_by
        if items := kwargs.get("items") or []:
            self.items = items
            return
        self.line = line

    def __lt__(self, other) -> bool:
        """< less than"""
        if hasattr(other, "sequence"):
            if self._sequence == other.sequence:
                if other.__class__.__name__ == "Remark":
                    return False
                if isinstance(other, Ace):
                    return False
                if isinstance(other, AceGroup):
                    return str(self) < str(other)
                raise TypeError(f"{other=} {AceGroup} expected")
            return self._sequence < other.sequence
        return False

    # =========================== property ===========================

    @property
    def group_by(self) -> str:
        """Groups ACEs to *AceGroup* by startswith ot this value in remarks"""
        return self._group_by

    @property
    def items(self) -> LUAce:
        """List of ACE items: *Ace*, *Remark*, *AceGroup*"""
        return self._items

    @items.setter
    def items(self, items: LUSAce) -> None:
        if isinstance(items, (str, Ace, Remark)):
            items = [items]
        if not isinstance(items, (list, tuple)):
            raise TypeError(f"{items=} {list} expected")

        _items: LUAce = []  # result
        for item in items:
            if isinstance(item, (Ace, Remark)):
                item._platform = self._platform
                item._type = self._type
                _items.append(item)
            elif isinstance(item, dict):
                ace_o: UAce = self._dict_to_ace(**item)
                _items.append(ace_o)
            elif isinstance(item, str):
                line = h.init_line(item)
                item_ = self._line_to_ace(line)
                _items.append(item_)
            else:
                raise TypeError(f"{item=} {str} expected")
        self._items = _items

    @property
    def line(self) -> str:
        """Group of ACL config line"""
        lines = [getattr(o, "line") for o in self._items]
        return "\n".join(lines)

    @line.setter
    def line(self, line: str) -> None:
        lines = line.split("\n")
        lines = [h.init_line(s) for s in lines]
        items_ = [self._line_to_oace(s, warning=True) for s in lines]
        items: LUAce = [o for o in items_ if isinstance(o, (Ace, Remark))]
        self.items = items
        sequence = self._items[0].sequence if self._items else 0
        self.sequence = sequence

    @property
    def name(self) -> str:
        """Acl/AceGroup name"""
        return self._name

    @name.setter
    def name(self, name: str) -> None:
        """Acl/AceGroup name, without "ip access-list "
        Requirements:
        - length <= 100 chars
        - all chars are digits
        - first char is ascii_letters, other chars are ascii_letters and punctuation
        """
        self._name = h.init_name(name)

    @property
    def platform(self) -> str:
        """Platform
        - "ios" Cisco IOS (extended ACL)
        - "nxos" Cisco Nexus NX-OS
        """
        return self._platform

    @platform.setter
    def platform(self, platform: str) -> None:
        """Changes platform, normalizes self.items regarding the new platform
        :param str platform: Platform: "ios", "nxos" (default "ios")
        """
        self._platform = h.init_platform(platform=platform)
        _items = []
        for item in self._items:
            item.type = self._type
            if self._platform == "nxos":
                self.ungroup_ports()
            item.platform = self._platform
            _items.append(item)
        self._items = _items
        self.line = self.line

    @property
    def type(self) -> str:
        """ACL type: standard, extended"""
        return self._type

    @type.setter
    def type(self, type_: str) -> None:
        type_ = h.init_type(type=type_, platform=self.platform)
        for item in self._items:
            item.type = type_
        self._type = type_
        self.line = self.line

    # =========================== methods ============================

    def copy(self) -> AceGroup:
        """Copies the self object"""
        kwargs = self.data()
        return AceGroup(**kwargs)

    def data(self) -> DAny:
        """Converts *AceGroup* object to *dict*
        :return: data in *dict* format
        """
        data = dict(
            # init
            line=self.line,
            platform=self._platform,
            type=self._type,
            name=self._name,
            items=[o.data() for o in self._items],
            group_by=self._group_by,
            note=self.note,
            protocol_nr=self._protocol_nr,
            port_nr=self._port_nr,
            # property
            sequence=self._sequence,
        )
        return data

    def delete_note(self) -> None:
        """Deletes note in all children self.items: Ace, AceGroup, Remark"""
        self.note = ""
        for item in self._items:
            item.note = ""
            if isinstance(item, AceGroup):
                item.delete_note()

    # noinspection PyIncorrectDocstring
    @h.check_start_step_sequence
    def resequence(self, start: int = 10, step: int = 10, **kwargs) -> int:
        """Resequence all AceGroup.items and change sequence numbers
        :param start: Starting sequence number. start=0 - delete all sequence numbers
        :param step: Step to increment the sequence number
        :param items: List of Ace objects (default self.items)
        :return: Last sequence number
        """
        items: LUAce = kwargs.get("items") or self._items
        sequence: int = int(start)
        count = len(items)

        for id_, item in enumerate(items, start=1):
            if isinstance(item, AceGroup):
                params = dict(items=item)
                sequence = self.resequence(start=sequence, step=step, **params)
            item.sequence = sequence
            if id_ < count:
                sequence += step
        return sequence

    def ungroup_ports(self) -> None:
        """Ungroups ACEs with multiple ports in single line ("eq" or "neq")
        to multiple lines with single port
        :example:
            aceg = AceGroup("permit tcp any eq 1 2 any eq 3 4")
            aceg.split_ports()
            aceg.line -> "permit tcp any eq 1 any eq 3
                          permit tcp any eq 1 any eq 4
                          permit tcp any eq 2 any eq 3
                          permit tcp any eq 2 any eq 4"
        """
        _items: LUAce = []
        for ace_o in self._items:
            if isinstance(ace_o, Ace):
                aces: LAce = ace_o.ungroup_ports()
                _items.extend(aces)
                continue
            _items.append(ace_o)
        self.items = _items

    # =========================== helpers ============================

    def _dict_to_ace(self, **kwargs) -> UAce:
        """Converts *dict* data to object: *Ace*, *Remark*
        :param kwargs: ACE data
        :return: ACE object: *Ace* or *Remark*

        :example: permit
            data: {line="permit ip any any"}
            return: Ace("permit ip any any")

        :example: remark
            data: {line="remark text"}
            return: Remark("text")
        """
        action = kwargs.get("action")
        if action not in ACTIONS:
            raise ValueError(f"invalid action in {kwargs=}, expected {ACTIONS=}")
        kwargs["platform"] = self._platform
        kwargs["type"] = self._type
        kwargs["protocol_nr"] = self._protocol_nr
        kwargs["port_nr"] = self._port_nr
        if action in ["remark"]:
            return Remark(**kwargs)
        return Ace(**kwargs)

    def _dict_to_aceg(self, **kwargs) -> UAceg:
        """Converts *dict* data to object: *AceGroup*, *Ace*, *Remark*
        :param kwargs: ACE data
        :return: ACE object: *AceGroup*, *Ace*, *Remark*"""
        items = kwargs.get("items")
        if isinstance(items, (list, tuple)):
            kwargs["platform"] = self._platform
            kwargs["type"] = self._type
            kwargs["protocol_nr"] = self._protocol_nr
            kwargs["port_nr"] = self._port_nr
            return AceGroup(**kwargs)
        return self._dict_to_ace(**kwargs)

    def _line_to_ace(self, line: str) -> UAce:
        """Converts config line to object: *Ace*, *Remark*
        :param line: ACE line
        :return: ACE object: *Ace* or *Remark*

        :example: permit
            line: "permit ip any any"
            return: Ace("permit ip any any")

        :example: remark
            line: "remark text"
            return: Remark("text")

        :example: not ACE line
            line: "text"
            return: None
        """
        action = h.parse_action(line)["action"]
        if action in ["remark"]:
            return Remark(line, platform=self._platform, type=self._type)
        ace_o = Ace(line=line,
                    platform=self._platform,
                    type=self._type,
                    protocol_nr=self._protocol_nr,
                    port_nr=self._port_nr)
        return ace_o

    def _line_to_oace(self, line: str, warning: bool = False) -> OUAce:
        """Converts config line to object: *Ace*, *Remark*, None"""
        skip = ["", "statistics per-entry"]
        if line in skip:
            return None
        try:
            ace_o = self._line_to_ace(line)
        except ValueError:
            if warning:
                msg = f"{line=} does not match ACE pattern"
                logging.warning(msg)
            ace_o = None
        return ace_o


# ============================= helpers ==============================


LAceGroup = List[AceGroup]
UAceg = Union[Ace, Remark, AceGroup]
LUAceg = List[UAceg]
