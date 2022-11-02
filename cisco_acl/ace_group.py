"""Group of ACE (Access Control Entry).
These are multiple ACEe items, which must be in a certain order.
If you are changing *Ace* items order (sequence numbers) inside *Acl*,
the AceGroup behaves like a single item and order of ACE items inside AceGroup is not changed.
AceGroup is useful for freezing ACEs section, to hold "deny" after certain "permit".
This class implements most of the Python list methods: append(), extend(), sort(), etc.
"""
from __future__ import annotations

import logging
from functools import total_ordering
from ipaddress import NetmaskValueError
from typing import List, Optional, Union

from cisco_acl import helpers as h
from cisco_acl.ace import Ace, LAce
from cisco_acl.ace_base import AceBase
from cisco_acl.group import Group
from cisco_acl.helpers import ACTIONS
from cisco_acl.remark import Remark, LRemark
from cisco_acl.types_ import DAny
from cisco_acl.wildcard import init_max_ncwb

UAce = Union[Ace, Remark]
USAce = Union[Ace, Remark, str]

OUAce = Optional[UAce]
LUAce = List[UAce]
LUSAce = List[USAce]

ULAce = Union[LAce, LRemark, LUAce]


@total_ordering
class AceGroup(AceBase, Group):
    """Group of ACE (Access Control Entry)"""

    def __init__(self, line: str = "", **kwargs):
        """Group of ACE (Access Control Entry).
        This class implements most of the Python list methods: append(), extend(), sort(), etc.
        :param line: String of ACEs, lines that starts with "allow", "deny", "remark".
        :type line: str

        :param platform: Platform: "ios" (default), "nxos"
        :type platform: str

        Helpers
        :param note: Object description
        :type note: Any

        :param max_ncwb: Max count of non-contiguous wildcard bits
        :type max_ncwb: int

        :param protocol_nr: Well-known ip protocols as numbers
            True  - all ip protocols as numbers
            False - well-known ip protocols as names (default)
        :type protocol_nr: bool

        :param port_nr: Well-known TCP/UDP ports as numbers
            True  - all tcp/udp ports as numbers
            False - well-known tcp/udp ports as names (default)
        :type port_nr: bool

        :param group_by: Startswith in remark line. ACEs group, starting from the Remark,
            where line startswith `group_by`, will be applied to the same AceGroup,
            until next Remark that also startswith `group_by`
        :type group_by: str

        Alternate way to get `name` and ACEs `items`, if `line` absent
        :param str type: ACL type: "extended", "standard" (default "extended")

        :param name: Name of AceGroup, usually Remark.text of 1st self.items
        :type name: str

        :param items: An alternate way to create *AceGroup* object from a list of *Ace*
            (default from `line`)
        :type items: List[Union[Ace, Remark, str]]

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
        AceBase.__init__(self, **kwargs)  # platform, type, note, sequence, protocol_nr, port_nr
        Group.__init__(self)
        if name := kwargs.get("name"):
            self._name = h.init_name(name)
        if group_by := str(kwargs.get("group_by") or ""):
            self._group_by = group_by
        # noinspection PyProtectedMember
        self.max_ncwb: int = init_max_ncwb(**kwargs)
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
        lines = [o.line for o in self._items]
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
        :param platform: Platform: "ios" (default), "nxos"
        """
        self._platform = h.init_platform(platform=platform)

        for item in self._items:
            item.type = self._type
            if self._platform == "nxos":
                self.ungroup_ports()
            item.platform = self._platform

        data = self.data(uuid=True)
        self.__init__(**data)  # type: ignore

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

        data = self.data(uuid=True)
        self.__init__(**data)  # type: ignore

    # =========================== methods ============================

    def data(self, uuid: bool = False) -> DAny:
        """Converts *AceGroup* object to *dict*
        :param uuid: Returns self.uuid in data
        :type uuid: bool

        :return: data in *dict* format
        """
        data = dict(
            # init
            line=self.line,
            platform=self._platform,
            type=self._type,
            name=self._name,
            items=[o.data(uuid=uuid) for o in self._items],
            group_by=self._group_by,
            note=self.note,
            protocol_nr=self._protocol_nr,
            port_nr=self._port_nr,
            # property
            sequence=self._sequence,
        )
        if uuid:
            data["uuid"] = self.uuid
        return data

    def delete_note(self) -> None:
        """Deletes note in all children self.items: Ace, AceGroup, Remark"""
        self.note = ""
        for item in self._items:
            item.note = ""
            if isinstance(item, AceGroup):
                item.delete_note()

    def get_remark_name(self) -> str:
        """Returns Rule name from 1st remark"""
        remark = self.get_remark()
        name = h.parse_remark_name(text=remark.text, group_by=self.group_by)
        return name

    def get_remark(self) -> Remark:
        """Returns 1st remark with Rule name"""
        remark = self.items[0]
        if not isinstance(remark, Remark):
            raise TypeError(f"{remark=} {Remark} expected")
        return remark

    def tcam_count(self) -> int:
        """Calculates sum of ACEs. Also takes into account the addresses in the address group.
        Useful for getting an estimate of the amount of TCAM resources needed for this ACL
        :return: Count of TCAM resources
        """
        counter = 0
        for item in self.items:
            if isinstance(item, AceGroup):
                counter += item.tcam_count()
                continue
            if not isinstance(item, Ace):
                continue
            if "addrgroup" not in [item.srcaddr.type, item.dstaddr.type]:
                counter += 1
                continue
            src_counter = 1
            if item.srcaddr.type == "addrgroup":
                src_counter = len(item.srcaddr.items) or 1
            dst_counter = 1
            if item.dstaddr.type == "addrgroup":
                dst_counter = len(item.dstaddr.items) or 1
            counter += src_counter * dst_counter
        return counter

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
                params = dict(items=item.items)
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
                    port_nr=self._port_nr,
                    max_ncwb=self.max_ncwb)
        return ace_o

    def _line_to_oace(self, line: str, warning: bool = False) -> OUAce:
        """Converts config line to object: *Ace*, *Remark*, None"""
        if not line:
            return None

        if h.is_line_for_acl(line):
            try:
                ace_o: UAce = self._line_to_ace(line)
            except NetmaskValueError:
                raise
            except ValueError as ex:
                if warning:
                    msg = f"{type(ex).__name__}: {ex}. {line=} does not match ACE pattern"
                    logging.warning(msg)
                return None
            return ace_o

        known_skip = ["statistics ", "description ", "ignore "]
        for skip in known_skip:
            if line.startswith(skip):
                return None

        if warning:
            msg = f"{line=} does not match ACE pattern"
            logging.warning(msg)
        return None


LAceGroup = List[AceGroup]
UAceg = Union[Ace, Remark, AceGroup]
LUAceg = List[UAceg]
