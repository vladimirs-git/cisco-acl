"""ACL - Access Control List.

This class implements most of the Python list methods: append(), extend(), sort(), etc.
"""

from __future__ import annotations

from functools import total_ordering
from typing import Dict, Generator, List, Union

from cisco_acl import helpers as h
from cisco_acl.ace import Ace, LAce
from cisco_acl.ace_group import AceGroup, UAceg, UAce, LUAceg, OUAce, LUAce
from cisco_acl.helpers import DEF_INDENT
from cisco_acl.remark import Remark
from cisco_acl.types_ import LStr, UStr, DAny, DLStr, SStr, T2Str, OLStr


@total_ordering
class Acl(AceGroup):
    """ACL - Access Control List."""

    def __init__(self, line: str = "", **kwargs):
        r"""Init Acl.

        Support lines that starts with "allow", "deny", "remark".

        :param line: ACL config, "show running-config" output
        :type line: str

        :param platform: Platform: "asa", "ios", "nxos". Default "ios".
        :type platform: str

        :param version: Software version, default is "0".
        :type version: str

        :param input: Interfaces, where Acl is used on input.
        :type input: str

        :param output: Interfaces, where Acl is used on output.
        :type output: str

        Helpers
        :param note: Object description.
        :type note: Any

        :param max_ncwb: Max count of non-contiguous wildcard bits.
        :type max_ncwb: int

        :param indent: ACE lines indentation (default "  ").
        :type indent: str

        :param protocol_nr: Well-known ip protocols as numbers.
            True  - all ip protocols as numbers,
            False - well-known ip protocols as names (default).
        :type protocol_nr: bool

        :param port_nr: Well-known TCP/UDP ports as numbers.
            True  - all tcp/udp ports as numbers,
            False - well-known tcp/udp ports as names (default).
        :type port_nr: bool

        :param group_by: Startswith in remark line. ACEs group, starting from the Remark,
            where line startswith `group_by`, will be applied to the same AceGroup,
            until next Remark that also startswith `group_by`.
        :type group_by: str

        Alternate way to get `name` and ACEs `items`, if `line` absent
        :param str type: ACL type: "extended", "standard" (default from `line`)

        :param name: ACL name (default from `line`).
        :type name: str

        :param items: ACEs items: string, Ace, AceGroup, Remark objects
            (default from `line`).
        :type items: List[Union[List[str], dict, List[Dict], Ace, Remark, AceGroup]]

        :example:
            acl = Acl(line="ip access-list extended NAME\nremark TEXT\npermit icmp any any"),
                      platform="ios",
                      input="interface FastEthernet1",
                      indent=" ")

            acl.line -> "ip access-list extended NAME\n remark TEXT\n permit icmp any any"
            acl.platform -> "ios"
            acl.name -> "NAME"
            acl.items -> [Remark("remark TEXT"), Ace("permit icmp any any")]
            acl.input -> ["interface FastEthernet1"]
            acl.output -> []
            acl.indent -> " "
        """
        self._items: LUAceg = []  # type: ignore
        items = kwargs.get("items") or []
        if "items" in kwargs:
            del kwargs["items"]

        self._indent: str = h.init_indent(**kwargs)
        self.input: LStr = kwargs.get("input") or []
        self.output: LStr = kwargs.get("output") or []
        super().__init__(**kwargs)  # name, group_by, items, max_ncwb

        if name := str(kwargs.get("name") or ""):
            self.name = name
        if _type := str(kwargs.get("type") or ""):
            self._type = h.init_type(type=_type, platform=self._platform)
        if items:
            self.items = items
            return
        self.line = line

    def __hash__(self) -> int:
        """__hash__."""
        return self.line.__hash__()

    def __eq__(self, other) -> bool:
        """== equality."""
        if self.__class__ == other.__class__:
            if self.__hash__() == other.__hash__():
                return True
        return False

    def __lt__(self, other) -> bool:
        """< less than."""
        if hasattr(other, "sequence"):
            if self._sequence == other.sequence:
                if isinstance(other, (Acl, Ace)):
                    return str(self) < str(other)
                return False
            return self._sequence < other.sequence
        return False

    def __repr__(self):
        """__repr__."""
        params = self._repr__params()
        params = self._repr__add_param("input", params)
        params = self._repr__add_param("output", params)
        if self._indent != DEF_INDENT:
            params = self._repr__add_param("indent", params)
        params = self._repr__add_param("protocol_nr", params)
        params = self._repr__add_param("port_nr", params)
        kwargs = ", ".join(params)
        name = self.__class__.__name__
        return f"{name}({kwargs})"

    # =========================== property ===========================

    @property
    def indent(self) -> str:
        """ACE lines indentation (default "  ")."""
        return self._indent

    @indent.setter
    def indent(self, indent: str) -> None:
        if indent is None:
            indent = DEF_INDENT
        self._indent = str(indent)

    @property
    def input(self) -> LStr:
        """Interface where Acl is used on input."""
        return self._input

    @input.setter
    def input(self, items: UStr) -> None:
        _items: LStr = h.convert_to_lstr(items=items)
        self._input = sorted(_items)

    @property  # type: ignore
    def items(self) -> LUAceg:  # type: ignore
        """List of ACE items: Ace, Remark, AceGroup."""
        return self._items

    @items.setter
    def items(self, items: LUAces) -> None:
        if isinstance(items, (str, dict, Ace, Remark, AceGroup)):
            items = [items]
        if not isinstance(items, (list, tuple, Generator)):
            raise TypeError(f"{items=} {list} expected")

        # items
        _items: LUAceg = []
        for item in items:
            # object
            if isinstance(item, (Ace, Remark, AceGroup)):
                item._platform = self._platform
                item.version = self.version
                item._type = self._type
                _items.append(item)
            # dict
            elif isinstance(item, dict):
                item["platform"] = self._platform
                item["version"] = str(self.version)
                aceg_o: UAceg = self._dict_to_aceg(**item)
                _items.append(aceg_o)
            # str
            elif isinstance(item, str):
                line = h.init_line(item)
                ace_o: UAce = self._line_to_ace(line)
                _items.append(ace_o)
            else:
                raise TypeError(f"{item=} {str} expected")
        self._items = _items

        if self._group_by:
            self.group(group_by=self._group_by)

    @property
    def line(self) -> str:
        """ACL config line."""
        items = []
        for item in self._items:
            if isinstance(item, AceGroup):
                for item_ in item.items:
                    items.append(item_)
                continue
            items.append(item)
        ace = "\n".join([f"{self._indent}{o}" for o in items])
        _line = "\n".join([self._cfg_acl_name(), ace])
        return _line

    @line.setter
    def line(self, line: str) -> None:
        items = h.lines_wo_spaces(line)
        if not items:
            return

        item1, *items = items
        acl_type, acl_name = self._parse_type_name(item1)
        self._type = acl_type
        self._name = acl_name

        aces: LUAceg = []
        for item in items:
            ace_o: OUAce = self._line_to_oace(line=item, warning=True)
            if isinstance(ace_o, (Ace, Remark)):
                aces.append(ace_o)
        self.items = aces

    @property
    def output(self) -> LStr:
        """Interfaces, where Acl is used on output."""
        return self._output

    @output.setter
    def output(self, items: UStr) -> None:
        _items: LStr = h.convert_to_lstr(items=items)
        self._output = sorted(_items)

    @property
    def platform(self) -> str:
        """Platform: Platform: "asa", "ios", "nxos"."""
        return self._platform

    @platform.setter
    def platform(self, platform: str) -> None:
        platform = h.init_platform(platform=platform)
        if platform == "nxos":
            self.ungroup_ports()
        self._platform = platform
        for item in self._items:
            item.platform = self._platform

    # =========================== method =============================

    def data(self, uuid: bool = False) -> DAny:
        r"""Convert Acl object to the dictionary.

        :param uuid: Return self.uuid in data.
        :type uuid: bool

        :return: The dictionary.

        :example:
        acl = Acl("ip access-list extended NAME\n"
                  "  10 permit tcp host 10.0.0.1 10.0.0.0 0.0.0.3 eq www 443 log")
        acl.data -> {
            "line": "ip access-list extended NAME\n"
                    "  10 permit tcp host 10.0.0.1 10.0.0.0 0.0.0.3 eq www 443 log",
            "platform": "ios",
            "name": "NAME",
            "items": [
                {"line": "10 permit tcp host 10.0.0.1 10.0.0.0 0.0.0.3 eq www 443 log",
                 "platform": "ios",
                 "version": "0",
                 "note": "",
                 "protocol_nr": False,
                 "port_nr": False,
                 "sequence": 10,
                 "action": "permit",
                 "protocol": {"line": "tcp",
                              "platform": "ios",
                              "version": "0",
                              "note": "",
                              "protocol_nr": False,
                              "has_port": True,
                              "name": "tcp",
                              "number": 6},
                 "srcaddr": {"line": "host 10.0.0.1",
                             "platform": "ios",
                             "version": "0",
                             "note": "",
                             "items": [],
                             "addrgroup": "",
                             "ipnet": IPv4Network("10.0.0.1/32"),
                             "prefix": "10.0.0.1/32",
                             "subnet": "10.0.0.1 255.255.255.255",
                             "wildcard": "10.0.0.1 0.0.0.0"},
                 "srcport": {"line": "",
                             "platform": "ios",
                             "version": "0",
                             "note": "",
                             "protocol": "",
                             "port_nr": False,
                             "items": [],
                             "operator": "",
                             "ports": [],
                             "sport": ""},
                 "dstaddr": {"line": "10.0.0.0 0.0.0.3",
                             "platform": "ios",
                             "version": "0",
                             "note": "",
                             "items": [],
                             "addrgroup": "",
                             "ipnet": IPv4Network("10.0.0.0/30"),
                             "prefix": "10.0.0.0/30",
                             "subnet": "10.0.0.0 255.255.255.252",
                             "wildcard": "10.0.0.0 0.0.0.3"},
                 "dstport": {"line": "eq www 443",
                             "platform": "ios",
                             "version": "0",
                             "note": "",
                             "protocol": "tcp",
                             "port_nr": False,
                             "items": [80, 443],
                             "operator": "eq",
                             "ports": [80, 443],
                             "sport": "80,443"},
                 "option": "log"}
            ],
            "input": ["interface Ethernet1"],
            "output": ["interface Ethernet2"],
            "group_by": "",
            "note": "",
            "indent": "  ",
            "protocol_nr": False,
            "port_nr": False,
        }
        """
        data = dict(
            # init
            line=self.line,
            platform=self._platform,
            version=str(self.version),
            type=self._type,
            input=self._input.copy(),
            output=self._output.copy(),
            name=self._name,
            items=[o.data(uuid=uuid) for o in self._items],
            group_by=self._group_by,
            note=self.note,
            max_ncwb=self.max_ncwb,
            indent=self._indent,
            protocol_nr=self._protocol_nr,
            port_nr=self._port_nr,
        )
        if uuid:
            data["uuid"] = self.uuid
        return data

    def group(self, group_by: str) -> None:
        """Group ACEs to AceGroup by `group_by` startswith in remarks.

        :param group_by: Startswith in remark line. ACEs group, starting from the Remark,
            where line startswith `group_by`, will be applied to the same AceGroup,
            until next Remark that also startswith `group_by`.
        :type group_by: str

        :example:
        group_by: "=== "
        self.items: [Remark("=== NAME1"),
                     Ace("permit tcp any any"),
                     Remark("=== NAME2"),
                     Ace("permit udp any any")]
        result:
         self.items: [AceGroup(items=[Remark("=== NAME1"), Ace("permit tcp any any")]),
                      AceGroup(items=[Remark("=== NAME2"), Ace("permit udp any any")])]
        """
        if not group_by:
            return
        ungrouped_l: LUAce = []
        for item in self._items:
            if isinstance(item, (Ace, Remark)):
                ungrouped_l.append(item)
            elif isinstance(item, AceGroup):
                _ungrouped = self._ungroup(item.items)
                ungrouped_l.extend(_ungrouped)

        grouped_items_d: Dict[str, LUAceg] = {}
        group_name = ""
        grouped_items_d[group_name] = []
        for item in ungrouped_l:
            if isinstance(item, Remark):
                if item.text.startswith(group_by):
                    group_name = item.text
                    if item.text not in grouped_items_d:
                        grouped_items_d[group_name] = [item]
                    continue
            grouped_items_d[group_name].append(item)

        grouped_items: LUAceg = []
        for group_name, aces_items in grouped_items_d.items():
            if aces_items:
                aceg_o = AceGroup(
                    platform=self._platform,
                    type=self._type,
                    group_by=group_by,
                    protocol_nr=self._protocol_nr,
                    port_nr=self._port_nr,
                    name=group_name,
                    items=aces_items,
                )
                grouped_items.append(aceg_o)
        self._items = grouped_items
        self._group_by = group_by

    def delete_shadow(self, skip: OLStr = None) -> DLStr:
        """Remove ACEs in the shadow (in the bottom, without hits) from ACL.

        :param skip: Skips checking specified address type: "addrgroup", "nc_wildcard".
        :return: dict Shading (in the top) and shadow (in the bottom) ACEs.

        :example:
        acl = Acl("ip access-list extended NAME
                     permit ip 10.0.0.0 0.0.0.3 any
                     permit ip host 10.0.0.1 any
                     permit ip host 10.0.0.2 any
                     permit ip host 10.0.0.4 any")
        acl.delete_shadow() -> {"permit ip 10.0.0.0 0.0.0.3 any": ["permit ip host 10.0.0.1 any",
                                                                   "permit ip host 10.0.0.2 any"]}
        acl.line == "ip access-list extended NAME
                      permit ip 10.0.0.0 0.0.0.3 any
                      permit ip host 10.0.0.4 any"
        """
        shading_d: DLStr = self.shading(skip)
        if not shading_d:
            return {}
        shadow: LStr = [s for ls in shading_d.values() for s in ls]

        acl_new: Acl = self.copy()
        acl_new.ungroup()
        aces: LStr = [o.line for o in acl_new.items]

        shading_reversed = list(shading_d)
        shading_reversed.reverse()
        for top in shading_reversed:
            idx = aces.index(top) + 1
            items_top = acl_new.items[:idx]
            items_bot = acl_new.items[idx:]
            items_bot = [o for o in items_bot if o.line not in shadow]
            shadow = [s for s in shadow if top != s]
            acl_new.items = items_top + items_bot

        if self.group_by:
            acl_new.group(self.group_by)
        self.items = acl_new.items
        return shading_d

    def shadow_of(self, skip: OLStr = None) -> LStr:
        """Return ACEs in the shadow (in the bottom).

        NOTES:
        - Method compare Ace with the same action. ACEs where self.action=="permit" and
            other.action=="deny" not taken into account (skip checking).
        :param skip: Skips checking specified address type: "addrgroup", "nc_wildcard".
        :return: ACEs in the shadow.

        :example:
        acl = Acl("ip access-list extended NAME
                     permit ip 10.0.0.0 0.0.0.3 any
                     permit ip host 10.0.0.1 any
                     permit ip host 10.0.0.2 any
                     permit ip host 10.0.0.4 any")
        acl.shadow_of() -> ["permit ip host 10.0.0.1 any", "permit ip host 10.0.0.2 any"]
        """
        shading_d: DLStr = self.shading(skip)
        shadow: LStr = [s for ls in shading_d.values() for s in ls]
        return shadow

    def shading(self, skip: OLStr = None) -> DLStr:
        """Return shading `in the top` and shadow `in the bottom` ACEs as dict.

        In dict key is shading rule, value shadow rules.
        NOTES:
        - Method compare Ace with the same action. ACEs where self.action=="permit" and
            other.action=="deny" not taken into account (skip checking).
        :param skip: Skips checking specified address type: "addrgroup", "nc_wildcard".

        :return: Shading (in the top) and shadow (in the bottom) ACEs
        :raises ValueError: addrgroup without addresses, non-contiguous wildcard
        :example:
        acl = Acl("ip access-list extended NAME
                     permit ip 10.0.0.0 0.0.0.3 any
                     permit ip host 10.0.0.1 any
                     permit ip host 10.0.0.2 any
                     permit ip host 10.0.0.4 any")
        acl.shading() -> {"permit ip 10.0.0.0 0.0.0.3 any": ["permit ip host 10.0.0.1 any",
                                                             "permit ip host 10.0.0.2 any"]}
        """
        acl_o = self.copy()
        acl_o.ungroup()
        aces = [o for o in acl_o.items if isinstance(o, Ace)]

        shading_d: DLStr = {}  # result
        shadow: SStr = set()
        for idx, ace_top in enumerate(aces):
            aces_bottom = aces[idx + 1 :]
            for ace_bottom in aces_bottom:
                if ace_bottom.shadow_of(other=ace_top, skip=skip):
                    if ace_bottom.line not in shadow:
                        shading_d.setdefault(ace_top.line, []).append(ace_bottom.line)
                    shadow.add(ace_bottom.line)
        return shading_d

    def tcam_count(self) -> int:
        """Calculate sum of ACEs. Also takes into account the addresses in the address group.

        Useful for getting an estimate of the amount of TCAM resources needed for this ACL.
        :return: Count of TCAM resources.
        """
        counter = super().tcam_count()
        counter += 1
        return counter

    def ungroup_ports(self) -> None:
        """Ungroup ACEs ports.

        Ungroup with multiple ports in single line ("eq" or "neq"),
        to multiple lines with single port.
        :example:
            acl = Acl("ip access-list extended NAME
                       permit tcp any eq 1 2 any eq 3 4")
            acl.split_ports()
            acl.line -> "ip access-list extended NAME
                           permit tcp any eq 1 any eq 3
                           permit tcp any eq 1 any eq 4
                           permit tcp any eq 2 any eq 3
                           permit tcp any eq 2 any eq 4"
        """
        _items: LUAceg = []
        for ace_o in self._items:
            if isinstance(ace_o, Ace):
                aces: LAce = ace_o.ungroup_ports()
                _items.extend(aces)
                continue
            if isinstance(ace_o, AceGroup):
                ace_o.ungroup_ports()
            _items.append(ace_o)
        self.items = _items
        if self._group_by:
            self.group(group_by=self._group_by)

    def ungroup(self) -> None:
        """Ungroup AceGroup to a flat list of Ace items.

        :example:
            self.items: [Ace("permit icmp any any"),
                         AceGroup(items=[Ace("permit tcp any any"), Ace("permit udp any any")])]

             after acl.ungroup()
             self.items: [Ace("permit icmp any any"),
                          Ace("permit tcp any any"),
                          Ace("permit udp any any")]
        """
        self._group_by = ""
        self.items = list(self._ungroup(self._items))

    # =========================== helper =============================

    def _cfg_acl_name(self) -> str:
        """Acl name line, with "ip access-list" keyword in beginning.

        :return: Acl name line.

        :example:
            self.name: "NAME"
            self.platform: "ios"
            return: "ip access-list extended NAME"

        :example:
            self.name: "NAME"
            self.platform: "nxos"
            return: "ip access-list NAME"
        """
        items = ["ip access-list"]
        if self._platform == "ios":
            items.append(self._type)
        items.append(self._name)
        return " ".join(items)

    def _parse_type_name(self, line: str) -> T2Str:
        """Parse ACL type and name from line "ip access-list "."""
        expected = "ip access-list "
        if not line.startswith(expected):
            raise ValueError(f"{line=}, {expected=}")

        _line = h.findall1("ip access-list (.+)", line)
        if not _line:
            return "", ""

        _type = ""
        if self._platform == "nxos":
            _type = "extended"
            name = _line
        else:  # ios
            _type, name = h.findall2("(extended) (.+)", _line)
            if not _type:
                _type, name = h.findall2("(standard) (.+)", _line)
                if not _type:
                    name = _line
                    if name in ["extended", "standard"]:
                        raise ValueError(f"invalid {line=}")
        _type = h.init_type(type=_type, platform=self._platform)

        if name:
            h.check_name(name)
        return _type, name

    def _ungroup(self, items: list) -> Generator:
        """Ungroup AceGroup to a flat list of items."""
        for item in items:
            if isinstance(item, (Acl, AceGroup)):
                yield from self._ungroup(item.items)
            else:
                yield item


# ============================ functions =============================


LAcl = List[Acl]
UAces = Union[str, LStr, dict, DAny, Generator, Ace, Remark, AceGroup]
LUAces = List[UAces]
