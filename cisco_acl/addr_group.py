"""AddrGroup.

Group of AddressAg addresses configured in "object-group network" (ios) or
"object-group ip address" (nxos).
"""
from __future__ import annotations

import logging
from functools import total_ordering
from ipaddress import IPv4Network
from typing import Any, Dict, List, Union

from cisco_acl import parsers, helpers as h
from cisco_acl.address_ag import AddressAg, OAddressAg, LUSAddressAg
from cisco_acl.address_ag import LAddressAg
from cisco_acl.base import Base
from cisco_acl.group import Group
from cisco_acl.types_ import LStr, LIpNet, DAny
from cisco_acl.wildcard import init_max_ncwb


@total_ordering
class AddrGroup(Base, Group):
    """AddrGroup."""

    def __init__(self, line: str = "", **kwargs):
        r"""Init AddrGroup.

        :param line: Address group config line.
        :type line: str

        :param platform: Platform: "asa", "ios", "nxos". Default "ios".
        :type platform: str

        :param version: Software version, default is "0".
        :type version: str

        Helpers
        :param note: Object description.
        :type note: Any

        :param indent: Address lines indentation (default "  ").
        :type indent: str

        :param max_ncwb: Max count of non-contiguous wildcard bits.
        :type max_ncwb: int

        Alternate way to get `name` and `items`, if `line` absent.
        :param name: Address group name (default from `line`)
        :type name: str

        :param items: List of addresses in group.
        :type items: List[str], List[AddressAg]

        :example:
            address = AddrGroup("object-group ip address NAME\nhost 10.0.0.1")
            result:
                address.line == "object-group ip address NAME\n  host 10.0.0.1"
                address.platform == "ios"
                address.indent == "  "
                address.items == [AddressAg("host 10.0.0.1")]
        """
        self._line: str = ""
        self._name = ""
        self._items: LAddressAg = []
        Base.__init__(self, **kwargs)  # platform, note
        Group.__init__(self)
        self._indent = h.init_indent(**kwargs)
        self.max_ncwb: int = init_max_ncwb(**kwargs)
        if name := str(kwargs.get("name") or ""):
            self.name = name
        if items := kwargs.get("items") or []:
            self.items = items
            return
        self.line = line

    def __hash__(self) -> int:
        """__hash__."""
        return self._name.__hash__()

    def __eq__(self, other) -> bool:
        """== equality."""
        if self.__class__ == other.__class__:
            return self.__hash__() == other.__hash__()
        return False

    def __lt__(self, other) -> bool:
        """< less than."""
        if self.__class__ == other.__class__:
            return self._name < other.name
        return False

    def __contains__(self, other: UAddrGr) -> bool:
        """__contains__."""
        if isinstance(other, AddressAg):
            if other in self._items:
                return True
            for item in self._items:
                if not isinstance(item, AddressAg):
                    raise TypeError(f"{item=} {AddressAg} expected")
                if other in item:
                    return True
            return False

        if isinstance(other, AddrGroup):
            for other_item in other.items:
                if not isinstance(other_item, (AddressAg, AddrGroup)):
                    raise TypeError(f"{other_item=} {AddressAg} expected")
                if other_item in self._items:
                    return True
                for item in self._items:
                    if not isinstance(item, AddressAg):
                        raise TypeError(f"{item=} {AddressAg} expected")
                    if other in item:
                        return True
            return False
        raise TypeError(f"{other=} {UAddrGr} expected")

    # =========================== property ===========================

    @property
    def indent(self) -> str:
        """Address lines indentation (default  "  ")."""
        return self._indent

    @indent.setter
    def indent(self, indent: Any) -> None:
        self._indent = h.init_indent(indent=indent)

    @property
    def items(self) -> LAddressAg:
        """List of AddressAg objects."""
        return self._items

    @items.setter
    def items(self, items: LUSAddressAg) -> None:
        if isinstance(items, (str, AddressAg, AddrGroup)):
            items = [items]
        if not isinstance(items, (list, tuple)):
            raise TypeError(f"{items=} {list} expected")

        _items: LAddressAg = []
        for item in items:
            if isinstance(item, (AddressAg, AddrGroup)):
                item._platform = self._platform
                _items.append(item)
            elif isinstance(item, dict):
                addr_o = AddressAg(**item)
                _items.append(addr_o)
            elif isinstance(item, str):
                line = h.init_line(item)
                # description
                if item.startswith("description "):  # todo description
                    continue
                # AddressAg
                item_: OAddressAg = self._line_to_address(line)
                if not item_:
                    msg = f"invalid {line=}"
                    logging.warning(msg)
                    continue
                _items.append(item_)
            else:
                raise TypeError(f"{item=} {str} expected")
        self._items = _items

    @property
    def line(self) -> str:
        r"""Address group config line.

        :example:
            self: AddrGroup("object-group ip address NAME\nhost 10.0.0.1")
            return: "object-group ip address NAME\n  host 10.0.0.1"
        """
        items = [f"{self._indent}{o.line}" for o in self._items]
        line = "\n".join([self.cmd_addgr_name(), *items])
        return line

    @line.setter
    def line(self, line: str) -> None:
        items = h.lines_wo_spaces(line)
        if not items:
            if self.name and self.items:
                return
            raise ValueError(f"absent {line=}")

        name = ""
        item1, *items = items
        if self._platform == "nxos":
            name = h.findall1(r"^object-group ip address (.+)", item1)
        elif self._platform == "ios":
            name = h.findall1(r"^object-group network (.+)", item1)
        if not name:
            raise ValueError(f"absent {name=} in {line=}")
        if len(name.split()) > 1 or not name:
            raise ValueError(f"invalid {name=} in {line=}")
        self.name = name

        if not items and not self.items:
            raise ValueError(f"absent {items=} in {line=}")
        addresses: LAddressAg = []
        re_idx, re_address = r"(\d+(?:\s+))?", "(.+)"
        regex = f"{re_idx}{re_address}"
        for item in items:
            idx, item = h.findall2(regex, item)
            try:
                address = AddressAg(line=item, platform=self._platform)
            except ValueError:
                msg = f"invalid {item=}"
                logging.debug(msg)
                continue
            address.sequence = h.init_int(idx)
            addresses.append(address)
        if not addresses:
            raise ValueError(f"absent {addresses=} in {line=}")
        self.items = addresses

    @property
    def name(self) -> str:
        """Address group name."""
        return self._name

    @name.setter
    def name(self, name: str) -> None:
        if name := h.init_name(name):
            h.check_name(name)
        self._name = name

    @property
    def platform(self) -> str:
        """Platform: Platform: "asa", "ios", "nxos"."""
        return self._platform

    @platform.setter
    def platform(self, platform: str) -> None:
        """Change platform, normalizes self.items regarding the new platform.

        :param platform: Platform: "asa", "ios", "nxos". Default "ios".
        """
        self._platform = h.init_platform(platform=platform)

        for item in self._items:
            item.platform = self._platform

        data = self.data(uuid=True)
        self.__init__(**data)  # type: ignore

    # =========================== method =============================

    def data(self, uuid: bool = False) -> DAny:
        """Return AddrGroup data as dict.

        :param uuid: Return self.uuid in data.
        :type uuid: bool

        :return: Address group data.
        """
        data = dict(
            # init
            line=self.line,
            platform=self._platform,
            version=str(self.version),
            note=self.note,
            indent=self._indent,
            name=self._name,
            items=[o.data(uuid=uuid) for o in self._items],
        )
        if uuid:
            data["uuid"] = self.uuid
        return data

    def cmd_addgr_name(self) -> str:
        """Address group name line, with "object-group ip address" keyword in beginning.

        :return: Address group name line.

        :example:
            self.name: "NAME"
            self.platform: "ios"
            return: "object-group network NAME"

        :example:
            self.name: "NAME"
            self.platform: "nxos"
            return: "object-group ip address NAME"
        """
        if self._platform == "nxos":
            return f"object-group ip address {self._name}"
        # ios
        return f"object-group network {self._name}"

    def ipnets(self) -> LIpNet:
        """List of IPv4Network from all addresses in address group.

        return: List of IpNetwork.
        :raises ValueError: If one of the address is non-contiguous wildcard.

        :example: all items ara valid addresses
            self.items: [AddressAd("10.0.0.0/30"),
                         AddressAd("object-group ip address NAME")]  # 10.1.1.0/30
            return: [IpNetwork("10.0.0.0/30"), IpNetwork("10.1.1.0/30")]

        :example: non-contiguous wildcard
            self.items: [AddressAd("10.0.0.0 0.0.3.3")]
            raises: ValueError
        """
        ipnets: LIpNet = []
        for address in self._items:
            ipnet = address.ipnet
            if not isinstance(ipnet, IPv4Network):
                raise TypeError(f"{self.line} {ipnet=} {IPv4Network} expected")
            ipnets.append(ipnet)
        return ipnets

    def prefixes(self) -> LStr:
        """Prefixe from all addresses in address group.

        :return: Prefixes "A.B.C.D/LEN".

        :example:
            self.items: [AddressAd("10.0.0.0/30"),
                         AddressAd("object-group ip address NAME")]  # 10.1.1.0/30
            return: [IpNetwork("10.0.0.0/30"), IpNetwork("10.1.1.0/30")]
        """
        ipnets = self.ipnets()
        return [str(o) for o in ipnets]

    # noinspection PyIncorrectDocstring
    @h.check_start_step_sequence
    def resequence(self, start: int = 10, step: int = 10, **kwargs) -> int:
        """Change sequence numbers for all addresses in address group.

        :param start: Starting sequence number. start=0 - delete all sequence numbers.
        :param step: Step to increment the sequence number.
        :param items: List of AddressAg objects (default self.items).
        :return: Last sequence number.
        """
        items: LAddressAg = kwargs.get("items") or self._items
        sequence: int = int(start)
        count = len(items)

        for id_, item in enumerate(items, start=1):
            item.sequence = sequence
            if id_ < count:
                sequence += step
        return sequence

    def subnets(self) -> LStr:
        """Subnets from all addresses in address group.

        :return: Subnets with mask "A.B.C.D A.B.C.D".

        :example:
            self.items: [AddressAd("10.0.0.0/30"),
                         AddressAd("object-group ip address NAME")]  # 10.1.1.0/30
            return: [IpNetwork("10.0.0.0 255.255.255.252"), IpNetwork("10.1.1.0 255.255.255.252")]
        """
        ipnets = self.ipnets()
        return [o.with_netmask.replace("/", " ") for o in ipnets]

    def wildcards(self) -> LStr:
        """Wildcards from all addresses in address group.

        :return: Wildcards "A.B.C.D A.B.C.D".
        """
        wildcards: LStr = []
        for addr_o in self._items:
            if addr_o.type == "addrgroup":
                raise TypeError("address group recursion is not supported")
            wildcards_ = addr_o.wildcards()
            wildcards.extend(wildcards_)
        return wildcards

    # =========================== helper =============================

    def _line_to_address(self, line: str) -> OAddressAg:
        """Convert config line to AddressAg object.

        :param line: Address line.
        :return: Address object.

        :example:
            line: "10 host 10.0.0.1"
            return: AddressAg("10 host 10.0.0.1")

        :example: not Address line
            line: "text"
            return: None
        """
        try:
            parsers.parse_address(line)
        except ValueError:
            return None
        addr_o = AddressAg(line=line, platform=self._platform, max_ncwb=self.max_ncwb)
        return addr_o


DAddrGroup = Dict[str, AddrGroup]
LAddrGroup = List[AddrGroup]
UAddrGr = Union[AddressAg, AddrGroup]
