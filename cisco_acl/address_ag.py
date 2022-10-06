"""AddressAg - Address of AddrGroup. A "group-object" item of "object-group network " command"""
from __future__ import annotations

import logging
import re
from functools import total_ordering
from ipaddress import IPv4Network
from typing import List, Optional, Union

from cisco_acl import helpers as h
from cisco_acl.base_address import BaseAddress
from cisco_acl.types_ import OIpNet, StrInt, LStr, DAny, LDAny


@total_ordering
class AddressAg(BaseAddress):
    """AddressAg - Address of AddrGroup. A "group-object" item of "object-group network " command"""

    def __init__(self, line: str, **kwargs):
        """Address of AddrGroup
        :param str line: Address line
            Line pattern        Platform    Description
            ==================  ==========  ================================
            description         ios         Address-group description
            A.B.C.D A.B.C.D     ios         Network subnet and mask bits
            host A.B.C.D        ios, nxos   A single host
            group-object        ios         Nested address-group name
            A.B.C.D A.B.C.D     nxos        Network subnet and wildcard bits
            A.B.C.D/LEN         nxos        Network prefix and length
        :param str platform: Platform: "ios", "nxos" (default "ios")

        Helpers
        :param str note: Object description
        :param list items: List of *AddressAg* objects for lines,
            that are configured under "object-group network" (ios) or
            "object-group ip address" (nxos)

        :example: wildcard
            address = AddressAg("10 10.0.0.0 0.0.0.3", platform="nxos")
            result:
                address.line == "10 10.0.0.0 0.0.0.3"
                address.addrgroup == ""
                address.ipnet == IPv4Network("10.0.0.0/30")
                address.prefix == "10.0.0.0/30"
                address.sequence == 10
                address.subnet == "10.0.0.0 255.255.255.252"
                address.wildcard == "10.0.0.0 0.0.0.3"

        :example: host
            address = AddressAg("host 10.0.0.1", platform="nxos")
            result:
                address.line == "10.0.0.1/32"
                address.addrgroup == ""
                address.ipnet == IPv4Network("10.0.0.1/32")
                address.prefix == "10.0.0.1/32"
                address.sequence == 0
                address.subnet == "10.0.0.1 255.255.255.255"
                address.wildcard == "10.0.0.1 0.0.0.0"

        :example: address group
            address = AddressAg("group-object NAME", platform="ios")
            result:
                address.line == "group-object NAME"
                address.addrgroup == "NAME"
                address.ipnet == None
                address.prefix == ""
                address.sequence == 0
                address.subnet == ""
                address.wildcard == ""
        """
        self._items: LAddressAg = []
        self._sequence: int = 0
        super().__init__(**kwargs)  # platform, note, line, addrgroup, ipnet, wildcard, items
        self.line = line
        if self._addrgroup:
            self.items = kwargs.get("items") or []

    # =========================== property ===========================

    @property
    def addrgroup(self) -> str:
        """Nested address-group name (only for platform "ios")
        :return: Address group name

        :example:
            self: Address("group-object NAME", platform="ios")
            return: "NAME"
        """
        return self._addrgroup

    @property
    def ipnet(self) -> OIpNet:
        """Address-group address IPv4Network
        :return: IPv4Network or None

        :example:
            self: Address("10.0.0.0 0.0.0.3", platform="ios")
            return: IPv4Network("10.0.0.0/30")

        :example:
            self: Address("group-object NAME", platform="ios")
            return: None
        """
        return self._ipnet

    @property
    def items(self) -> LAddressAg:
        """List of *AddressAg* objects for lines,
            that are configured under "object-group network" (ios) or
            "object-group ip address" (nxos)"""
        return self._items

    @items.setter
    def items(self, items: LUAddressAg) -> None:
        if isinstance(items, (str, dict, AddressAg)):
            items = [items]
        if not isinstance(items, (list, tuple)):
            raise TypeError(f"{items=} {list} expected")

        _items: LAddressAg = []  # result
        for item in items:
            if isinstance(item, AddressAg):
                item.platform = self._platform
                _items.append(item)
            elif isinstance(item, dict):
                addr_o = AddressAg(item["line"], platform=self._platform)
                _items.append(addr_o)
            elif isinstance(item, str):
                line = h.init_line(item)
                addr_o = AddressAg(line, platform=self._platform)
                _items.append(addr_o)
            else:
                raise TypeError(f"{item=} {str} expected")
        self._items = _items

    @property
    def line(self) -> str:
        """Address-group address line

        :example:
            self: Address("10.0.0.0/24", platform="nxos")
            return: "10.0.0.0/24"
        """
        items = []
        if self._sequence:
            items.append(str(self._sequence))
        if self._type == "addrgroup":
            items.append(f"{self._cmd_addrgroup()}{self._addrgroup}")
        elif self._type == "any":
            items.append("any")
        elif self._type == "host":
            if not isinstance(self._ipnet, IPv4Network):
                raise TypeError(f"{self._ipnet=} {IPv4Network} expected")
            items.append(f"host {self._ipnet.network_address}")
        elif self._type == "prefix":
            items.append(self.prefix)
        elif self._type == "subnet":
            items.append(self.subnet)
        else:
            items.append(self.wildcard)
        items = [s for s in items if s]
        return " ".join(items)

    @line.setter
    def line(self, line: str) -> None:
        line = h.init_line(line)
        line_d = h.parse_address(line)
        line = line_d["address"]
        self._sequence = h.init_int(line_d["sequence"])

        if self._is_address_host(line):
            self._line__host(line)
        elif self._is_address_prefix(line):
            self._line__prefix(line)
        elif self._is_address_wildcard(line):
            if self._platform == "nxos":
                self._line__wildcard(line)
            else:  # ios
                self._line__subnet(line)
        elif self._is_addrgroup(line):
            self._line_addrgroup(line)
        else:
            raise ValueError(f"invalid address {line=}")

    @property
    def platform(self) -> str:
        """Platform: "ios" Cisco IOS, "nxos" Cisco Nexus NX-OS"""
        return self._platform

    @platform.setter
    def platform(self, platform: str) -> None:
        """Changes platform, normalizes self regarding the new platform
        :param str platform: Platform: "ios", "nxos" (default "ios")
        """
        line = self.line
        self._platform = h.init_platform(platform=platform)

        if self._is_addrgroup(line):
            self._type = "addrgroup"

        elif self._platform == "ios":
            if isinstance(self._ipnet, IPv4Network):
                if self._ipnet.prefixlen == 32:
                    self._type = "host"
                else:
                    self._type = "subnet"
            else:  # wildcard
                wildcard = line
                raise ValueError(f"{wildcard=} can not be transformed to subnet")
            self._sequence = 0

        elif self._platform == "nxos":
            if isinstance(self._ipnet, IPv4Network):
                self._type = "prefix"
            else:
                self._type = "wildcard"
        self.line = self.line

    @property
    def sequence(self) -> int:
        """Address-group address sequence number
        :return: Sequence number

        :example: Address with sequence number
            self: Address("111 10.0.0.0/24", platform="nxos")
            return: 111

        :example: Address without sequence number
            self: Address("10.0.0.0/24", platform="nxos")
            return: 0
        """
        return self._sequence

    @sequence.setter
    def sequence(self, sequence: StrInt) -> None:
        self._sequence = h.init_int(sequence)

    @property
    def subnet(self) -> str:
        """Address-group subnet
        :return: Subnet with mask

        :example:
            self: Address("10.0.0.0/24", platform="nxos")
            return: "10.0.0.0 255.255.255.0"
        """
        if not self._ipnet:
            return ""
        return self._ipnet.with_netmask.replace("/", " ")

    @property
    def wildcard(self) -> str:
        """Address-group wildcard
        :return: Subnet with wildcard

        :example:
            self: Address("10.0.0.0/24", platform="nxos")
            return: "10.0.0.0 0.0.0.255"
        """
        return self._wildcard

    # =========================== methods ============================

    def copy(self) -> AddressAg:
        """Copies the self object"""
        kwargs = self.data()
        return AddressAg(**kwargs)

    def data(self) -> DAny:
        """Converts *AddressAg* object to *dict*
        :return: Address data

        :example:
            address = AddressAg("10.0.0.0/24", platform="nxos")
            address.data() ->
                {"line": "10.0.0.0/24",
                "platform": "nxos",
                "note": "",
                "items": [],
                "sequence": 0,
                "addrgroup": "",
                "ipnet": IPv4Network("10.0.0.0/24"),
                "prefix": "10.0.0.0/24",
                "subnet": "10.0.0.0 255.255.255.0",
                "wildcard": "10.0.0.0 0.0.0.255"}
        """
        data = dict(
            # init
            line=self.line,
            platform=self._platform,
            note=self.note,
            items=[o.data() for o in self._items],
            # property
            sequence=self._sequence,
            type=self._type,
            addrgroup=self._addrgroup,
            ipnet=self._ipnet,
            prefix=self.prefix,
            subnet=self.subnet,
            wildcard=self._wildcard,
        )
        return data

    # =========================== helpers ============================

    def _cmd_addrgroup(self) -> str:
        """Address group line beginning
        :return: "group-object "
        """
        return "group-object "

    def _is_addrgroup(self, line: str) -> bool:
        """True if address is group "group-object NAME" """
        regex = "^group-object (.+)"
        if re.match(regex, line):
            return True
        return False

    def _line_addrgroup(self, line):
        """Sets attributes for address group: "group-object NAME" """
        if self._platform == "nxos":
            platform = self._platform
            raise ValueError(f"invalid address {line=} for {platform=}")
        name = h.findall1("^group-object (.+)", line)
        h.check_name(name)
        self._type = "addrgroup"
        self._addrgroup = name
        self._ipnet = None
        self._wildcard = ""

    def _line__host(self, line: str) -> None:
        """Sets attributes for host: host A.B.C.D"""
        ip_ = h.findall1(f"host ({h.OCTETS})", line)
        self._type = "host"
        self._addrgroup = ""
        self._ipnet = IPv4Network(f"{ip_}/32")
        self._wildcard = h.invert_mask(f"{ip_} 255.255.255.255")

    def _line__prefix(self, line: str) -> None:
        """Sets attributes for prefix: A.B.C.D/LEN"""
        try:
            ipnet = IPv4Network(address=line)
        except ValueError as ex:
            if "has host bits set" not in str(ex):
                raise type(ex)(*ex.args)
            line_ = line.split("/")[0] + "/32"
            ipnet = IPv4Network(address=line_)
            msg = f"ValueError: {ex}. Fixed to {ipnet}"
            logging.warning(msg)

        if self._platform == "ios":
            subnet = ipnet.with_netmask.replace("/", " ")
            self._line__subnet(subnet)
            return

        self._type = "prefix"
        self._addrgroup = ""
        self._ipnet = ipnet
        self._wildcard = ipnet.with_hostmask.replace("/", " ")

    def _line__subnet(self, line: str) -> None:
        """Sets attributes for subnet "A.B.C.D A.B.C.D" """
        subnet = line
        if line == "0.0.0.0 0.0.0.0":
            if self._platform == "ios":
                raise ValueError(f"invalid {subnet=} ,configuring any is not allowed")

        if not line.endswith(" 255.255.255.255"):
            if h.is_contiguous_wildcard(subnet):
                raise ValueError(f"invalid mask in {subnet=}")

        self._type = "subnet"
        self._ipnet = IPv4Network(subnet.replace(" ", "/"))
        self._wildcard = h.invert_mask(subnet)
        self._addrgroup = ""

    def _line__wildcard(self, line: str) -> None:
        """Sets attributes for wildcard: A.B.C.D A.B.C.D"""
        wildcard = line
        self._type = "wildcard"
        self._addrgroup = ""
        self._wildcard = wildcard

        if not h.is_contiguous_wildcard(wildcard):
            self._ipnet = None
            return

        subnet = h.invert_mask(wildcard)
        try:
            ipnet = IPv4Network(subnet.replace(" ", "/"))
        except ValueError as ex:
            raise ValueError(f"invalid {wildcard=}") from ex
        self._ipnet = ipnet


LAddressAg = List[AddressAg]
OAddressAg = Optional[AddressAg]
UAddressAg = Union[str, LStr, DAny, LDAny, AddressAg, LAddressAg]
LUAddressAg = List[UAddressAg]
LUSAddressAg = List[Union[str, AddressAg]]
