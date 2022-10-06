"""Address - Source or destination address in ACE"""
from __future__ import annotations

from functools import total_ordering
from ipaddress import IPv4Network
from typing import List, Optional, Union

from cisco_acl import helpers as h
from cisco_acl.base_address import BaseAddress
from cisco_acl.types_ import LStr, DAny, LDAny


@total_ordering
class Address(BaseAddress):
    """Address - Source or destination address in ACE"""

    def __init__(self, line: str, **kwargs):
        """Address
        :param str line: Address line
            Line pattern        Platform    Description
            ==================  ==========  ===========================
            A.B.C.D A.B.C.D                 Address and wildcard bits
            A.B.C.D/LEN         nxos        Network prefix
            any                             Any host
            host A.B.C.D        ios         A single host
            object-group NAME   ios         Network object group
            addrgroup NAME      nxos        Network object group
        :param str platform: Platform: "ios", "nxos" (default "ios")

        Helpers
        :param str note: Object description
        :param list items: List of *Address* objects for "object-group" (ios) or "addrgroup" (nxos),
            that are configured under "object-group network" (ios) or
            "object-group ip address" (nxos)

        :example: wildcard
            address = Address("10.0.0.0 0.0.0.3", platform="ios")
            result:
                address.line == "10.0.0.0 0.0.0.3"
                address.addrgroup == ""
                address.ipnet == IPv4Network("10.0.0.0/30")
                address.prefix == "10.0.0.0/30"
                address.subnet == "10.0.0.0 255.255.255.252"
                address.wildcard == "10.0.0.0 0.0.0.3"

        :example: host
            address = Address("host 10.0.0.1", platform=="nxos")
            result:
                address.line == "10.0.0.1/32"
                address.addrgroup == ""
                address.ipnet == IPv4Network("10.0.0.1/32")
                address.prefix == "10.0.0.1/32"
                address.subnet == "10.0.0.1 255.255.255.255"
                address.wildcard == "10.0.0.1 0.0.0.0"

        :example: address group
            address = Address("object-group NAME", platform="ios")
            result:
                address.line == "object-group network NAME"
                address.addrgroup == "NAME"
                address.ipnet == None
                address.prefix == ""
                address.subnet == ""
                address.wildcard == ""
        """
        super().__init__(**kwargs)  # platform, note, line, addrgroup, ipnet, wildcard, items
        self._items: LAddress = []
        self.line = line
        if self._type == "addrgroup":
            self.items = kwargs.get("items") or []

    # =========================== property ===========================

    @property
    def items(self) -> LAddress:
        """List of *Address* objects for "object-group" (ios) or "addrgroup" (nxos),
            that are configured under "object-group network" (ios) or
            "object-group ip address" (nxos)"""
        return self._items

    @items.setter
    def items(self, items: LUAddress) -> None:
        if isinstance(items, (str, dict, Address)):
            items = [items]
        if not isinstance(items, (list, tuple)):
            raise TypeError(f"{items=} {list} expected")

        _items: LAddress = []  # result
        for item in items:
            if isinstance(item, Address):
                item.platform = self._platform
                _items.append(item)
            elif isinstance(item, dict):
                addr_o = Address(item["line"], platform=self._platform)
                _items.append(addr_o)
            elif isinstance(item, str):
                line = h.init_line(item)
                addr_o = Address(line, platform=self._platform)
                _items.append(addr_o)
            else:
                raise TypeError(f"{item=} {str} expected")
        self._items = _items

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

        if self._is_addrgroup(self.line) or self._is_addrgroup(line):
            self._type = "addrgroup"

        elif self._platform == "ios":
            if isinstance(self._ipnet, IPv4Network):
                if self._ipnet.prefixlen == 32:
                    self._type = "host"
                elif str(self._ipnet) == "0.0.0.0/0":
                    self._type = "any"
                else:
                    self._type = "wildcard"
            else:
                self._type = "wildcard"

        elif self._platform == "nxos":
            if isinstance(self._ipnet, IPv4Network):
                if str(self._ipnet) == "0.0.0.0/0":
                    self._type = "any"
                else:
                    self._type = "prefix"
            else:
                self._type = "wildcard"
        self.line = self.line

    # =========================== methods ============================

    def copy(self) -> Address:
        """Copies the self object"""
        kwargs = self.data()
        return Address(**kwargs)

    def data(self) -> DAny:
        """Converts *Address* object to *dict*
        :return: Address data

        :example:
            address = Address("10.0.0.0/24", platform="nxos")
            address.data() ->
                {"line": "10.0.0.0/24",
                "platform": "nxos",
                "note": "",
                "items": [],
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
            type=self._type,
            addrgroup=self._addrgroup,
            ipnet=self._ipnet,
            prefix=self.prefix,
            subnet=self.subnet,
            wildcard=self._wildcard,
        )
        return data


LAddress = List[Address]
OAddress = Optional[Address]
UAddress = Union[str, LStr, DAny, LDAny, Address, LAddress]
LUAddress = List[UAddress]
