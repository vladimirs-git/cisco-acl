"""AddressAg - Address of AddrGroup. A "group-object" item of "object-group network " command"""
from __future__ import annotations

from functools import total_ordering
from ipaddress import IPv4Network
from typing import Iterable, List, Optional, Union

from cisco_acl import address_base
from cisco_acl import helpers as h
from cisco_acl.address_base import AddressBase
from cisco_acl.types_ import StrInt, LStr, DAny, LDAny
from cisco_acl.wildcard import Wildcard


@total_ordering
class AddressAg(AddressBase):
    """AddressAg - Address of AddrGroup. A "group-object" item of "object-group network " command"""

    def __init__(self, line: str, **kwargs):
        """Address of AddrGroup
        :param line: Address line
            Line pattern        Platform    Description
            ==================  ==========  ================================
            description         ios         Address group description
            A.B.C.D A.B.C.D     ios         Network subnet and mask bits
            host A.B.C.D        ios, nxos   A single host
            group-object        ios         Nested address group name
            A.B.C.D A.B.C.D     nxos        Network subnet and wildcard bits
            A.B.C.D/LEN         nxos        Network prefix and length
        :type line: str

        :param platform: Platform: "ios" (default), "nxos"
        :type platform: str

        Helpers
        :param note: Object description
        :type note: Any

        :param items: List of *AddressAg*
        :type items: str, List[str], dict, List[dict], AddressAg, List[AddressAg]

        :param max_ncwb: Max count of non-contiguous wildcard bits
        :type max_ncwb: int

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
    def items(self) -> LAddressAg:
        """List of *AddressAg* objects for address group (type="addrgroup")"""
        return self._items

    @items.setter
    def items(self, items: LUAddressAg) -> None:
        items_ = self._init_items(items)
        self._items = [o for o in items_ if isinstance(o, AddressAg)]

    @property
    def line(self) -> str:
        """Address group address line

        :example:
            self: AddressAg("10 10.0.0.0/24", platform="nxos")
            return: "10 10.0.0.0/24"
        """
        line_ = super().line
        if self._sequence:
            return f"{self._sequence} {line_}"
        return line_

    @line.setter
    def line(self, line: str) -> None:
        line = h.init_line(line)
        line_d = h.parse_address(line)
        line = line_d["address"]
        self._sequence = h.init_int(line_d["sequence"])

        if self._is_address_any(line):
            if self._platform == "nxos":
                self._line__prefix("0.0.0.0/0")
            else:
                raise ValueError(f"invalid address {line=}")
        elif self._is_address_prefix(line):
            self._line__prefix(line)
        elif self._is_address_wildcard(line):
            if self._platform == "nxos":
                self._line__wildcard(line)
            else:  # ios
                self._line__subnet(line)
        elif self._is_address_host(line):
            self._line__host(line)
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
        :param platform: Platform: "ios" (default), "nxos"
        """
        line = self.line
        self._platform = h.init_platform(platform=platform)

        if self._is_addrgroup(line):
            self._type = "addrgroup"

        elif isinstance(self.ipnet, IPv4Network):
            if str(self.ipnet) == "0.0.0.0/0":
                self._type = "any"
            elif self.ipnet.prefixlen == 32:
                self._type = "host"
            elif self._platform == "ios":
                self._type = "subnet"
                self._sequence = 0
            elif self._platform == "nxos":
                self._type = "prefix"

        elif self._platform == "ios":
            msg = f"non-contiguous wildcard={line!r} can not be transformed to subnet"
            raise ValueError(msg)

        elif self._platform == "nxos":
            self._type = "wildcard"

        for item in self._items:
            item.platform = self._platform

        data = self.data(uuid=True)
        self.__init__(**data)  # type: ignore

    @property
    def sequence(self) -> int:
        """Address group address sequence number
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

    # =========================== method =============================

    def data(self, uuid: bool = False) -> DAny:
        """Converts *AddressAg* object to *dict*
        :param uuid: Returns self.uuid in data
        :type uuid: bool

        :return: *AddressAg* data
        """
        data = super().data(uuid)
        data["sequence"] = self._sequence
        return data

    # =========================== helper =============================

    def _cmd_addrgroup(self) -> str:
        """Address group line beginning
        :return: "group-object"
        """
        return "group-object"

    def _is_addrgroup(self, line: str) -> bool:
        """True if address is group "group-object NAME" """
        return line.startswith("group-object")

    def _line_addrgroup(self, line):
        """Sets attributes for address group: "group-object NAME" """
        if self._platform == "nxos":
            raise ValueError(f"invalid address {line=} for platform={self._platform!r}")
        addrgroup = h.findall1("^group-object (.+)", line)
        h.check_name(addrgroup)
        self._type = "addrgroup"
        self._addrgroup = addrgroup
        self._wildcard = None

    def _line__prefix(self, line: str) -> None:
        """Sets attributes for prefix: A.B.C.D/LEN"""
        self._addrgroup = ""
        ipnet = h.prefix_to_ipnet(line)
        wildcard = ipnet.with_hostmask.replace("/", " ")

        if ipnet.prefixlen == 32:
            self._type = "host"
            self._wildcard = Wildcard(wildcard, platform=self._platform, max_ncwb=self.max_ncwb)

        elif self._platform == "ios":
            subnet = ipnet.with_netmask.replace("/", " ")
            self._line__subnet(subnet)

        elif self._platform == "nxos":
            self._type = "prefix"
            self._wildcard = Wildcard(wildcard, platform=self._platform, max_ncwb=self.max_ncwb)

    def _line__subnet(self, line: str) -> None:
        """Sets attributes for subnet "A.B.C.D A.B.C.D" """
        if line == "0.0.0.0 0.0.0.0" and self._platform == "ios":
            raise ValueError(f"{line!r} is denied for platform={self._platform!r}")

        self._addrgroup = ""
        self._wildcard = Wildcard.fsubnet(line, platform=self._platform, max_ncwb=self.max_ncwb)

        self._type = "subnet"
        if isinstance(self.ipnet, IPv4Network):
            if self.ipnet.prefixlen == 32:
                self._type = "host"

    def _line__wildcard(self, line: str) -> None:
        """Sets attributes for wildcard: A.B.C.D A.B.C.D"""
        super()._line__wildcard(line)
        if self._type == "any":
            if self._platform == "ios":
                raise ValueError(f"{line!r} is denied for platform={self._platform!r}")
            if self._platform == "nxos":
                self._type = "prefix"


IAddressAg = Iterable[AddressAg]
LAddressAg = List[AddressAg]
OAddressAg = Optional[AddressAg]
UAddressAg = Union[str, LStr, DAny, LDAny, AddressAg, LAddressAg]
LUAddressAg = List[UAddressAg]
LUSAddressAg = List[Union[str, AddressAg]]


# ============================ functions =============================

def collapse(addresses: IAddressAg) -> LAddressAg:
    """Collapses a list of *AddressAg* objects and deletes subnets in the shadow
        :param addresses: Iterable *AddressAg* objects
        :return: List of collapsed *AddressAg* objects

        :raises TypeError: Passed addresses not match conditions:
            - Item of `addresses` is not *AddressAg*
            - AddressAg is non-contiguous wildcard

        :example:
            wildcard = AddressAg("10.0.0.0 255.255.255.254")
            host2 = AddressAg("host 10.0.0.2")
            host3 = AddressAg("host 10.0.0.3")
            collapse([wildcard, host2, host3]) -> [AddressAg("10.0.0.0 255.255.255.252")]
    """
    addresses = list(addresses)
    for address in addresses:
        if not isinstance(address, AddressAg):
            raise TypeError(f"{address=} {AddressAg} expected")
    # noinspection PyProtectedMember
    collapsed = address_base.collapse_(addresses)
    return [o for o in collapsed if isinstance(o, AddressAg)]
