"""BaseAddress - Parent of: Address, AddressAg"""

import re
from abc import abstractmethod
from functools import total_ordering
from ipaddress import IPv4Network
from typing import Optional

from cisco_acl import helpers as h
from cisco_acl.base import Base
from cisco_acl.types_ import DAny, OIpNet, LIpNet, LStr
from cisco_acl.wildcard import Wildcard


@total_ordering  # type: ignore
class BaseAddress(Base):
    """BaseAddress - Parent of: Address, AddressAg"""

    def __init__(self, **kwargs):
        """BaseAddress
        :param platform: Platform: "ios", "nxos" (default "ios")
        :type platform: str

        Helpers
        :param note: Object description
        :type note: Any

        :param max_ncwb: Max count of non-contiguous wildcard bits
        :type max_ncwb: int
        """
        self._type = ""
        self._addrgroup: str = ""
        self._items = []
        self._wildcard = None
        super().__init__(**kwargs)  # platform, note
        # noinspection PyProtectedMember
        self.max_ncwb: int = Wildcard._init_max_ncwb(**kwargs)

    def __repr__(self):
        params = self._repr__params()
        params = self._repr__add_param("items", params)
        kwargs = ", ".join(params)
        name = self.__class__.__name__
        return f"{name}({kwargs})"

    # ========================== redefined ===========================

    def __hash__(self) -> int:
        wildcard = ""
        if isinstance(self._wildcard, Wildcard):
            wildcard = self._wildcard.line
        return (self._addrgroup, wildcard).__hash__()

    def __eq__(self, other) -> bool:
        """== equality"""
        if self.__class__ == other.__class__:
            return self.__hash__() == other.__hash__()
        return False

    def __lt__(self, other) -> bool:
        """< less than"""
        if self.__class__ == other.__class__:
            if self.ipnet and other.ipnet:
                return self.ipnet < other.ipnet
            if self.ipnet and not other.ipnet:
                return True
            if not self.ipnet and other.ipnet:
                return False
            if self.wildcard or other.wildcard:
                return self.wildcard < other.wildcard
            if self._addrgroup or other.addrgroup:
                return self._addrgroup < other.addrgroup
            return self.line < other.line
        return False

    def __contains__(self, other) -> bool:
        """Returns True if other.ipnet is subnet of self.ipnet"""
        self_ipnet = self._get_ipnet(self)
        if not self_ipnet:
            raise TypeError(f"{self_ipnet=} {IPv4Network} expected")

        # other=AddressAg
        if other_ipnet := self._get_ipnet(other):
            if other_ipnet.subnet_of(self_ipnet):
                return True
            return False

        # other=AddrGroup, other_items=LAddressAg
        if other_items := self._get_items(other):
            for other_item in other_items:
                other_ipnet = self._get_ipnet(other_item)
                if not other_ipnet:
                    raise TypeError(f"{other_ipnet=} {IPv4Network} expected")
                if other_ipnet.subnet_of(self_ipnet):
                    return True
            return False

        raise TypeError(f"{other=} type AddressAg expected")

    # =========================== property ===========================

    @property
    @abstractmethod
    def items(self):
        """List of *Address* or *AddressAg* objects for address group"""

    def _init_items(self, items) -> list:
        """Init items of *Address*, *AddressAg* objects for address group"""
        if isinstance(items, (str, dict, self.__class__)):
            items = [items]
        if not isinstance(items, (list, tuple)):
            raise TypeError(f"{items=} {list} expected")

        items_ = []
        for item in items:
            if isinstance(item, self.__class__):
                item.platform = self._platform
                items_.append(item)
            elif isinstance(item, dict):
                addr_o = self.__class__(**item)
                items_.append(addr_o)
            elif isinstance(item, str):
                line = h.init_line(item)
                addr_o = self.__class__(line=line, platform=self._platform, max_ncwb=self.max_ncwb)
                items_.append(addr_o)
            else:
                raise TypeError(f"{item=} {str} expected")
        return items_

    @property
    def addrgroup(self) -> str:
        """Address group name, if type="addrgroup". Value of "object-group NAME", "addrgroup NAME"
        :return: Address group name

        :example:
            self: Address("object-group NAME", platform="ios")
            return: "NAME"

        :example:
            self: Address("addrgroup NAME", platform="nxos")
            return: "NAME"
        """
        return self._addrgroup

    @property
    def ipnet(self) -> OIpNet:
        """Address IPv4Network object, None if type="addrgroup"
        :return: *IPv4Network* or None

        :example:
            self: Address("10.0.0.0 0.0.0.3", platform="ios")
            return: IPv4Network("10.0.0.0/30")

        :example:
            self: Address("object-group NAME", platform="ios")
            return: None
        """
        if not isinstance(self._wildcard, Wildcard):
            return None
        return self._wildcard.ipnet

    @property
    def line(self) -> str:
        """ACE address line: "A.B.C.D A.B.C.D", "A.B.C.D/LEN", "any", "host A.B.C.D",
        "object-group NAME", "addrgroup NAME"

        :example:
            self: Address("host 10.0.0.1", platform="nxos")
            return: "host 10.0.0.0.1"
        """
        if self._type == "addrgroup":
            return f"{self._cmd_addrgroup()}{self._addrgroup}"
        if self._type == "any":
            return "any"
        if self._type == "host":
            if not isinstance(self.ipnet, IPv4Network):
                raise TypeError(f"{self.ipnet=} {IPv4Network} expected")
            return f"host {self.ipnet.network_address}"
        if self._type == "prefix":
            return self.prefix
        if self._type == "subnet":
            return self.subnet
        return self.wildcard

    @line.setter
    def line(self, line: str) -> None:
        line = h.init_line(line)
        if self._is_address_any(line):
            self._line__any()
        elif self._is_address_host(line):
            self._line__host(line)
        elif self._is_address_prefix(line):
            self._line__prefix(line)
        elif self._is_address_wildcard(line):
            self._line__wildcard(line)
        elif self._is_addrgroup(line):
            self._line_addrgroup(line)
        else:
            raise ValueError(f"invalid address {line=}")

    @property
    def platform(self) -> str:
        """Platform: "ios" Cisco IOS, "nxos" Cisco Nexus NX-OS"""
        return self._platform

    @platform.setter
    def platform(self, platform: str) -> None:  # pylint: disable=too-many-branches)
        """Changes platform, normalizes self regarding the new platform
        :param platform: Platform: "ios", "nxos" (default "ios")
        """
        line = self.line
        self._platform = h.init_platform(platform=platform)

        if self._is_addrgroup(self.line) or self._is_addrgroup(line):
            self._type = "addrgroup"

        elif self._platform == "ios":
            if isinstance(self.ipnet, IPv4Network):
                if self.ipnet.prefixlen == 32:
                    self._type = "host"
                elif str(self.ipnet) == "0.0.0.0/0":
                    self._type = "any"
                else:
                    self._type = "wildcard"
            else:
                self._type = "wildcard"

        elif self._platform == "nxos":
            if isinstance(self.ipnet, IPv4Network):
                if str(self.ipnet) == "0.0.0.0/0":
                    self._type = "any"
                else:
                    self._type = "prefix"
            else:
                self._type = "wildcard"

        for item in self._items:
            item.platform = self._platform

        data = self.data(uuid=True)
        self.__init__(**data)  # type: ignore

    @property
    def prefix(self) -> str:
        """Address prefix, "" if type="addrgroup"
        :return: Subnet with prefix length "A.B.C.D/LEN"

        :example:
            self: Address("10.0.0.0 0.0.0.3", platform="ios")
            return: "10.0.0.0/32"
        """
        if not isinstance(self.ipnet, IPv4Network):
            return ""
        return str(self.ipnet)

    @prefix.setter
    def prefix(self, prefix: str) -> None:
        self.line = prefix

    @property
    def subnet(self) -> str:
        """Address subnet, "" if type="addrgroup"
        :return: Subnet with mask "A.B.C.D A.B.C.D"

        :example:
            self: Address("10.0.0.0 0.0.0.3", platform="ios")
            return: "10.0.0.0 255.255.255.252"
        """
        if not isinstance(self.ipnet, IPv4Network):
            return ""
        return self.ipnet.with_netmask.replace("/", " ")

    @property
    def wildcard(self) -> str:
        """Address wildcard, "" if type="addrgroup"
        :return: Subnet with wildcard mask "A.B.C.D A.B.C.D"

        :example:
            self: Address("10.0.0.0/30", platform="nxos")
            return: "10.0.0.0 0.0.0.3"
        """
        if not isinstance(self._wildcard, Wildcard):
            return ""
        return self._wildcard.line

    @property
    def type(self) -> str:
        """Address type: "addrgroup", "prefix", "subnet", "wildcard"
        :return: Address type

        :example:
            self: Address("10.0.0.0 0.0.0.3", platform="ios")
            return: "wildcard"
        """
        return self._type

    # =========================== methods ============================

    def data(self, uuid: bool = False) -> DAny:
        """Converts *Address* object to *dict*
        :param uuid: Returns self.uuid in data
        :type uuid: bool

        :return: Address data

        :example:
            address = Address("10.0.0.0/24", platform="nxos")
            address.data() ->
                {"line": "10.0.0.0/24",
                 "platform": "nxos",
                 "note": "",
                 "items": [],
                 "max_ncwb": 16,
                 "type": "prefix",
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
            items=[o.data(uuid=uuid) for o in self._items],
            max_ncwb=self.max_ncwb,
            # property
            type=self._type,
            addrgroup=self._addrgroup,
            ipnet=self.ipnet,
            prefix=self.prefix,
            subnet=self.subnet,
            wildcard=self.wildcard,
        )
        if uuid:
            data["uuid"] = self.uuid
        return data

    def ipnets(self) -> LIpNet:
        """All IPv4Networks, including address group and wildcard items
        :return: List of IPv4Network

        :example: contiguous wildcard
            Address("10.0.0.0 0.0.0.3").ipnets() -> [IPv4Network("10.0.0.0/30")]

        :example: non-contiguous wildcard
            self: Address("10.0.0.0 0.0.1.3")
            return: [IPv4Network("10.0.0.0/30"), IPv4Network("10.0.1.0/30")]
        """
        if isinstance(self.ipnet, IPv4Network):
            return [self.ipnet]

        if isinstance(self._wildcard, Wildcard):
            return self._wildcard.ipnets()

        ipnets: LIpNet = []
        if self.type == "addrgroup":
            for item in self._items:
                wildcard_o = getattr(item, "_wildcard")
                if not isinstance(wildcard_o, Wildcard):
                    raise TypeError(f"{self.line} {item=} {Wildcard} expected")
                # noinspection PyProtectedMember
                ipnets_ = item._wildcard.ipnets()
                ipnets.extend(ipnets_)
        return ipnets

    def prefixes(self) -> LStr:
        """All prefixes, including address group and wildcard items
        :return: Subnets with prefix length

        :example:
            self: Address("object-group NAME", platform="ios")
            return: ["10.0.1.0/30", "10.0.2.0/30"]

        :example:
            self: Address("10.0.0.0 0.0.0.3", platform="ios")
            return: ["10.0.0.0/30"]
        """
        ipnets = self.ipnets()
        return [str(o) for o in ipnets]

    def subnet_of(self, other) -> bool:
        """Checks self *Address* (all ipnets) is subnet of `other` *Address* (any of ipnet)
        :param other: Other *Address* (top)
        :type other: *Union[Address, AddressAg]*
        :return: True - if *Address* is subnet of `other` *Address*
        """
        tops = other.ipnets()
        bottoms = self.ipnets()
        is_subnet = h.subnet_of(tops=tops, bottoms=bottoms)
        return is_subnet

    def subnets(self) -> LStr:
        """All subnets, including address group and wildcard items
        :return: Subnets with mask

        :example:
            self: Address("object-group NAME", platform="ios")
            return: ["10.0.1.0 255.255.255.252", "10.0.2.0 255.255.255.252"]

        :example:
            self: Address("10.0.0.0 0.0.0.3", platform="ios")
            return: ["10.0.0.0 255.255.255.252"]
        """
        ipnets = self.ipnets()
        return [o.with_netmask.replace("/", " ") for o in ipnets]

    def wildcards(self) -> LStr:
        """All wildcards, including address group and wildcard items
        :return: LIst of wildcard *str*

        :example:
            self: Address("object-group NAME", platform="ios")
            return: ["10.0.1.0 0.0.0.3", "10.0.2.0 0.0.0.3"]

        :example:
            self: Address("10.0.0.0 0.0.0.3", platform="ios")
            return: ["10.0.0.0 0.0.0.3"]
        """
        if isinstance(self._wildcard, Wildcard):
            return [self._wildcard.line]
        wildcards: LStr = []
        for item in self._items:
            wildcard_o = getattr(item, "_wildcard")
            if not isinstance(wildcard_o, Wildcard):
                raise TypeError(f"{self.line} {item=} {Wildcard} expected")
            wildcards.append(wildcard_o.line)
        return wildcards

    # =========================== helpers ============================

    def _cmd_addrgroup(self) -> str:
        """Address group line beginning
        :return: "object-group " or "addrgroup "

        :example:
            self.platform: "ios"
            return: "object-group "

        :example:
            self.platform: "nxos"
            return: "addrgroup "
        """
        if self._platform == "nxos":
            return "addrgroup "
        return "object-group "

    @staticmethod
    def _get_ipnet(obj) -> OIpNet:
        """Gets IPv4Network from object"""
        if hasattr(obj, "ipnet"):
            if ipnet := getattr(obj, "ipnet"):
                if isinstance(ipnet, IPv4Network):
                    return ipnet
        return None

    @staticmethod
    def _get_items(obj) -> Optional[list]:
        """Gets list of items from object"""
        if hasattr(obj, "items"):
            if items := getattr(obj, "items"):
                if isinstance(items, list):
                    return items
        return None

    @staticmethod
    def _is_address_any(line: str) -> bool:
        """True if address is any"""
        return line == "any"

    def _is_addrgroup(self, line: str) -> bool:
        """True if address is group "object-group NAME" or "addrgroup NAME" """
        regex = f"^{self._cmd_addrgroup()}(.+)"
        return bool(re.match(regex, line))

    @staticmethod
    def _is_address_host(line: str) -> bool:
        """True if address is "host A.B.C.D" """
        regex = f"host {h.OCTETS}"
        return bool(re.match(regex, line))

    @staticmethod
    def _is_address_prefix(line: str) -> bool:
        """True if address is prefix "A.B.C.D/LEN" """
        regex = h.OCTETS + r"/\d+$"
        return bool(re.match(regex, line))

    @staticmethod
    def _is_address_subnet(line: str) -> bool:
        """True if address is subnet: "A.B.C.D A.B.C.D" """
        regex = f"{h.OCTETS} {h.OCTETS}"
        if re.match(regex, line):
            try:
                IPv4Network(line.replace(" ", "/"))
            except ValueError:
                return False
            return True
        return False

    @staticmethod
    def _is_address_wildcard(line: str) -> bool:
        """True if address is wildcard: "A.B.C.D A.B.C.D" """
        regex = f"{h.OCTETS} {h.OCTETS}"
        return bool(re.match(regex, line))

    def _line_addrgroup(self, line):
        """Sets attributes for address group: "object-group NAME" or "addrgroup NAME" """
        regex = f"^{self._cmd_addrgroup()}(.+)"
        addrgroup = h.findall1(regex, line)
        h.check_name(addrgroup)
        self._type = "addrgroup"
        self._addrgroup = addrgroup
        self._wildcard = None

    def _line__any(self) -> None:
        """ACE address line, any"""
        self._type = "any"
        self._addrgroup = ""
        wildcard = "0.0.0.0 255.255.255.255"
        self._wildcard = Wildcard(wildcard, platform=self._platform, max_ncwb=self.max_ncwb)

    def _line__host(self, line: str) -> None:
        """Sets attributes for host: host A.B.C.D"""
        ip_ = h.findall1(f"^host ({h.OCTETS})", line)
        self._type = "host"
        self._addrgroup = ""
        wildcard = f"{ip_} 0.0.0.0"
        self._wildcard = Wildcard(wildcard, platform=self._platform, max_ncwb=self.max_ncwb)

    def _line__prefix(self, line: str) -> None:
        """Sets attributes for prefix: A.B.C.D/LEN"""
        ipnet = h.prefix_to_ipnet(line)

        self._type = "prefix"
        if self.platform == "ios":
            self._type = "wildcard"

        self._addrgroup = ""
        wildcard = ipnet.with_hostmask.replace("/", " ")
        self._wildcard = Wildcard(wildcard, platform=self._platform, max_ncwb=self.max_ncwb)

    def _line__wildcard(self, line: str) -> None:
        """Sets attributes for wildcard: A.B.C.D A.B.C.D"""
        self._type = "wildcard"
        self._addrgroup = ""
        self._wildcard = Wildcard(line, platform=self._platform, max_ncwb=self.max_ncwb)


# ============================ functions =============================


def collapse_(addresses: list) -> list:
    """Collapses *LAddress*, *LAddressAg*
    :param addresses: List of Address objects
    :return: Collapsed Address objects
    :raises TypeError: Passed addresses not match: Address.ipnet is not *IPv4Network*
    """
    if not addresses:
        return []
    for address in addresses:
        if address.type == "wildcard" and not isinstance(address.ipnet, IPv4Network):
            raise TypeError(f"{address=} is non-contiguous wildcard")

    collapsed: LIpNet = []
    ipnets: LIpNet = [o for a in addresses for o in a.ipnets()]
    while ipnets:
        ipnet = ipnets.pop()
        if [o for o in ipnets if ipnet.subnet_of(o)]:
            continue
        supernet = ipnet.supernet()
        subnets = set(supernet.subnets())
        if subnets.issubset({*ipnets, ipnet}):
            if supernet not in ipnets:
                ipnets.insert(0, supernet)
            continue
        collapsed.append(ipnet)

    addresses_ = []  # result
    for ipnet_ in collapsed:
        addr_o = addresses[0].copy()
        addr_o.note = None
        addr_o.prefix = str(ipnet_)
        addresses_.append(addr_o)
    return sorted(addresses_)
