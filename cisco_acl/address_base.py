"""AddressBase, parent of: Address, AddressAg."""
import re
from abc import abstractmethod
from functools import total_ordering
from ipaddress import IPv4Network
from typing import Optional

from cisco_acl import helpers as h
from cisco_acl.base import Base
from cisco_acl.types_ import DAny, OIpNet, LIpNet, LStr
from cisco_acl.wildcard import Wildcard, init_max_ncwb


@total_ordering  # type: ignore
class AddressBase(Base):
    """AddressBase, parent of: Address, AddressAg."""

    def __init__(self, **kwargs):
        """Init AddressBase.

        :param platform: Platform: "asa", "ios", "nxos". Default "ios".
        :type platform: str

        :param version: Software version, default is "0".
        :type version: str

        Helpers
        :param note: Object description.
        :type note: Any

        :param max_ncwb: Max count of non-contiguous wildcard bits.
        :type max_ncwb: int
        """
        self._type = ""
        self._addrgroup: str = ""
        self._items = []
        self._wildcard = None
        super().__init__(**kwargs)  # platform, note
        # noinspection PyProtectedMember
        self.max_ncwb: int = init_max_ncwb(**kwargs)

    def __repr__(self):
        """__repr__."""
        params = self._repr__params()
        params = self._repr__add_param("items", params)
        kwargs = ", ".join(params)
        name = self.__class__.__name__
        return f"{name}({kwargs})"

    # ========================== redefined ===========================

    def __hash__(self) -> int:
        """__hash__."""
        wildcard = ""
        if isinstance(self._wildcard, Wildcard):
            wildcard = self._wildcard.line
        return (self._addrgroup, wildcard).__hash__()

    def __eq__(self, other) -> bool:
        """== equality."""
        if self.__class__ == other.__class__:
            return self.__hash__() == other.__hash__()
        return False

    def __lt__(self, other) -> bool:
        """< less than."""
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
        """Return True if other.ipnet is subnet of self.ipnet."""
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
        """List of Address or AddressAg objects for address group."""

    def _init_items(self, items) -> list:
        """Init items of Address, AddressAg objects for address group."""
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
        """Address group name, if type="addrgroup". Value of "object-group NAME", "addrgroup NAME".

        :return: Address group name

        :example:
            address = Address("object-group NAME", platform="ios")
            address.addrgroup -> "NAME"

            address = Address("addrgroup NAME", platform="nxos")
            address.addrgroup -> "NAME"
        """
        return self._addrgroup

    @property
    def ipnet(self) -> OIpNet:
        """Address IPv4Network object, None if type="addrgroup".

        :return: IPv4Network or None.

        :example:
            address = Address("10.0.0.0 0.0.0.3", platform="ios")
            address.ipnet -> IPv4Network("10.0.0.0/30")

        :example:
            address = Address("object-group NAME", platform="ios")
            address.ipnet is None
        """
        if not isinstance(self._wildcard, Wildcard):
            return None
        return self._wildcard.ipnet

    @property
    def line(self) -> str:
        """ACE address line.

        "A.B.C.D A.B.C.D", "A.B.C.D/LEN", "any", "host A.B.C.D",
        "object-group NAME", "addrgroup NAME".

        :example:
            address = Address("host 10.0.0.1", platform="nxos")
            address.line -> "host 10.0.0.0.1"
        """
        if self._type == "addrgroup":
            return f"{self._cmd_addrgroup()} {self._addrgroup}"
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
        elif self._is_address_prefix(line):
            self._line__prefix(line)
        elif self._is_address_wildcard(line):
            self._line__wildcard(line)
        elif self._is_address_host(line):
            self._line__host(line)
        elif self._is_addrgroup(line):
            self._line_addrgroup(line)
        else:
            raise ValueError(f"invalid address {line=}")

    @property
    def platform(self) -> str:
        """Platform: Platform: "asa", "ios", "nxos"."""
        return self._platform

    @platform.setter
    def platform(self, platform: str) -> None:  # pylint: disable=too-many-branches)
        """Change platform, normalizes self regarding the new platform.

        :param platform: Platform: "asa", "ios", "nxos". Default "ios".
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
        """Address prefix, "" if type="addrgroup".

        :return: Subnet with prefix length "A.B.C.D/LEN".

        :example:
            address = Address("10.0.0.0 0.0.0.3", platform="ios")
            address.prefix -> "10.0.0.0/32"
        """
        if not isinstance(self.ipnet, IPv4Network):
            return ""
        return str(self.ipnet)

    @prefix.setter
    def prefix(self, prefix: str) -> None:
        self.line = prefix

    @property
    def subnet(self) -> str:
        """Address subnet, "" if type="addrgroup".

        :return: Subnet with mask "A.B.C.D A.B.C.D".

        :example:
            address = Address("10.0.0.0 0.0.0.3", platform="ios")
            address.subnet -> "10.0.0.0 255.255.255.252"
        """
        if not isinstance(self.ipnet, IPv4Network):
            return ""
        return self.ipnet.with_netmask.replace("/", " ")

    @property
    def wildcard(self) -> str:
        """Address wildcard, "" if type="addrgroup".

        :return: Subnet with wildcard mask "A.B.C.D A.B.C.D".

        :example:
            address = Address("10.0.0.0/30", platform="nxos")
            address.wildcard -> "10.0.0.0 0.0.0.3"
        """
        if not isinstance(self._wildcard, Wildcard):
            return ""
        return self._wildcard.line

    @property
    def type(self) -> str:
        """Address type: "addrgroup", "prefix", "subnet", "wildcard".

        :return: Address type.

        :example:
            address = Address("10.0.0.0 0.0.0.3", platform="ios")
            address.type == "wildcard"
        """
        return self._type

    # =========================== method =============================

    def data(self, uuid: bool = False) -> DAny:
        """Convert Address object to the dictionary.

        :param uuid: Return self.uuid in data.
        :type uuid: bool

        :return: Address data.

        :example:
            address = Address("10.0.0.0/24", platform="nxos")
            address.data() -> {
                "line": "10.0.0.0/24",
                "platform": "nxos",
                "version": "0",
                "note": "",
                "items": [],
                "max_ncwb": 16,
                "type": "prefix",
                "addrgroup": "",
                "ipnet": IPv4Network("10.0.0.0/24"),
                "prefix": "10.0.0.0/24",
                "subnet": "10.0.0.0 255.255.255.0",
                "wildcard": "10.0.0.0 0.0.0.255",
            }
        """
        data = dict(
            # init
            line=self.line,
            platform=self._platform,
            version=str(self.version),
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
        """All IPv4Networks, including address group and wildcard items.

        :return: List of IPv4Network

        :example: contiguous wildcard
            address = Address("10.0.0.0 0.0.0.3")
            address.ipnets() -> [IPv4Network("10.0.0.0/30")]

            address = Address("10.0.0.0 0.0.1.3")
            address.ipnets() -> [IPv4Network("10.0.0.0/30"), IPv4Network("10.0.1.0/30")]
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
        """All prefixes, including address group and wildcard items.

        :return: Subnets with prefix length.

        :example:
            address = Address("object-group NAME")
            address.prefixes() -> ["10.0.1.0/30", "10.0.2.0/30"]

            address = Address("10.0.0.0 0.0.0.3")
            address.prefixes() -> ["10.0.0.0/30", "10.0.1.0/30", "10.0.2.0/30", "10.0.3.0/30"]
        """
        ipnets: LIpNet = self.ipnets()
        return [str(o) for o in ipnets]

    def subnet_of(self, other) -> bool:
        """Check self Address (all ipnets) is subnet of `other` Address (any of ipnet).

        :param other: Other Address (top).
        :type other: Address, AddressAg

        :return: True - if Address is subnet of `other` Address.
        """
        tops = other.ipnets()
        bottoms = self.ipnets()
        is_subnet = h.subnet_of(tops=tops, bottoms=bottoms)
        return is_subnet

    def subnets(self) -> LStr:
        """All subnets, including address group and wildcard items.

        :return: Subnets with mask.

        :example:
            address = Address("object-group NAME")
            address.subnets() -> ["10.0.1.0 255.255.255.252", "10.0.2.0 255.255.255.252"]

            address = Address("10.0.0.0 0.0.1.3")
            address.subnets() -> ["10.0.0.0 255.255.255.252", "10.0.1.0 255.255.255.252"]
        """
        ipnets = self.ipnets()
        return [o.with_netmask.replace("/", " ") for o in ipnets]

    def wildcards(self) -> LStr:
        """All wildcards, including address group and wildcard items.

        :return: LIst of wildcard string.

        :example:
            address = Address("object-group NAME")
            address.wildcards() -> ["10.0.1.0 0.0.0.3", "10.0.2.0 0.0.0.3"]

            address = Address("10.0.0.0 0.0.1.3")
            address.wildcards() -> ["10.0.0.0 0.0.1.3"]
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

    # =========================== helper =============================

    def _cmd_addrgroup(self) -> str:
        """Address group line beginning.

        :return: nxos: "addrgroup", ios: "object-group".
        """
        if self._platform == "nxos":
            return "addrgroup"
        return "object-group"

    @staticmethod
    def _get_ipnet(obj) -> OIpNet:
        """Get IPv4Network from object."""
        if hasattr(obj, "ipnet"):
            if ipnet := getattr(obj, "ipnet"):
                if isinstance(ipnet, IPv4Network):
                    return ipnet
        return None

    @staticmethod
    def _get_items(obj) -> Optional[list]:
        """Get list of items from object."""
        if hasattr(obj, "items"):
            if items := getattr(obj, "items"):
                if isinstance(items, list):
                    return items
        return None

    @staticmethod
    def _is_address_any(line: str) -> bool:
        """Return True if address is any."""
        return line == "any"

    def _is_addrgroup(self, line: str) -> bool:
        """Return True if address is group "object-group NAME" or "addrgroup NAME"."""
        addrgroup_ = self._cmd_addrgroup()
        return line.startswith(addrgroup_)

    @staticmethod
    def _is_address_host(line: str) -> bool:
        """Return True if address is "host A.B.C.D"."""
        return line.startswith("host ") or bool(re.match(f"{h.OCTETS}$", line))

    @staticmethod
    def _is_address_prefix(line: str) -> bool:
        """Return True if address is prefix "A.B.C.D/LEN"."""
        return bool(line) and line[0].isdigit() and line.find("/") > -1

    @staticmethod
    def _is_address_wildcard(line: str) -> bool:
        """Return True if address is wildcard: "A.B.C.D A.B.C.D"."""
        return bool(line) and line[0].isdigit() and line.find(" ") > -1

    def _line_addrgroup(self, line):
        """Set attributes for address group: "object-group NAME" or "addrgroup NAME"."""
        regex = f"^{self._cmd_addrgroup()} (.+)"
        addrgroup = h.findall1(regex, line)
        h.check_name(addrgroup)
        self._type = "addrgroup"
        self._addrgroup = addrgroup
        self._wildcard = None

    def _line__any(self) -> None:
        """ACE address line, any."""
        self._type = "any"
        self._addrgroup = ""
        wildcard = "0.0.0.0 255.255.255.255"
        self._wildcard = Wildcard(wildcard, platform=self._platform, max_ncwb=self.max_ncwb)

    def _line__host(self, line: str) -> None:
        """Set attributes for host: host A.B.C.D."""
        ip_ = h.findall1(f"({h.OCTETS})", line)
        self._type = "host"
        self._addrgroup = ""
        wildcard = f"{ip_} 0.0.0.0"
        self._wildcard = Wildcard(wildcard, platform=self._platform, max_ncwb=self.max_ncwb)

    def _line__prefix(self, line: str) -> None:
        """Set attributes for prefix: A.B.C.D/LEN."""
        self._type = "prefix"
        self._addrgroup = ""
        ipnet = h.prefix_to_ipnet(line)
        wildcard = ipnet.with_hostmask.replace("/", " ")
        self._wildcard = Wildcard(wildcard, platform=self._platform, max_ncwb=self.max_ncwb)

        if ipnet.prefixlen == 32:
            self._type = "host"
            return
        if self.platform == "nxos":
            if str(ipnet) == "0.0.0.0/0":
                self._type = "any"
            return
        if self.platform == "ios":
            self._type = "wildcard"

    def _line__wildcard(self, line: str) -> None:
        """Set attributes for wildcard: A.B.C.D A.B.C.D."""
        self._type = "wildcard"
        self._addrgroup = ""
        self._wildcard = Wildcard(line, platform=self._platform, max_ncwb=self.max_ncwb)

        if isinstance(self._wildcard.ipnet, IPv4Network):
            if self._wildcard.ipnet.prefixlen == 32:
                self._type = "host"
            elif str(self._wildcard.ipnet) == "0.0.0.0/0":
                self._type = "any"
            elif self._platform == "nxos":
                self._type = "prefix"


# ============================ functions =============================


def collapse_(addresses: list) -> list:
    """Collapse LAddress, LAddressAg.

    :param addresses: List of Address objects.
    :return: Collapsed Address objects.
    :raises TypeError: Passed addresses not match: Address.ipnet is not IPv4Network.
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
