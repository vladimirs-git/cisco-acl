"""BaseAddress - Parent of: Address, AddressAg"""

import logging
import re
from abc import abstractmethod
from functools import total_ordering
from ipaddress import IPv4Network
from typing import Optional

from cisco_acl import helpers as h
from cisco_acl.base import Base
from cisco_acl.types_ import OIpNet, DAny, LIpNet, LStr


@total_ordering  # type: ignore
class BaseAddress(Base):
    """BaseAddress - Parent of: Address, AddressAg"""

    def __init__(self, **kwargs):
        """BaseAddress
        :param platform: Platform: "ios", "nxos" (default "ios")

        Helpers
        :param note: Object description
        """
        self._type = ""
        self._addrgroup: str = ""
        self._ipnet: OIpNet = None
        self._wildcard: str = ""
        self._items = []
        super().__init__(**kwargs)  # platform, note

    def __repr__(self):
        params = self._repr__parameters()
        params = self._repr__add_param("items", params)
        kwargs = ", ".join(params)
        name = self.__class__.__name__
        return f"{name}({kwargs})"

    # ========================== redefined ===========================

    def __hash__(self) -> int:
        return (self._addrgroup, self._wildcard).__hash__()

    def __eq__(self, other) -> bool:
        """== equality"""
        if self.__class__ == other.__class__:
            return self.__hash__() == other.__hash__()
        return False

    def __lt__(self, other) -> bool:
        """< less than"""
        if self.__class__ == other.__class__:
            if self._ipnet and other.ipnet:
                return self._ipnet < other.ipnet
            if self._ipnet and not other.ipnet:
                return True
            if not self._ipnet and other.ipnet:
                return False
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
    def addrgroup(self) -> str:
        """Address addrgroup name
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
        """Address IPv4Network
        :return: IPv4Network or None

        :example:
            self: Address("10.0.0.0 0.0.0.3", platform="ios")
            return: IPv4Network("10.0.0.0/30")

        :example:
            self: Address("object-group NAME", platform="ios")
            return: None
        """
        return self._ipnet

    @property
    def line(self) -> str:
        """ACE address line

        :example:
            self: Address("host 10.0.0.1", platform="nxos")
            return: "host 10.0.0.0.1"
        """
        if self._type == "addrgroup":
            return f"{self._cmd_addrgroup()}{self._addrgroup}"
        if self._type == "any":
            return "any"
        if self._type == "host":
            if not isinstance(self._ipnet, IPv4Network):
                raise TypeError(f"{self._ipnet=} {IPv4Network} expected")
            return f"host {self._ipnet.network_address}"
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
    def prefix(self) -> str:
        """Address prefix
        :return: Subnet with prefix length

        :example:
            self: Address("10.0.0.0 0.0.0.3", platform="ios")
            return: "10.0.0.0/32"
        """
        if self._ipnet:
            return str(self._ipnet)
        return ""

    @property
    def subnet(self) -> str:
        """Address subnet
        :return: Subnet with mask

        :example:
            self: Address("10.0.0.0 0.0.0.3", platform="ios")
            return: "10.0.0.0 255.255.255.252"
        """
        if not self._ipnet:
            return ""
        return self._ipnet.with_netmask.replace("/", " ")

    @property
    def wildcard(self) -> str:
        """Address wildcard
        :return: Subnet with wildcard mask

        :example:
            self: Address("10.0.0.0/30", platform="ios")
            return: "10.0.0.0 0.0.0.3"
        """
        return self._wildcard

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

    @abstractmethod
    def copy(self):
        """Copies the self object"""

    @abstractmethod
    def data(self) -> DAny:
        """Returns *Address* data as *dict*"""

    def ipnets(self) -> LIpNet:
        """Address IPv4Networks (from address group also)
        :return: List of IPv4Network

        :example:
            self: Address("10.0.0.0 0.0.0.3", platform="ios")
            return: [IPv4Network("10.0.0.0/30")]

        :example:
            self: Address("object-group NAME", platform="ios")
            self.items: [Address("10.1.1.0 0.0.0.3"), Address("10.2.2.0 0.0.0.3")]
            return: [IPv4Network("10.1.1.0/30"), IPv4Network("10.2.2.0/30")]

        :example: not contiguous wildcard
            self: Address("10.0.0.0 0.0.3.3")
            raises: ValueError
        """
        if self._ipnet and isinstance(self._ipnet, IPv4Network):
            return [self._ipnet]
        ipnets: LIpNet = []
        for item in self._items:
            ipnet = getattr(item, "ipnet")
            if not isinstance(ipnet, IPv4Network):
                raise TypeError(f"{self.line} {ipnet=} {IPv4Network} expected")
            ipnets.append(ipnet)
        return ipnets

    def prefixes(self) -> LStr:
        """Address prefixes (from address group also)
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

    def subnets(self) -> LStr:
        """Address subnets (from address group also)
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
        """Address wildcards (from address group also)
        :return: Subnets with wildcard mask

        :example:
            self: Address("object-group NAME", platform="ios")
            return: ["10.0.1.0 0.0.0.3", "10.0.2.0 0.0.0.3"]

        :example:
            self: Address("10.0.0.0 0.0.0.3", platform="ios")
            return: ["10.0.0.0 0.0.0.3"]
        """
        if self._wildcard:
            return [self._wildcard]
        wildcards: LStr = []
        for item in self._items:
            wildcard = getattr(item, "wildcard")
            if not wildcard:
                raise ValueError(f"{self.line} {wildcard=} expected")
            wildcards.append(str(wildcard))
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
        if line == "any":
            return True
        return False

    def _is_addrgroup(self, line: str) -> bool:
        """True if address is group "object-group NAME" or "addrgroup NAME" """
        regex = f"^{self._cmd_addrgroup()}(.+)"
        if re.match(regex, line):
            return True
        return False

    @staticmethod
    def _is_address_host(line: str) -> bool:
        """True if address is "host A.B.C.D" """
        regex = f"host {h.OCTETS}"
        if re.match(regex, line):
            return True
        return False

    @staticmethod
    def _is_address_prefix(line: str) -> bool:
        """True if address is prefix "A.B.C.D/LEN" """
        regex = h.OCTETS + r"/\d+"
        if re.match(regex, line):
            return True
        return False

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
        if re.match(regex, line):
            return True
        return False

    def _line_addrgroup(self, line):
        """Sets attributes for address group: "object-group NAME" or "addrgroup NAME" """
        regex = f"^{self._cmd_addrgroup()}(.+)"
        addrgroup = h.findall1(regex, line)
        h.check_name(addrgroup)
        self._type = "addrgroup"
        self._addrgroup = addrgroup
        self._ipnet = None
        self._wildcard = ""

    def _line__any(self) -> None:
        """ACE address line, any"""
        self._type = "any"
        self._addrgroup = ""
        self._ipnet = IPv4Network("0.0.0.0/0")
        self._wildcard = "0.0.0.0 255.255.255.255"

    def _line__host(self, line: str) -> None:
        """Sets attributes for host: host A.B.C.D"""
        ip_ = h.findall1(f"^host ({h.OCTETS})", line)
        self._type = "host"
        self._addrgroup = ""
        self._ipnet = IPv4Network(f"{ip_}/32")
        self._wildcard = h.invert_mask(f"{ip_} 255.255.255.255")

    def _line__prefix(self, line: str) -> None:
        """Sets attributes for prefix: A.B.C.D/LEN"""
        prefix = line
        try:
            ipnet = IPv4Network(address=prefix)
        except ValueError as ex:
            if "has host bits set" not in str(ex):
                raise type(ex)(*ex.args)
            line_ = prefix.split("/")[0] + "/32"
            ipnet = IPv4Network(address=line_)
            msg = f"ValueError: {ex}, invalid {prefix} fixed to {ipnet}"
            logging.warning(msg)

        _type = "prefix"
        if self.platform == "ios":
            _type = "wildcard"

        self._type = _type
        self._addrgroup = ""
        self._ipnet = ipnet
        self._wildcard = ipnet.with_hostmask.replace("/", " ")

    def _line__wildcard(self, line: str) -> None:
        """Sets attributes for wildcard: A.B.C.D A.B.C.D"""
        wildcard = line
        self._type = "wildcard"
        self._addrgroup = ""
        self._wildcard = wildcard

        mask = wildcard.split(" ")[1]
        if not h.is_contiguous_wildcard(wildcard):
            self._ipnet = None
        elif mask == "255.255.255.255":
            self._ipnet = IPv4Network("0.0.0.0/0")
            self._wildcard = "0.0.0.0 255.255.255.255"
        else:
            subnet = h.invert_mask(wildcard).replace(" ", "/")
            self._ipnet = IPv4Network(subnet)
