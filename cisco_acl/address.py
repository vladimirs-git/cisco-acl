"""ACE Address"""

import re
from functools import total_ordering
from ipaddress import ip_network, IPv4Network
from typing import List

from cisco_acl import helpers as h
from cisco_acl.base import Base
from cisco_acl.types_ import OIpNetwork


@total_ordering
class Address(Base):
    """ACE Address"""

    _default: str = "any"

    __slots__ = ("_platform", "_note", "_line",
                 "_addrgroup", "_prefix", "_subnet", "_wildcard", "_ipnet")

    def __init__(self, line: str = "any", **kwargs):
        """ACE Address
        :param str line: Address line
            Line pattern        Platform    Description
            ==================  ==========  ===========================
            A.B.C.D A.B.C.D                 Address and wildcard bits
            A.B.C.D/LEN         nxos        Network prefix
            any                             Any host
            host A.B.C.D        ios         A single host
            object-group NAME   ios         Network object group
            addrgroup NAME      nxos        Network object group
        :param str platform: Platform: "ios", "nxos" (default "ios").
        :param str note: Object description. Not part of the ACE configuration,
            can be used for ACEs sorting

        :example: Wildcard
            line: "10.0.0.0 0.0.0.3"
            platform: "ios"
            result:
                self.line = "10.0.0.0 0.0.0.3"
                self.addrgroup = ""
                self.prefix = "10.0.0.0/30"
                self.subnet = "10.0.0.0 255.255.255.252"
                self.wildcard = "10.0.0.0 0.0.0.3"
                self.ipnet: ip_network("10.0.0.0/30")

        :example: Host
            line: "host 10.0.0.1"
            platform: "nxos"
            result:
                self.line = "10.0.0.1/32"
                self.addrgroup = ""
                self.prefix = "10.0.0.1/32"
                self.subnet = "10.0.0.1 255.255.255.255"
                self.wildcard = "10.0.0.1 0.0.0.0"
                self.ipnet: ip_network("10.0.0.1/32")

        :example: Object Group
            line: "object-group NAME"
            platform: "ios"
            result:
                self.line = "object-group NAME"
                self.addrgroup = "NAME"
                self.prefix = ""
                self.subnet = ""
                self.wildcard = ""
                self.ipnet: None
        """
        super().__init__(**kwargs)
        self.line = line

    # ========================== redefined ===========================

    def __hash__(self) -> int:
        return self.line.__hash__()

    def __eq__(self, other) -> bool:
        """== equality"""
        return self.__hash__() == other.__hash__()

    def __lt__(self, other) -> bool:
        """< less than"""
        if self.__class__ == other.__class__:
            if self.ipnet != other.ipnet:
                if self.ipnet and other.ipnet:
                    return self.ipnet < other.ipnet
                if self.ipnet and not other.ipnet:
                    return True
                return False
            return False
        return False

    # =========================== property ===========================

    @property
    def line(self) -> str:
        """ACE source or destination address line
        Line                    Platform    Description
        ======================  ==========  ====================
        "object-group NAME"     ios         Network object group
        "addrgroup NAME"        nxos        Network object group
        "any"                               Any source host
        "host 10.0.0.1"         ios         Single source host
        "10.0.0.1/32"           nxos        Network prefix
        "10.0.0.0 0.0.0.3"                  Network wildcard
        """
        return self._line

    @line.setter
    def line(self, line: str) -> None:
        line = self._init_line(line)

        # "any"
        if line in ["any", "0.0.0.0/0", "0.0.0.0 255.255.255.255"]:
            self._line__any()
            return

        # wildcard: "A.B.C.D A.B.C.D"
        octets = r"\d+\.\d+\.\d+\.\d+"
        regex = f"{octets} {octets}"
        if re.findall(regex, line):
            self._line__wildcard(line)
            return

        # prefix: "A.B.C.D/LEN"
        regex = octets + r"/\d+"
        if re.findall(regex, line):
            self._line__prefix(line)
            return

        # "host A.B.C.D"
        regex = f"host ({octets})"
        if ip_ := h.re_find_s(regex, line):
            self._line__host(ip_)
            return

        # "object-group NAME"
        regex = r"(?:object-group|addrgroup) (.+)"
        if name := h.re_find_s(regex, line):
            h.check_name(name)
            addr_line = "addrgroup" if self.platform == "nxos" else "object-group"
            addr_line = f"{addr_line} {name}"

            self._line: str = addr_line
            self._addrgroup: str = name
            self._subnet: str = ""
            self._ipnet: OIpNetwork = None
            self._prefix: str = ""
            self._wildcard: str = ""
            return

        raise ValueError(f"invalid address {line=}")

    @line.deleter
    def line(self) -> None:
        self._line__any()

    @property
    def addrgroup(self) -> str:
        """ACE address addrgroup
        :return: Address group name

        :example:
            Address("addrgroup NAME")
            return: "NAME"
        """
        return self._addrgroup

    @addrgroup.setter
    def addrgroup(self, name: str) -> None:
        if self.platform == "nxos":
            line = f"addrgroup {name}"
        else:
            line = f"object-group {name}"
        self.line = line

    @property
    def ipnet(self) -> OIpNetwork:
        """ACE address IPv4Network object
        :return: ip_network or None

        :example:
            Address("10.0.0.0 0.0.0.3")
            return: ip_network("10.0.0.0/30")
        """
        return self._ipnet

    @ipnet.setter
    def ipnet(self, ipnet: IPv4Network) -> None:
        if not isinstance(ipnet, IPv4Network):
            raise TypeError(f"{ipnet=} {IPv4Network} expected")
        self.line = str(ipnet)

    @property
    def platform(self) -> str:
        """Device platform type: "ios", "nxos" """
        return self._platform

    @platform.setter
    def platform(self, platform: str) -> None:
        self._platform = self._init_platform(platform=platform)
        self.line = self.line

    @property
    def prefix(self) -> str:
        """ACE address prefix
        :return: Subnet with prefix length

        :example:
            Address("10.0.0.0 0.0.0.3")
            return: "10.0.0.0/32"
        """
        return self._prefix

    @prefix.setter
    def prefix(self, prefix: str) -> None:
        self.line = prefix

    @property
    def subnet(self) -> str:
        """ACE address subnet
        :return: Subnet with mask

        :example:
            Address("10.0.0.0 0.0.0.3")
            return: "10.0.0.0 255.255.255.252"
        """
        return self._subnet

    @subnet.setter
    def subnet(self, subnet: str) -> None:
        h.check_subnet(subnet)
        subnet = h.invert_mask(subnet)
        self.line = subnet

    @property
    def wildcard(self) -> str:
        """ACE address wildcard
        :return: Subnet with wildcard

        :example:
            Address("10.0.0.0 0.0.0.3")
            return: "10.0.0.0 0.0.0.3"
        """
        return self._wildcard

    @wildcard.setter
    def wildcard(self, wildcard: str) -> None:
        h.check_subnet(wildcard)
        self.line = wildcard

    # =========================== helpers ============================

    def _line__any(self) -> None:
        """ACE address line, any"""
        self._line = "any"
        self._addrgroup = ""
        self._subnet = "0.0.0.0 0.0.0.0"
        ipnet = ip_network("0.0.0.0/0")
        if not isinstance(ipnet, IPv4Network):
            raise TypeError(f"{ipnet} expected {IPv4Network}")
        self._ipnet = ipnet
        self._prefix = "0.0.0.0/0"
        self._wildcard = "0.0.0.0 255.255.255.255"

    def _line__wildcard(self, line: str) -> None:
        """ACE address line, wildcard: A.B.C.D A.B.C.D
        Result line is different for ios, nxos, host

        :example: ios
            line: "10.0.0.0 0.0.0.3"
            self.platform: "ios"
            result: self.line = "10.0.0.0 0.0.0.3", ...

        :example: ios host
            line: "10.0.0.0 0.0.0.0"
            self.platform: "ios"
            result: self.line = "host 10.0.0.1", ...

        :example: nxos
            line: "10.0.0.0 0.0.0.3"
            self.platform: "nxos"
            result: self.line = "10.0.0.0/30", ...
        """
        wildcard = line
        if not h.is_valid_wildcard(wildcard):
            self._line = wildcard
            self._addrgroup = ""
            self._subnet = ""
            self._ipnet = None
            self._prefix = ""
            self._wildcard = wildcard
            return

        subnet = h.invert_mask(wildcard)
        ipnet = ip_network(subnet.replace(" ", "/"))
        if not isinstance(ipnet, IPv4Network):
            raise TypeError(f"{ipnet} expected {IPv4Network}")
        prefix = str(ipnet)
        if self.platform == "nxos":
            self._line = prefix
        else:
            self._line = wildcard
            if ipnet.prefixlen == 32:
                self._line = f"host {ipnet.network_address}"
        self._subnet = subnet
        self._ipnet = ipnet
        self._prefix = prefix
        self._wildcard = wildcard
        self._addrgroup = ""

    def _line__prefix(self, line: str) -> None:
        """ACE address line, prefix A.B.C.D/LEN
        Result line is different for ios, nxos, host

        :example: os host
            line: "10.0.0.1/32"
            self.platform: "ios"
            result: self.line = "host 10.0.0.1", ...

        :example: nxos
            line: "10.0.0.0/30"
            self.platform: "nxos"
            result: self.line = "10.0.0.0/30", ...
        """
        ipnet = ip_network(line)
        if not isinstance(ipnet, IPv4Network):
            raise TypeError(f"{ipnet} expected {IPv4Network}")
        subnet = ipnet.with_netmask.replace("/", " ")
        wildcard = ipnet.with_hostmask.replace("/", " ")
        prefix = str(ipnet)
        if self.platform == "nxos":
            self._line = prefix
        else:
            self._line = wildcard
            if ipnet.prefixlen == 32:
                self._line = f"host {ipnet.network_address}"

        self._addrgroup = ""
        self._subnet = subnet
        self._ipnet = ipnet
        self._prefix = prefix
        self._wildcard = wildcard

    def _line__host(self, ip_: str) -> None:
        """ACE address line, host
        Result line is different for ios, nxos, host

        :example: ios
            host: "10.0.0.1"
            self.platform: "ios"
            result: self.line = "host 10.0.0.1", ...

        :example: nxos
            host: "10.0.0.1"
            self.platform: "nxos"
            result: self.line = "10.0.0.1/32", ...
        """
        subnet = f"{ip_} 255.255.255.255"
        ipnet = ip_network(f"{ip_}/32")
        if not isinstance(ipnet, IPv4Network):
            raise TypeError(f"{ipnet} expected {IPv4Network}")
        prefix = str(ipnet)
        self._line = prefix if self.platform == "nxos" else f"host {ip_}"
        self._addrgroup = ""
        self._subnet = subnet
        self._ipnet = ipnet
        self._prefix = prefix
        self._wildcard = h.invert_mask(subnet)


LAddress = List[Address]
