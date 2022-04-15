"""ACE. Address."""

import re
from typing import List

from netaddr import IPNetwork  # type: ignore

from cisco_acl import helpers as h
from cisco_acl.base import Base
from cisco_acl.types_ import OIPNetwork


class Address(Base):
    """ACE. Address."""

    _default: str = "any"

    __slots__ = ("_platform", "_note", "_line",
                 "_addrgroup", "_prefix", "_subnet", "_wildcard", "_ipnet")

    def __init__(self, line: str, **kwargs):
        """ACE. Address.
        :param line: Address line.
            line pattern        platform    description
            ==================  ==========  ===========================
            A.B.C.D A.B.C.D                 Address and wildcard bits
            A.B.C.D/LEN         cnx         Network prefix
            any                             Any host
            host A.B.C.D        ios         A single host
            object-group NAME   ios         Network object group
            addrgroup NAME      cnx         Network object group

        :param kwargs: Params.
            platform: Supported platforms: "ios", "cnx". By default: "ios".
            note: Object description (used only in object).

        Example1:
            line: "10.0.0.0 0.0.0.3"
            platform: "ios"
                self.line = "10.0.0.0 0.0.0.3"
                self.addrgroup = ""
                self.prefix = "10.0.0.0/30"
                self.subnet = "10.0.0.0 255.255.255.252"
                self.wildcard = "10.0.0.0 0.0.0.3"
                self.ipnet: IPNetwork(10.0.0.0/30)
        Example2:
            line: "host 10.0.0.1"
            platform: "cnx"
                self.line = "10.0.0.1/32"
                self.addrgroup = ""
                self.prefix = "10.0.0.1/32"
                self.subnet = "10.0.0.1 255.255.255.255"
                self.wildcard = "10.0.0.1 0.0.0.0"
                self.ipnet: IPNetwork(10.0.0.1/32)
        Example3:
            line: "object-group NAME"
            platform: "ios"
                self.line = "object-group NAME"
                self.addrgroup = "NAME"
                self.prefix = ""
                self.subnet = ""
                self.wildcard = ""
                self.ipnet: None
        """
        super().__init__(**kwargs)
        self.line = line

    # =========================== property ===========================

    @property
    def line(self) -> str:
        """ACE address line.
        Line                    Platform    Description
        ======================  ==========  ====================
        "object-group NAME"     ios         Network object group
        "addrgroup NAME"        cnx         Network object group
        "any"                               Any source host
        "host 10.0.0.1"         ios         Single source host
        "10.0.0.1/32"           cnx         Network prefix
        "10.0.0.0 0.0.0.3"                  Network wildcard
        """
        return self._line

    @line.setter
    def line(self, line: str) -> None:
        line = self._init_line(line)

        # "any"
        if line == "any":
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
            addr_line = "addrgroup" if self.platform == "cnx" else "object-group"
            addr_line = f"{addr_line} {name}"

            self._line = addr_line
            self._addrgroup = name
            self._subnet = ""
            self._ipnet = None
            self._prefix = ""
            self._wildcard = ""
            return

        raise ValueError(f"invalid address {line=}")

    @line.deleter
    def line(self) -> None:
        self._line__any()

    @property
    def addrgroup(self) -> str:
        """ACE address addrgroup.
        Example:
            Address("addrgroup NAME")
            :return: "NAME" """
        return self._addrgroup

    @addrgroup.setter
    def addrgroup(self, name: str) -> None:
        if self.platform == "cnx":
            line = f"addrgroup {name}"
        else:
            line = f"object-group {name}"
        self.line = line

    @property
    def ipnet(self) -> OIPNetwork:
        """ACE address netaddr.IPNetwork object.
        Example:
            Address("10.0.0.0 0.0.0.3")
            :return: IPNetwork("10.0.0.0/30") """
        return self._ipnet

    @ipnet.setter
    def ipnet(self, ipnet: IPNetwork) -> None:
        if not isinstance(ipnet, IPNetwork):
            raise TypeError(f"{ipnet=} {IPNetwork} expected")
        self.line = str(ipnet)

    @property
    def prefix(self) -> str:
        """ACE address prefix.
        Example:
            Address("10.0.0.0 0.0.0.3")
            :return: "10.0.0.0/32" """
        return self._prefix

    @prefix.setter
    def prefix(self, prefix: str) -> None:
        self.line = prefix

    @property
    def subnet(self) -> str:
        """ACE address subnet.
        Example:
            Address("10.0.0.0 0.0.0.3")
            :return: "10.0.0.0 255.255.255.252" """
        return self._subnet

    @subnet.setter
    def subnet(self, subnet: str) -> None:
        h.check_subnet(subnet)
        subnet = h.invert_mask(subnet)
        self.line = subnet

    @property
    def wildcard(self) -> str:
        """ACE address wildcard.
        Example:
            Address("10.0.0.0 0.0.0.3")
            :return: "10.0.0.0 0.0.0.3" """
        return self._wildcard

    @wildcard.setter
    def wildcard(self, wildcard: str) -> None:
        h.check_subnet(wildcard)
        self.line = wildcard

    # =========================== helpers ============================

    def _line__any(self) -> None:
        """ACE address line, any."""
        self._line = "any"
        self._addrgroup = ""
        self._subnet = "0.0.0.0 0.0.0.0"
        self._ipnet = IPNetwork("0.0.0.0/0")
        self._prefix = "0.0.0.0/0"
        self._wildcard = "0.0.0.0 255.255.255.255"

    def _line__wildcard(self, line: str) -> None:
        """ACE address line, wildcard: A.B.C.D A.B.C.D.
        Result line is different for ios, cnx, host.

        Example1 - ios:
            line: "10.0.0.0 0.0.0.3"
            self.platform: "ios"
            return: self.line = "10.0.0.0 0.0.0.3", ...

        Example2 - ios host:
            line: "10.0.0.0 0.0.0.0"
            self.platform: "ios"
            return: self.line = "host 10.0.0.1", ...

        Example3 - cnx:
            line: "10.0.0.0 0.0.0.3"
            self.platform: "cnx"
            return: self.line = "10.0.0.0/30", ...
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
        ipnet = IPNetwork(subnet.replace(" ", "/"))
        prefix = str(ipnet)
        if self.platform == "cnx":
            self._line = prefix
        else:
            self._line = wildcard
            if ipnet.prefixlen == 32:
                self._line = f"host {ipnet.ip}"
        self._subnet = subnet
        self._ipnet = ipnet
        self._prefix = prefix
        self._wildcard = wildcard
        self._addrgroup = ""

    def _line__prefix(self, line: str, type_: str = "prefix") -> None:
        """ACE address line, prefix A.B.C.D/LEN.
        Result line is different for ios, cnx, host.

        Example1 - ios host:
            line: "10.0.0.1/32"
            self.platform: "ios"
            return: self.line = "host 10.0.0.1", ...

        Example2 - cnx:
            line: "10.0.0.0/30"
            self.platform: "cnx"
            return: self.line = "10.0.0.0/30", ...
        """
        ipnet = IPNetwork(line)
        subnet = f"{ipnet.ip} {ipnet.netmask}"
        wildcard = h.invert_mask(subnet)
        prefix = str(ipnet)
        if self.platform == "cnx":
            self._line = prefix
        else:
            self._line = wildcard
            if ipnet.prefixlen == 32:
                self._line = f"host {ipnet.ip}"

        self._addrgroup = ""
        self._subnet = subnet
        self._ipnet = ipnet
        self._prefix = prefix
        self._wildcard = wildcard

    def _line__host(self, ip_: str) -> None:
        """ACE address line, host.
        Result line is different for ios, cnx, host.

        Example1 - ios:
            host: "10.0.0.1"
            self.platform: "ios"
            return: self.line = "host 10.0.0.1", ...

        Example2 - cnx:
            host: "10.0.0.1"
            self.platform: "cnx"
            return: self.line = "10.0.0.1/32", ...
        """
        subnet = f"{ip_} 255.255.255.255"
        ipnet = IPNetwork(f"{ip_}/32")
        prefix = str(ipnet)
        self._line = prefix if self.platform == "cnx" else f"host {ip_}"
        self._addrgroup = ""
        self._subnet = subnet
        self._ipnet = ipnet
        self._prefix = prefix
        self._wildcard = h.invert_mask(subnet)


LAddress = List[Address]
