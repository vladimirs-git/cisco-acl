"""ACE - Access Control Entry"""
from __future__ import annotations

from functools import total_ordering
from typing import List

from cisco_acl import helpers as h
from cisco_acl.address import Address
from cisco_acl.base_ace import BaseAce
from cisco_acl.port import Port
from cisco_acl.protocol import Protocol
from cisco_acl.sequence import Sequence
from cisco_acl.static import DEFAULT_PLATFORM
from cisco_acl.types_ import LStr, LInt


@total_ordering
class Ace(BaseAce):
    """ACE (Access Control Entry)"""

    __slots__ = ("_platform", "_note", "_line",
                 "_sequence", "_action", "_protocol", "_srcaddr", "_srcport",
                 "_dstaddr", "_dstport", "_option")

    def __init__(self, line: str, **kwargs):
        """ACE (Access Control Entry).
        :param line: ACE line.
        :param kwargs: Params.
            platform: Supported platforms: "ios", "cnx". By default: "ios".
            note: Object description (can be used for ACEs sorting).

        Example:
        line: "10 permit tcp host 10.0.0.1 eq 179 10.0.0.0 0.0.0.3 eq 80 443 log"
        platform: "ios"
        note: "allow web"

        result:
            self.line = "10 permit tcp host 10.0.0.1 10.0.0.0 0.0.0.3 eq www 443 log"
            self.platform = "ios"
            self.sequence = Sequence("10")
            self.action = "permit"
            self.protocol = Protocol("tcp")
            self.srcaddr = Address("host 10.0.0.1")
            self.srcport = Port("eq bgp")
            self.dstaddr = Address("10.0.0.0 0.0.0.3")
            self.dstport = Port("eq www 443")
            self.option = "log"
            self.note = "allow web"
        """
        self._sequence = Sequence()
        self._action = ""
        self._protocol = Protocol()
        self._srcaddr = Address()
        self._srcport = Port()
        self._dstaddr = Address()
        self._dstport = Port()
        self._option = ""
        super().__init__(line, **kwargs)

    def __hash__(self) -> int:
        return self.line.__hash__()

    def __eq__(self, other) -> bool:
        """== equality"""
        if self.__class__ == other.__class__:
            return self.__hash__() == other.__hash__()
        return False

    def __lt__(self, other) -> bool:
        """< less than"""
        if hasattr(other, "sequence"):
            # sequence
            if self.sequence.number != other.sequence.number:
                return self.sequence.number < other.sequence.number
            # object
            if other.__class__.__name__ == "Remark":
                return False
            if other.__class__.__name__ == "AceGroup":
                return True
            if isinstance(other, Ace):
                # protocol
                if self.protocol.number != other.protocol.number:
                    return self.protocol.number < other.protocol.number
                # srcaddr
                if self.srcaddr.ipnet != other.srcaddr.ipnet:
                    if self.srcaddr.ipnet and other.srcaddr.ipnet:
                        return self.srcaddr.ipnet < other.srcaddr.ipnet
                    if self.srcaddr.ipnet and not other.srcaddr.ipnet:
                        return True
                    return False
                # srcport
                if self.srcport.operator and other.srcport.operator:
                    if self.srcport.operator != other.srcport.operator:
                        return self.srcport.operator < other.srcport.operator
                    if self.srcport.items[0] != other.srcport.items[0]:
                        return self.srcport.items[0] < other.srcport.items[0]
                    if self.srcport.items[-1] != other.srcport.items[-1]:
                        return self.srcport.items[-1] < other.srcport.items[-1]
                # dstaddr
                if self.dstaddr.ipnet != other.dstaddr.ipnet:
                    if self.dstaddr.ipnet and other.dstaddr.ipnet:
                        return self.dstaddr.ipnet < other.dstaddr.ipnet
                    if self.dstaddr.ipnet and not other.dstaddr.ipnet:
                        return True
                    return False
                # dstport
                if self.dstport.operator and other.dstport.operator:
                    if self.dstport.operator != other.dstport.operator:
                        return self.dstport.operator < other.dstport.operator
                    if self.dstport.items[0] != other.dstport.items[0]:
                        return self.dstport.items[0] < other.dstport.items[0]
                    if self.dstport.items[-1] != other.dstport.items[-1]:
                        return self.dstport.items[-1] < other.dstport.items[-1]
                # option, addrgroup
                return self.line < other.line
            raise TypeError(f"{other=} {Ace} expected")
        return False

    # =========================== property ===========================

    @property
    def action(self):
        """ACE action: "permit", "deny".
        Example:
            Ace("10 permit ip any any")
            :return: "permit"
        """
        return self._action

    @action.setter
    def action(self, action: str):
        expected = ["permit", "deny"]
        if action not in expected:
            raise ValueError(f"invalid {action=}, {expected=}")
        self._action = action

    @property
    def dstaddr(self) -> Address:
        """ACE source address: "any", "host A.B.C.D", "A.B.C.D A.B.C.D", "A.B.C.D/24",
            "object-group NAME".

        Example1:
            Ace("permit ip host 1.1.1.1 any")
            return: Address("host 1.1.1.1")

        Example2:
            Ace("10 permit ip host 1.1.1.1 any", platform="cnx")
            return: Address("1.1.1.1/32")
        """
        return self._dstaddr

    @dstaddr.setter
    def dstaddr(self, dstaddr: Address):
        if not isinstance(dstaddr, Address):
            raise TypeError(f"{dstaddr=} {Address} expected")
        self._dstaddr = dstaddr

    @property
    def dstport(self) -> Port:
        """ACE destination ports: "eq www 443", ""neq 1 2", "lt 2", "gt 2", "range 1 3".
        Example:
            Ace("permit tcp host 1.1.1.1 eq www 443 any eq 1025 log")
            return: Port("eq 1025")
        """
        return self._dstport

    @dstport.setter
    def dstport(self, dstport: Port):
        if not isinstance(dstport, Port):
            raise TypeError(f"{dstport=} {Port} expected")
        self._dstport = dstport

    @property
    def line(self):
        """ACE line.
        Example:
            Ace("10 permit ip any any")
            :return: "10 permit ip any any"
        """
        items = [
            self.sequence.line,
            self.action,
            self.protocol.line,
            self.srcaddr.line,
            self.srcport.line,
            self.dstaddr.line,
            self.dstport.line,
            self.option,
        ]
        return " ".join([s for s in items if s])

    @line.setter
    def line(self, line: str):
        line = self._init_line(line)
        h.check_line_length(line)
        ace_d = h.parse_ace(line)
        self.sequence.line = ace_d["sequence"]
        self.action = ace_d["action"]
        self.protocol = Protocol(ace_d["protocol"], platform=self.platform)
        self.srcaddr = Address(ace_d["srcaddr"], platform=self.platform)
        self.srcport = Port(ace_d["srcport"], platform=self.platform)
        self.dstaddr = Address(ace_d["dstaddr"], platform=self.platform)
        self.dstport = Port(ace_d["dstport"], platform=self.platform)
        self.option = ace_d["option"]

    @property
    def platform(self) -> str:
        """Platforms: "ios", "cnx"."""
        return self._platform

    @platform.setter
    def platform(self, platform: str):
        platform = self._init_platform(platform=platform)
        if platform == self.platform:
            return

        self._platform = platform
        self.protocol.platform = platform
        self.srcaddr.platform = platform
        self.srcport.platform = platform
        self.dstaddr.platform = platform
        self.dstport.platform = platform
        items = [
            self.sequence.line,
            self.action,
            self.protocol.line,
            self.srcaddr.line,
            self.srcport.line,
            self.dstaddr.line,
            self.dstport.line,
            self.option,
        ]
        items = [s for s in items if s]
        self.line = " ".join(items)

    @property
    def protocol(self) -> Protocol:
        """ACE protocol: "ip", "icmp", "tcp", etc.
        Example:
            Ace("10 permit ip any any")
            :return: Protocol("ip")
        """
        return self._protocol

    @protocol.setter
    def protocol(self, protocol: Protocol):
        if not isinstance(protocol, Protocol):
            raise TypeError(f"{protocol=} {Protocol} expected")
        self._protocol = protocol

    @property
    def srcaddr(self) -> Address:
        """ACE source address: "any", "host A.B.C.D", "A.B.C.D A.B.C.D", "A.B.C.D/24",
            "object-group NAME".

        Example1: Ace("permit ip host 1.1.1.1 any")
            return: Address("host 1.1.1.1")

        Example2: Ace("10 permit ip host 1.1.1.1 any", platform="cnx")
            return: Address("1.1.1.1/32")
        """
        return self._srcaddr

    @srcaddr.setter
    def srcaddr(self, srcaddr: Address):
        if not isinstance(srcaddr, Address):
            raise TypeError(f"{srcaddr=} {Address} expected")

        self._srcaddr = srcaddr

    @property
    def srcport(self) -> Port:
        """ACE source ports: "eq www 443", ""neq 2", "lt 2", "gt 2", "range 1 3".
        Example:
            Ace("permit tcp host 1.1.1.1 eq www 443 any eq 1025 log")
            return: Port("eq www 443")
        """
        return self._srcport

    @srcport.setter
    def srcport(self, srcport: Port):
        if not isinstance(srcport, Port):
            raise TypeError(f"{srcport=} {Port} expected")
        self._srcport = srcport

    # =========================== methods ============================

    def copy(self) -> Ace:
        """Return a shallow copy of self."""
        return Ace(self.line, platform=self.platform, note=self.note)

    @classmethod
    def rule(cls, **kwargs) -> LAce:
        """Convert data of Rule to Ace object.
        Example:
        :param kwargs: Params.
            platform: "ios"
            action: "permit"
            srcaddrs: ["10.0.0.1/32"]
            dstaddrs: ["10.0.0.0/30"]
            protocols: ["tcp"]
            tcp_srcports: []
            tcp_dstports: [80, 443]
            udp_srcports: []
            udp_dstports: []
            options: ["log"]
        :return: Ace("permit tcp host 10.0.0.1 10.0.0.0 0.0.0.3 eq www 443 log")
        """
        platform: str = kwargs.get("platform") or DEFAULT_PLATFORM
        action: str = kwargs["action"]
        action = dict(allow="permit", deny="deny")[action]
        options: LStr = kwargs.get("options") or []

        srcaddrs: LStr = kwargs.get("srcaddrs") or ["0.0.0.0/0"]
        dstaddrs: LStr = kwargs.get("dstaddrs") or ["0.0.0.0/0"]
        if not (srcaddrs and dstaddrs):
            raise ValueError(f"absent {srcaddrs=} {dstaddrs=}")
        srcaddrs = [h.make_wildcard(s) for s in srcaddrs]
        dstaddrs = [h.make_wildcard(s) for s in dstaddrs]

        protocols: LStr = kwargs.get("protocols") or ["ip"]
        tcp_srcports: LInt = kwargs.get("tcp_srcports") or []
        tcp_dstports: LInt = kwargs.get("tcp_dstports") or []
        udp_srcports: LInt = kwargs.get("udp_srcports") or []
        udp_dstports: LInt = kwargs.get("udp_dstports") or []
        if "tcp" in protocols and not (tcp_srcports or tcp_dstports):
            raise ValueError(f"absent {tcp_srcports=} {tcp_dstports=}")
        if "udp" in protocols and not (udp_srcports or udp_dstports):
            raise ValueError(f"absent {udp_srcports=} {udp_dstports=}")
        if "tcp" not in protocols and (tcp_srcports or tcp_dstports):
            raise ValueError(f"protocol tcp is required for {tcp_srcports=} {tcp_dstports=}")
        if "udp" not in protocols and (udp_srcports or udp_dstports):
            raise ValueError(f"protocol udp is required for {udp_srcports=} {udp_dstports=}")

        aces: LStr = []
        for srcaddr in srcaddrs:
            for dstaddr in dstaddrs:
                for proto in protocols:
                    aces_: LStr = [f"{action} {proto} {srcaddr}"]
                    if proto == "tcp" and tcp_srcports:
                        aces_ = split_by_ports(aces_, tcp_srcports, platform)
                    if proto == "udp" and udp_srcports:
                        aces_ = split_by_ports(aces_, udp_srcports, platform)
                    aces_ = [f"{s} {dstaddr}" for s in aces_]
                    if proto == "tcp" and tcp_dstports:
                        aces_ = split_by_ports(aces_, tcp_dstports, platform)
                    if proto == "udp" and udp_dstports:
                        aces_ = split_by_ports(aces_, udp_dstports, platform)
                    if options:
                        aces_ = [join_option(s, options) for s in aces_]
                    aces.extend(aces_)
        return sorted([Ace(s, platform=platform) for s in aces])


# =========================== helpers ============================


def split_by_ports(aces: LStr, ports: LInt, platform: str) -> LStr:
    """If platform="ios", join ports to string and append to aces lines.
    If platform="cnx", make multiple ACE lines, each port in separate ace line.

    Example1 source ports for cnx:
        :param aces: "permit tcp any"
        :param ports: [1, 2]
        :param platform: "cnx"
        :return: ["permit tcp any eq 1", "permit tcp any  eq 2"]

    Example2 destination ports fo cnx:
        :param aces: "permit tcp any eq 1 any"
        :param ports: [3, 4]
        :param platform: "cnx"
        :return: ["permit tcp any eq 1 any eq 3", "permit tcp any eq 1 any eq 4"]

    Example3 source ports for ios:
        :param aces: "permit tcp any"
        :param ports: [1, 2, 3]
        :param platform: "ios"
        :return: ["permit tcp any eq 1 2 3"]
    """
    aces_: LStr = []
    for ace in aces:
        if platform == "cnx":
            aces_.extend([join_ports(ace=ace, ports=[i]) for i in ports])
        else:
            aces_.append(join_ports(ace=ace, ports=ports))
    return aces_


def join_ports(ace: str, ports: list) -> str:
    """Add ports to ace line"""
    ports_ = " ".join([str(i) for i in ports])
    return f"{ace} eq {ports_}"


def join_option(ace: str, options: LStr) -> str:
    """Add options to ace line"""
    option = " ".join(options)
    return f"{ace} {option}"


LAce = List[Ace]
LLAce = List[LAce]
