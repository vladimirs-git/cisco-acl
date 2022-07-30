"""ACE - Access Control Entry"""
from __future__ import annotations

from functools import total_ordering
from typing import List

import netports

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
    """ACE - Access Control Entry"""

    __slots__ = ("_platform", "_note", "_line", "_protocol_nr", "_port_nr",
                 "_sequence", "_action", "_protocol", "_srcaddr",
                 "_srcport",
                 "_dstaddr", "_dstport", "option")

    def __init__(self, line: str, **kwargs):
        """ACE - Access Control Entry
        :param str line: ACE config line
        :param str platform: Platform: "ios", "nxos" (default "ios")
        :param bool protocol_nr: Cisco ACL outputs well-known ip protocols as numbers
            True  - all ip protocols as numbers
            False - well-known ip protocols as names (default)
        :param bool port_nr: ACL prints well-known TCP/UDP ports as numbers
            True  - all tcp/udp ports as numbers
            False - well-known tcp/udp ports as names (default)
        :param note: Object description. Not part of the ACE configuration,
            can be used for ACEs sorting

        :example:
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
        self.option = ""
        super().__init__(line, **kwargs)

    def __hash__(self) -> int:
        return self.line.__hash__()

    def __eq__(self, other) -> bool:
        """== equality"""
        if self.__class__ == other.__class__:
            return self.__hash__() == other.__hash__()
        return False

    # noinspection DuplicatedCode
    def __lt__(self, other) -> bool:
        """< less than"""
        if hasattr(other, "sequence"):
            # sequence
            if self._sequence.number != other.sequence.number:
                return self._sequence.number < other.sequence.number
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
    def action(self) -> str:
        """ACE action: "permit", "deny"
        :return: ACE action
        :example:
            Ace("10 permit ip any any")
            return: "permit"
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
            "object-group NAME"
        :return: ACE destination Address object

        :example: ios
            Ace("permit ip host 1.1.1.1 any")
            return: Address("host 1.1.1.1")

        :example: nxos
            Ace("10 permit ip host 1.1.1.1 any", platform="nxos")
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
        """ACE destination ports: "eq www 443", ""neq 1 2", "lt 2", "gt 2", "range 1 3"
        :return: ACE destination Port object

        :example:
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
    def line(self) -> str:
        """ACE config line
        :return: ACE config line

        :example:
            Ace("10 permit ip any any")
            return: "10 permit ip any any"
        """
        items = [
            self._sequence.line,
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
        self.srcaddr = Address(ace_d["srcaddr"], platform=self.platform)
        self.dstaddr = Address(ace_d["dstaddr"], platform=self.platform)
        protocol = Protocol(line=ace_d["protocol"],
                            platform=self.platform,
                            port_nr=self.port_nr,
                            protocol_nr=self.protocol_nr)
        kwargs_port = dict(platform=self.platform, protocol=protocol.name, port_nr=self.port_nr)
        self.srcport = Port(ace_d["srcport"], **kwargs_port)
        self.dstport = Port(ace_d["dstport"], **kwargs_port)
        protocol.has_port = bool(self.srcport.line or self.dstport.line)
        self.protocol = protocol
        self.option = ace_d["option"]

    @property
    def platform(self) -> str:
        """Platform
        - "ios" - Cisco IOS (extended ACL)
        - "nxos" Cisco Nexus NX-OS
        """
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
            self._sequence.line,
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
        :return: ACE Protocol object

        :example:
            Ace("10 permit ip any any")
            return: Protocol("ip")
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
        :return: ACE source Address object

        :example: ios
            Ace("permit ip host 1.1.1.1 any")
            return: Address("host 1.1.1.1")

        :example: nxos
            Ace("10 permit ip host 1.1.1.1 any", platform="nxos")
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
        """ACE source ports: "eq www 443", ""neq 2", "lt 2", "gt 2", "range 1 3"
        :return: ACE source Port object

        :example:
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
        """Copies the self object
        :return: A shallow copy of self
        """
        ace = Ace(line=self.line,
                  platform=self.platform,
                  port_nr=self.port_nr,
                  note=self.note)
        return ace

    def range(self, protocol: str = "", srcport: str = "", dstport: str = "") -> LAce:
        """Generates range of protocols and TCP/UDP source/destination ports
        :param protocol: Range of ip protocols
        :param srcport: Range of source TCP/UDP ports
        :param dstport: Range of destination TCP/UDP ports
        :return: Newly generated *Ace* objects
        """
        if protocol and srcport:
            raise ValueError(f"mutually exclusive {protocol=} {srcport=}")
        if protocol and dstport:
            raise ValueError(f"mutually exclusive {protocol=} {dstport=}")
        aces: LAce = []  # return
        aces_ = self._range__protocol(protocol)
        aces.extend(aces_)
        aces_ = self._range__port("src", srcport)
        aces.extend(aces_)
        aces_ = self._range__port("dst", dstport)
        aces.extend(aces_)
        return aces

    # noinspection PyIncorrectDocstring
    @classmethod
    def rule(cls, **kwargs) -> LAce:
        """Converts data of Rule to Ace objects
        :param str platform: Platform: "ios", "nxos" (default "ios")
        :param str action: ACE action: "permit", "deny"
        :param List[str] srcaddrs: Source addresses
        :param List[str] dstaddrs: Destination addresses
        :param List[str] protocols: Protocols
        :param List[int] tcp_srcports: TCP source ports
        :param List[int] tcp_dstports: TCP destination ports
        :param List[int] udp_srcports: UDP source ports
        :param List[int] udp_dstports: UDP destination ports
        :return: List of Ace objects

        :example:
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
            return: [Ace("permit tcp host 10.0.0.1 10.0.0.0 0.0.0.3 eq www 443 log")]
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
                        aces_ = _split_by_ports(aces_, tcp_srcports, platform)
                    if proto == "udp" and udp_srcports:
                        aces_ = _split_by_ports(aces_, udp_srcports, platform)
                    aces_ = [f"{s} {dstaddr}" for s in aces_]
                    if proto == "tcp" and tcp_dstports:
                        aces_ = _split_by_ports(aces_, tcp_dstports, platform)
                    if proto == "udp" and udp_dstports:
                        aces_ = _split_by_ports(aces_, udp_dstports, platform)
                    if options:
                        aces_ = [_join_option(s, options) for s in aces_]
                    aces.extend(aces_)
        return sorted([Ace(s, platform=platform) for s in aces])

    # =========================== helpers ============================

    def _range__port(self, sdst: str, range_: str) -> LAce:
        """Generates range of TCP/UDP source/destination ports
        :param sdst: "src", "dst"
        :param range_: Range of src/dst ports
        :return: Newly generated *Ace* objects
        """
        aces: LAce = []  # return
        ports: LInt = netports.itcp(range_)
        for port in ports:
            ace = self.copy()
            port_o: Port = getattr(ace, f"{sdst}port")
            operator = port_o.operator or "eq"
            expected = ("eq", "gt", "lt", "neq")
            if operator not in expected:
                raise ValueError(f"invalid {operator=}, {expected=}")
            port_o._operator = operator
            port_o._items = [port]
            aces.append(ace)
        return aces

    def _range__protocol(self, range_: str) -> LAce:
        """Generates range of protocols
        :param range_: Range of src/dst ports
        :return: Newly generated *Ace* objects
        """
        aces: LAce = []  # return
        protocols: LInt = netports.iip(range_)
        for proto in protocols:
            ace = self.copy()
            ace.protocol = Protocol(str(proto))
            aces.append(ace)
        return aces


# =========================== helpers ============================

def _split_by_ports(aces: LStr, ports: LInt, platform: str) -> LStr:
    """If platform="ios", join ports to string and append to aces lines
    If platform="nxos", make multiple ACE lines, each port in separate ace line
    :param aces: List of ACE lines, ready for split
    :param ports: List of ports
    :param platform: Platform: "ios", "nxos"
    :return: Split list of ACE lines

    :example: source ports for nxos
        aces: "permit tcp any"
        ports: [1, 2]
        platform: "nxos"
        return: ["permit tcp any eq 1", "permit tcp any  eq 2"]

    :example: destination ports fo nxos
        aces: "permit tcp any eq 1 any"
        ports: [3, 4]
        platform: "nxos"
        return: ["permit tcp any eq 1 any eq 3", "permit tcp any eq 1 any eq 4"]

    :example: source ports for ios
        aces: "permit tcp any"
        ports: [1, 2, 3]
        platform: "ios"
        return: ["permit tcp any eq 1 2 3"]
    """
    aces_: LStr = []
    for ace in aces:
        if platform == "nxos":
            aces_.extend([_join_ports(ace=ace, ports=[i]) for i in ports])
        else:
            aces_.append(_join_ports(ace=ace, ports=ports))
    return aces_


def _join_ports(ace: str, ports: list) -> str:
    """Adds ports to ace line"""
    ports_ = " ".join([str(i) for i in ports])
    return f"{ace} eq {ports_}"


def _join_option(ace: str, options: LStr) -> str:
    """Adds options to ace line"""
    option = " ".join(options)
    return f"{ace} {option}"


LAce = List[Ace]
LLAce = List[LAce]
