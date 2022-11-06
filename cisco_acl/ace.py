"""ACE - Access Control Entry"""
from __future__ import annotations

from functools import total_ordering
from typing import List

from cisco_acl import helpers as h
from cisco_acl.address import Address
from cisco_acl.ace_base import AceBase
from cisco_acl.option import Option
from cisco_acl.port import Port
from cisco_acl.protocol import Protocol
from cisco_acl.types_ import DAny, OBool, DStr, LStr


@total_ordering
class Ace(AceBase):
    """ACE - Access Control Entry"""

    def __init__(self, line: str, **kwargs):
        """ACE - Access Control Entry
        :param line: ACE config, a line that starts with "allow" or "deny"
        :type line: str

        :param platform: Platform: "ios" (default), "nxos"
        :type platform: str

        Helpers
        :param note: Object description
        :type note: Any

        :param max_ncwb: Max count of non-contiguous wildcard bits
        :type max_ncwb: int

        :param protocol_nr: Well-known ip protocols as numbers
            True  - all ip protocols as numbers
            False - well-known ip protocols as names (default)
        :type protocol_nr: bool

        :param port_nr: Well-known TCP/UDP ports as numbers
            True  - all tcp/udp ports as numbers
            False - well-known tcp/udp ports as names (default)
        :type port_nr: bool

        :example:
            ace=Ace("10 permit tcp host 10.0.0.1 eq 179 10.0.0.0 0.0.0.3 eq 80 443 log")

            ace.line == "10 permit tcp host 10.0.0.1 10.0.0.0 0.0.0.3 eq www 443 log"
            ace.platform == "ios"
            ace.sequence == 10
            ace.action == "permit"
            ace.protocol == Protocol("tcp")
            ace.srcaddr == Address("host 10.0.0.1")
            ace.srcport == Port("eq bgp")
            ace.dstaddr == Address("10.0.0.0 0.0.0.3")
            ace.dstport == Port("eq www 443")
            ace.option == Option("log")
        """
        self._action = ""
        self._protocol = Protocol()
        self._srcaddr = Address("any")
        self._srcport = Port()
        self._dstaddr = Address("any")
        self._dstport = Port()
        self._option = Option()
        super().__init__(**kwargs)  # platform, note, protocol_nr, port_nr, max_ncwb
        if srcaddr := kwargs.get("srcaddr") or {}:
            self._srcaddr = Address(**srcaddr)
        if dstaddr := kwargs.get("dstaddr") or {}:
            self._dstaddr = Address(**dstaddr)
        self.line = line

    # ========================== redefined ===========================

    # noinspection DuplicatedCode
    def __lt__(self, other) -> bool:
        """< less than"""
        if hasattr(other, "sequence"):
            # sequence
            if self._sequence != other.sequence:
                return self._sequence < other.sequence
            # object
            if other.__class__.__name__ == "Remark":
                return False
            if other.__class__.__name__ == "AceGroup":
                return True
            if isinstance(other, Ace):
                # protocol
                if self._protocol.number != other.protocol.number:
                    return self._protocol.number < other.protocol.number
                # srcaddr
                if self._srcaddr.ipnet != other.srcaddr.ipnet:
                    return self._lt__srcaddr(other)
                # srcport
                if self._srcport.operator and other.srcport.operator:
                    is_lt = self._lt__srcport(other)
                    if isinstance(is_lt, bool):
                        return is_lt
                # dstaddr
                if self._dstaddr.ipnet != other.dstaddr.ipnet:
                    return self._lt__dstaddr(other)
                # dstport
                if self._dstport.operator and other.dstport.operator:
                    is_lt = self._lt__dstport(other)
                    if isinstance(is_lt, bool):
                        return is_lt
                # option, addrgroup
                return self.line < other.line
        return False

    # =========================== property ===========================

    @property
    def action(self) -> str:
        """ACE action: "permit", "deny"
        :return: ACE action
        :example:
            self: Ace("10 permit ip any any")
            return: "permit"
        """
        return self._action

    @property
    def dstaddr(self) -> Address:
        """ACE source address: "any", "host A.B.C.D", "A.B.C.D A.B.C.D", "A.B.C.D/24",
            "object-group NAME"
        :return: ACE destination Address object

        :example: ios
            self: Ace("permit ip host 1.1.1.1 any")
            return: Address("host 1.1.1.1")

        :example: nxos
            self: Ace("10 permit ip host 1.1.1.1 any", platform="nxos")
            return: Address("1.1.1.1/32")
        """
        return self._dstaddr

    @property
    def dstport(self) -> Port:
        """ACE destination ports: "eq www 443", ""neq 1 2", "lt 2", "gt 2", "range 1 3"
        :return: ACE destination Port object

        :example:
            self: Ace("permit tcp host 1.1.1.1 eq www 443 any eq 1025 log")
            return: Port("eq 1025")
        """
        return self._dstport

    @property
    def line(self) -> str:
        """ACE config, a line that starts with "allow" or "deny"
        :return: ACE config, a line that starts with "allow" or "deny"

        :example:
            self: Ace("10 permit ip any any")
            return: "10 permit ip any any"
        """
        if self._type == "extended":
            items = [
                self._sequence_s(),
                self._action,
                self._protocol.line,
                self._srcaddr.line,
                self._srcport.line,
                self._dstaddr.line,
                self._dstport.line,
                self._option.line,
            ]
        else:  # standard
            items = [
                self._sequence_s(),
                self._action,
                self._srcaddr.line,
                self._option.line,
            ]
        return " ".join([s for s in items if s])

    @line.setter
    def line(self, line: str) -> None:
        line = h.init_line(line)

        # parse line to dict
        if ace_d := h.parse_ace_extended(line):
            self._type = "extended"
        else:
            if ace_d := h.parse_ace_standard(line):
                self._type = "standard"
            else:
                raise ValueError(f"invalid {line=}")
        self._check_parsed_elements(data=ace_d, line=line)

        self._sequence = h.init_int(ace_d["sequence"])
        self._action = h.init_ace_action(ace_d["action"])
        self._srcaddr = Address(ace_d["srcaddr"],
                                platform=self._platform,
                                items=self._srcaddr.items,
                                max_ncwb=self.max_ncwb)
        self._dstaddr = Address(ace_d["dstaddr"],
                                platform=self._platform,
                                items=self._dstaddr.items,
                                max_ncwb=self.max_ncwb)
        protocol_o = Protocol(line=ace_d["protocol"],
                              platform=self._platform,
                              port_nr=self._port_nr,
                              protocol_nr=self._protocol_nr)
        kwargs_port = dict(platform=self._platform, protocol=protocol_o.name, port_nr=self._port_nr)
        self._srcport = Port(ace_d["srcport"], **kwargs_port)
        self._dstport = Port(ace_d["dstport"], **kwargs_port)
        protocol_o.has_port = bool(self._srcport.line or self._dstport.line)
        self._protocol = protocol_o
        self._option = Option(ace_d["option"], platform=self._platform)

    @property
    def option(self) -> Option:
        """ACE option: "syn", "ack", "log", etc
        :return: ACE option
        :example:
            self: Ace("10 permit ip any any log")
            return: "log"
        """
        return self._option

    @property
    def platform(self) -> str:
        """Platform: "ios" Cisco IOS, "nxos" Cisco Nexus NX-OS"""
        return self._platform

    @platform.setter
    def platform(self, platform: str) -> None:
        """Changes platform, normalizes self.items regarding the new platform
        :param platform: Platform: "ios" (default), "nxos"
        """
        self._platform = h.init_platform(platform=platform)
        self._protocol.platform = self._platform
        self._srcaddr.platform = self._platform
        self._srcport.platform = self._platform
        self._dstaddr.platform = self._platform
        self._dstport.platform = self._platform
        self._option.platform = self._platform
        data = self.data(uuid=True)
        self.__init__(**data)  # type: ignore

    @property
    def protocol(self) -> Protocol:
        """ACE protocol: "ip", "icmp", "tcp", etc.
        :return: ACE Protocol object

        :example:
            self: Ace("10 permit ip any any")
            return: Protocol("ip")
        """
        return self._protocol

    @property
    def srcaddr(self) -> Address:
        """ACE source address: "any", "host A.B.C.D", "A.B.C.D A.B.C.D", "A.B.C.D/24",
            "object-group NAME".
        :return: ACE source Address object

        :example: ios
            self: Ace("permit ip host 1.1.1.1 any")
            return: Address("host 1.1.1.1")

        :example: nxos
            self: Ace("10 permit ip host 1.1.1.1 any", platform="nxos")
            return: Address("1.1.1.1/32")
        """
        return self._srcaddr

    @property
    def srcport(self) -> Port:
        """ACE source ports: "eq www 443", ""neq 2", "lt 2", "gt 2", "range 1 3"
        :return: ACE source Port object

        :example:
            self: Ace("permit tcp host 1.1.1.1 eq www 443 any eq 1025 log")
            return: Port("eq www 443")
        """
        return self._srcport

    @property
    def type(self) -> str:
        """ACL type: standard, extended"""
        return self._type

    @type.setter
    def type(self, type_: str) -> None:
        type_ = h.init_type(type=type_, platform=self.platform)
        if self._type == "extended" and type_ == "standard":
            if self._srcaddr.addrgroup:
                addrgroup = self._srcaddr.addrgroup
                raise ValueError(f"mutually exclusive: type={type_!r}, {addrgroup=}")
            self._protocol.line = "ip"
            self._srcport.line = ""
            self._dstaddr.line = "any"
            self._dstport.line = ""
            self.option.line = ""
        self._type = type_
        data = self.data(uuid=True)
        self.__init__(**data)  # type: ignore

    # =========================== method =============================

    def data(self, uuid: bool = False) -> DAny:
        """Converts *Ace* object to *dict*
        :param uuid: Returns self.uuid in data
        :type uuid: bool

        :return: ACE data

        :example:
            ace = Ace("10 permit tcp host 10.0.0.1 10.0.0.0 0.0.0.3 eq 80 443 log")
            ace.data() -> {
                "line": "10 permit tcp host 10.0.0.1 10.0.0.0 0.0.0.3 eq www log",
                "platform": "ios",
                "type": "extended",
                "sequence": 10,
                "action": "permit",
                "protocol": {"line": "tcp",
                             "platform": "ios",
                             "note": "",
                             "protocol_nr": False,
                             "has_port": True,
                             "name": "tcp",
                             "number": 6},
                "srcaddr": {"line": "host 10.0.0.1",
                            "platform": "ios",
                            "items": [],
                            "note": "",
                            "addrgroup": "",
                            "ipnet": IPv4Network("10.0.0.1/32"),
                            "prefix": "10.0.0.1/32",
                            "subnet": "10.0.0.1 255.255.255.255",
                            "wildcard": "10.0.0.1 0.0.0.0"},
                "srcport": {"line": "",
                            "platform": "ios",
                            "protocol": "",
                            "note": "",
                            "port_nr": False,
                            "items": [],
                            "operator": "",
                            "ports": [],
                            "sport": ""},
                "dstaddr": {"line": "10.0.0.0 0.0.0.3",
                            "platform": "ios",
                            "items": [],
                            "note": "",
                            "addrgroup": "",
                            "ipnet": IPv4Network("10.0.0.0/30"),
                            "prefix": "10.0.0.0/30",
                            "subnet": "10.0.0.0 255.255.255.252",
                            "wildcard": "10.0.0.0 0.0.0.3"},
                "dstport": {"line": "eq www 443",
                            "platform": "ios",
                            "protocol": "tcp",
                            "note": "",
                            "port_nr": False,
                            "items": [80,
                            443],
                            "operator": "eq",
                            "ports": [80,
                            443],
                            "sport": "80,443"},
                "option": {"line": "log",
                           "platform": "ios",
                           "note": "",
                           "flags": [],
                           "logs": ["log"]},
                "note": "a"}
        """
        data = dict(
            # init
            line=self.line,
            platform=self._platform,
            type=self._type,
            note=self.note,
            max_ncwb=self.max_ncwb,
            protocol_nr=self._protocol_nr,
            port_nr=self._port_nr,
            # property
            sequence=self._sequence,
            action=self._action,
            protocol=self._protocol.data(uuid=uuid),
            srcaddr=self._srcaddr.data(uuid=uuid),
            srcport=self._srcport.data(uuid=uuid),
            dstaddr=self._dstaddr.data(uuid=uuid),
            dstport=self._dstport.data(uuid=uuid),
            option=self._option.data(uuid=uuid),
        )
        if uuid:
            data["uuid"] = self.uuid
        return data

    def shadow_of(self, other: Ace, skip: LStr = None) -> bool:
        """Checks is ACE in the shadow of other ACE
        NOTES:
        - Method compare *Ace* with the same action. ACEs where self.action=="permit" and
            other.action=="deny" not taken into account (skip checking)
        :param other: Other *Ace* object (rule in the top)
        :param skip: Skips checking specified address type: "addrgroup", "nc_wildcard"

        :return: True - self *Ace* is in the shadow of other *Ace*
        :raises ValueError: addrgroup without addresses, non-contiguous wildcard

        :example: self is in the shadow of other, because tcp=2 is in tcp=[1, 2, 3]
            other.line == "permit tcp any any range 1 3"
            self.line == "permit tcp any any eq 2"
            return: True
        """
        if self._action != other.action:
            return False
        if not self._shadow_of__protocol(other):
            return False
        if not self._shadow_of__srcaddr(other=other, skip=skip):
            return False
        if not self._shadow_of__dstaddr(other=other, skip=skip):
            return False
        if not self._shadow_of__srcport(other):
            return False
        if not self._shadow_of__dstport(other):
            return False
        if not self._shadow_of__option(other):
            return False
        return True

    def ungroup_ports(self) -> LAce:
        """If self.srcport or self.dstport has "eq" or "neq" with multiple ports,
            then split them to multiple *Ace*
        :return: List of *Ace* with single port in each line
        :example:
            ace = Ace("permit tcp any eq 1 2 any eq 3 4", platform="ios")
            ace.split_ports -> [Ace("permit tcp any eq 1 any eq 3"),
                                Ace("permit tcp any eq 1 any eq 4"),
                                Ace("permit tcp any eq 2 any eq 3"),
                                Ace("permit tcp any eq 2 any eq 4")]
        """
        _aces: LAce = []
        if self.srcport.operator in ["eq", "neq"]:
            for item in self.srcport.items:
                ace_o = self.copy()
                ace_o.srcport.items = [item]
                _aces.append(ace_o)
        else:
            _aces.append(self.copy())

        aces = []  # result
        for ace_o_ in _aces:
            if ace_o_.dstport.operator in ["eq", "neq"]:
                for item in ace_o_.dstport.items:
                    ace_o = ace_o_.copy()
                    ace_o.dstport.items = [item]
                    aces.append(ace_o)
            else:
                aces.append(ace_o_.copy())
        if len(aces) == 1:
            return [self]
        return aces

    # =========================== helper =============================

    @staticmethod
    def _check_parsed_elements(line: str, data: DStr) -> bool:
        """Checks parsed ACE elements
        :return: True if all elements are valid
        :raises: ValueError - some element in line is invalid
        """
        protocol = data["protocol"]
        srcport = data["srcport"]
        dstport = data["dstport"]
        if not (protocol or srcport or dstport):
            raise ValueError(f"invalid {line=}, required one of: {protocol=} {srcport=} {dstport=}")
        if protocol == "ip" and srcport:
            raise ValueError(f"invalid {line=}, mutually exclusive {protocol=} {srcport=}")
        if protocol == "ip" and dstport:
            raise ValueError(f"invalid {line=}, mutually exclusive {protocol=} {dstport=}")
        return True

    # noinspection DuplicatedCode
    def _shadow_of__srcaddr(self, other: Ace, skip: LStr = None) -> bool:
        """True if bottom address is in the shadow of the top address
        :param other: *Ace* in the top
        :param skip: Skips checking specified address type: "addrgroup", "nc_wildcard"
        """
        skip = skip or []
        if "addrgroup" in skip:
            if "addrgroup" in [self.srcaddr.type, other.srcaddr.type]:
                return False
        elif "nc_wildcard" in skip:
            if "wildcard" in [self.srcaddr.type, other.srcaddr.type]:
                if not (self.srcaddr.ipnet and other.srcaddr.ipnet):
                    return False

        tops = other.srcaddr.ipnets()
        bottoms = self._srcaddr.ipnets()
        is_subnet = h.subnet_of(tops=tops, bottoms=bottoms)
        return is_subnet

    # noinspection DuplicatedCode
    def _shadow_of__dstaddr(self, other: Ace, skip: LStr = None) -> bool:
        """True if bottom address is in the shadow of the top address
        :param other: *Ace* in the top
        :param skip: Skips checking specified address type: "addrgroup", "nc_wildcard"
        """
        skip = skip or []
        if "addrgroup" in skip:
            if "addrgroup" in [self.dstaddr.type, other.dstaddr.type]:
                return False
        elif "nc_wildcard" in skip:
            if "wildcard" in [self.dstaddr.type, other.dstaddr.type]:
                if not (self.dstaddr.ipnet and other.dstaddr.ipnet):
                    return False

        tops = other.dstaddr.ipnets()
        bottoms = self._dstaddr.ipnets()
        return h.subnet_of(tops=tops, bottoms=bottoms)

    def _shadow_of__protocol(self, other: Ace) -> bool:
        """True if self.protocol is in the shadow of the  other.protocol"""
        if other.protocol.name == "ip":
            return True
        return other.protocol.number == self._protocol.number

    def _shadow_of__srcport(self, other: Ace) -> bool:
        """True if self.srcport is in the shadow of the  other.srcport"""
        if top := set(other.srcport.ports):
            if bottom := set(self._srcport.ports):
                diff = bottom.intersection(top)
                return diff == bottom
            return False
        return True

    def _shadow_of__dstport(self, other: Ace) -> bool:
        """True if self.dstport is in the shadow of the  other.dstport"""
        if top := set(other.dstport.ports):
            if bottom := set(self._dstport.ports):
                diff = bottom.intersection(top)
                return diff == bottom
            return False
        return True

    def _shadow_of__option(self, other: Ace) -> bool:
        """True if self.dstport is in the shadow of the  other.dstport"""
        if top := set(other.option.flags):
            if bottom := set(self._option.flags):
                diff = bottom.intersection(top)
                return diff == bottom
            return False
        return True

    def _lt__srcaddr(self, other: Ace) -> bool:
        """< less than, srcaddr"""
        if self._srcaddr.ipnet and other.srcaddr.ipnet:
            return self._srcaddr.ipnet < other.srcaddr.ipnet
        if self._srcaddr.ipnet and not other.srcaddr.ipnet:
            return True
        return False

    def _lt__dstaddr(self, other: Ace) -> bool:
        """< less than, dstaddr"""
        if self._dstaddr.ipnet and other.dstaddr.ipnet:
            return self._dstaddr.ipnet < other.dstaddr.ipnet
        if self._dstaddr.ipnet and not other.dstaddr.ipnet:
            return True
        return False

    # noinspection DuplicatedCode
    def _lt__srcport(self, other: Ace) -> OBool:
        """< less than, srcport"""
        if self._srcport.operator != other.srcport.operator:
            return self._srcport.operator < other.srcport.operator
        if self._srcport.items[0] != other.srcport.items[0]:
            return self._srcport.items[0] < other.srcport.items[0]
        if self._srcport.items[-1] != other.srcport.items[-1]:
            return self._srcport.items[-1] < other.srcport.items[-1]
        return None

    # noinspection DuplicatedCode
    def _lt__dstport(self, other: Ace) -> OBool:
        """< less than, dstport"""
        if self._dstport.operator != other.dstport.operator:
            return self._dstport.operator < other.dstport.operator
        if self._dstport.items[0] != other.dstport.items[0]:
            return self._dstport.items[0] < other.dstport.items[0]
        if self._dstport.items[-1] != other.dstport.items[-1]:
            return self._dstport.items[-1] < other.dstport.items[-1]
        return None


LAce = List[Ace]
LLAce = List[LAce]
