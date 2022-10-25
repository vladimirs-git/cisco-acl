"""Functions to create *Acl* objects From the "show running-config" output"""
import logging
from typing import Union

import netports

from cisco_acl import helpers as h
from cisco_acl.ace import Ace, LAce
from cisco_acl.ace_group import LUAceg
from cisco_acl.acl import Acl, LAcl
from cisco_acl.addr_group import AddrGroup, LAddrGroup
from cisco_acl.address import Address, LAddress
from cisco_acl.address_ag import AddressAg
from cisco_acl.config_parser import ConfigParser
from cisco_acl.port import Port
from cisco_acl.protocol import Protocol
from cisco_acl.types_ import LDAny, LInt, LStr

UAddress = Union[Address, AddressAg]


# noinspection PyIncorrectDocstring,DuplicatedCode
def acls(config: str, **kwargs) -> LAcl:
    """Creates *Acl* objects based on the "show running-config" output.
    Support address group objects.
    Each ACE line is treated as an independent *Ace* element (default) or ACE lines can be
    grouped to *AceGroup* by text in remarks (param `group_by`)

    :param config: Cisco config, "show running-config" output
    :type config: str

    :param platform: Platform: "ios", "nxos" (default "ios")
    :type platform: str

    :param version: Software version (not implemented, planned for compatability)
    :type version: str

    :param names: Parse only ACLs with specified names
    :type names: List[str]

    :param group_by: Startswith in remark line. ACEs group, starting from the Remark,
        where line startswith `group_by`, will be applied to the same AceGroup,
        until next Remark that also startswith `group_by`
    :type group_by: str

    :return: List of *Acl* objects
    :rtype: List[Acl]
    """
    platform = h.init_platform(**kwargs)
    version = str(kwargs.get("version") or "")
    group_by = str(kwargs.get("group_by") or "")
    names = kwargs.get("names")

    parser = ConfigParser(config=config, platform=platform, version=version)
    parser.parse_config()
    parsed_acls = parser.acls(names=names)

    _acls: LAcl = [Acl(**d) for d in parsed_acls]
    _add_addgr_to_aces(_acls, parser)
    if group_by:
        for acl_o in _acls:
            acl_o.group(group_by=group_by)
    return _acls


# noinspection PyIncorrectDocstring,DuplicatedCode
def aces(config: str, **kwargs) -> LUAceg:
    """Creates *Ace* objects based on the "show running-config" output

    :param config: Cisco config, "show running-config" output
    :type config: str

    :param platform: Platform: "ios", "nxos" (default "ios")
    :type platform: str

    :param version: Software version (not implemented, planned for compatability)
    :type version: str

    :param group_by: Startswith in remark line. ACEs group, starting from the Remark,
        where line startswith `group_by`, will be applied to the same AceGroup,
        until next Remark that also startswith `group_by`
    :type group_by: str

    :return: List of *Ace* objects
    :rtype: List[Ace]
    """
    platform = h.init_platform(**kwargs)
    version = str(kwargs.get("version") or "")
    group_by = str(kwargs.get("group_by") or "")
    parser = ConfigParser(config=config, platform=platform, version=version)
    parser.parse_config()

    acl_o = Acl(platform=platform)
    for line in parser.lines:
        # noinspection PyProtectedMember
        if ace_o := acl_o._line_to_oace(line):
            acl_o.items.append(ace_o)

    if group_by:
        acl_o.group(group_by=group_by)
    return acl_o.items


# noinspection PyIncorrectDocstring
def addrgroups(config: str, **kwargs) -> LAddrGroup:
    """Creates *AddrGroup* objects based on the "show running-config" output

    :param config: Cisco config, "show running-config" output
    :type config: str

    :param platform: Platform: "ios", "nxos" (default "ios")
    :type platform: str

    :param version: Software version (not implemented, planned for compatability)
    :type version: str

    :return: List of *AddrGroup* objects
    :rtype: List[AddrGroup]
    """
    platform = h.init_platform(**kwargs)
    version = str(kwargs.get("version") or "")
    parser = ConfigParser(config=config, platform=platform, version=version)
    parser.parse_config()

    parsed_addgrs: LDAny = parser.addgrs()
    addgrs: LAddrGroup = [AddrGroup(**d) for d in parsed_addgrs]
    return addgrs


# noinspection PyIncorrectDocstring
def range_ports(**kwargs) -> LStr:
    """Generates ACEs in required range of TCP/UDP source/destination ports

    :param srcports: Range of TCP/UDP source ports
    :type srcports: str

    :param dstports: Range of TCP/UDP destination ports
    :type dstports: str

    :param line: ACE pattern, on whose basis new ACEs will be generated
        (default "permit tcp any any", operator "eq")
    :type line: str

    :param platform: Platform: "ios", "nxos" (default "ios")
    :type platform: str

    :param port_nr: Well-known TCP/UDP ports as numbers
        True  - all tcp/udp ports as numbers
        False - well-known tcp/udp ports as names (default)
    :type port_nr: bool

    :return: List of newly generated ACE lines
    :rtype: List[str]

    :example:
        range_ports("21-23,80") -> ["permit tcp any eq ftp any",
                                    "permit tcp any eq 22 any",
                                    "permit tcp any eq telnet any",
                                    "permit tcp any eq www any"]
    """
    srcports = str(kwargs.get("srcports") or "")
    dstports = str(kwargs.get("dstports") or "")

    aces_: LAce = []  # result
    _aces = _range__port(range=srcports, sdst="src", **kwargs)
    aces_.extend(_aces)
    _aces = _range__port(range=dstports, sdst="dst", **kwargs)
    aces_.extend(_aces)
    return [o.line for o in aces_]


# noinspection PyIncorrectDocstring
def range_protocols(**kwargs) -> LStr:
    """Generates ACEs in required range of IP protocols

    :param protocols: Range of IP protocols
    :type protocols: str

    :param line: ACE pattern, on whose basis new ACEs will be generated
        (default "permit ip any any")
    :type line: str

    :param platform: Platform: "ios", "nxos" (default "ios")
    :type platform: str

    :param protocol_nr: Well-known ip protocols as numbers
        True  - all ip protocols as numbers
        False - well-known ip protocols as names (default)
    :type protocol_nr: bool

    :return: List of newly generated ACE lines
    :rtype: List[str]

    :example:
        range_protocols(protocols="1-2,6", line="permit ip host 10.0.0.1 any") ->
            ["permit icmp host 10.0.0.1 any",
             "permit igmp host 10.0.0.1 any",
             "permit tcp host 10.0.0.1 any"]
    """
    range_ = str(kwargs.get("protocols") or "")
    line = str(kwargs.get("line") or "permit ip any any")
    platform = h.init_platform(**kwargs)
    protocol_nr = bool(kwargs.get("protocol_nr") or False)

    aces_: LAce = []  # result
    protocols: LInt = netports.iip(range_)
    for proto in protocols:
        ace_o = Ace(line, platform=platform, protocol_nr=protocol_nr)
        ace_o._protocol = Protocol(str(proto), platform=platform, protocol_nr=protocol_nr)
        ace_o.platform = platform
        aces_.append(ace_o)
    return [o.line for o in aces_]


def subnet_of(top: UAddress, bottom: UAddress) -> bool:
    """Checks `bottom` address (all ipnets) is subnet of `top` address (any of ipnet)

    :param top: Other address object to check with self address
    :type top: Union[Address, AddressAg]

    :param bottom: Other address object to check with self address
    :type bottom: Union[Address, AddressAg]

    :return: True - if address is subnet of `other` address
    :rtype: bool
    """
    tops_ = top.ipnets()
    bottoms_ = bottom.ipnets()

    for bottom_ in bottoms_:
        for top_ in tops_:
            if bottom_.subnet_of(top_):
                break
        else:
            return False
    return True


# ============================= helpers ==============================

def _create_acls_w_acegs(parser: ConfigParser, group_by: str) -> LAcl:
    """Creates Acls with AceGroups. Groups ACEs to *AceGroup* by `group_by` in startswith remarks

    :param parser: Semi-parsed config

    :param group_by: Startswith in remark line. ACEs group, starting from the Remark,
        where line startswith `group_by`, will be applied to the same AceGroup,
        until next Remark that also startswith `group_by`

    :return: List of parsed ACLs
    """
    parsed_acls = parser.acls()
    acls_w_aceg: LAcl = [Acl(**d) for d in parsed_acls]

    for acl_o in acls_w_aceg:
        acl_o.group(group_by=group_by)

    _add_addgr_to_aces(acls_w_aceg, parser)
    return acls_w_aceg


def _add_addgr_to_aces(acls_: LAcl, parser: ConfigParser) -> None:
    """Adds address groups to Ace.srcaddr Ace.dstaddr
    :param acls_: Side effect
    """
    parsed_addgrs = parser.addgrs()
    addgrs: LAddrGroup = [AddrGroup(**d) for d in parsed_addgrs]

    for acl_o in acls_:
        _aces: LAce = [o for o in acl_o.items if isinstance(o, Ace)]
        for ace_o in _aces:
            addrs_w_addgr: LAddress = [o for o in (ace_o.srcaddr, ace_o.dstaddr) if o.addrgroup]
            addrs_w_addgr = [o for o in addrs_w_addgr if _check_addgr(ace_o, addgrs, o, parser)]
            for addr_ace_o in addrs_w_addgr:
                addgr_name = addr_ace_o.addrgroup
                addgr_o: AddrGroup = [o for o in addgrs if o.name == addgr_name][0]
                for address_ag_o in addgr_o.items:
                    if not isinstance(address_ag_o, AddressAg):
                        continue
                    address_ag_o.sequence = 0
                    address_ag_d = address_ag_o.data()
                    addr_item_o = Address(**address_ag_d)
                    addr_ace_o.items.append(addr_item_o)


def _check_addgr(ace_o, addgrs, address_o, parser) -> bool:
    """Checks addresses in address group

    :return: True - Single Address group present in config
        False - Address group not found in config or detected multiple groups
        with the same name
    """
    ace = ace_o.line
    addrgroup = address_o.addrgroup
    addgrs_ = [o for o in addgrs if o.name == addrgroup]
    count = len(addgrs_)
    if not count:
        line = f"{parser.pattern__object_group()} {addrgroup}"
        msg = f"{ace=} has no addresses, {line=} not found in config"
        logging.warning(msg)
        return False
    if count != 1:
        msg = f"{ace=} has no addresses, found multiple {addrgroup=}, expected 1"
        logging.warning(msg)
        return False
    return True


def _range__port(sdst: str, **kwargs) -> LAce:
    """Generates range of TCP/UDP source/destination ports

    :param sdst: "src", "dst"
    :type sdst: str

    :param range: Range of TCP/UDP source/destination ports
    :type range: str

    :param port_nr: Well-known TCP/UDP ports as numbers
    :type port_nr: bool

    :return: List of newly generated *Ace* objects
    :rtype: List[Ace]
    """
    range_ = str(kwargs.get("range") or "")
    line = str(kwargs.get("line") or "permit tcp any any")
    platform = h.init_platform(**kwargs)
    port_nr = bool(kwargs.get("port_nr") or False)

    aces_: LAce = []  # result
    ports: LInt = netports.itcp(range_)
    for port in ports:
        ace_o = Ace(line, platform=platform, port_nr=port_nr)
        ace_o.protocol.has_port = True

        # check operator=="range"
        port_o: Port = getattr(ace_o, f"{sdst}port")
        operator = port_o.operator or "eq"
        expected = ["eq", "gt", "lt", "neq"]
        if operator not in expected:
            raise ValueError(f"invalid {operator=}, {expected=}")

        port_o = Port(line=f"{operator} {port}",
                      platform=ace_o.platform,
                      protocol=ace_o.protocol.name,
                      port_nr=ace_o.port_nr)
        setattr(ace_o, f"_{sdst}port", port_o)
        aces_.append(ace_o)
    return aces_
