"""Functions to create Acl objects From the "show running-config" output."""

import logging
from ipaddress import IPv4Network
from typing import Union

import netports
from vhelpers import vlist

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
from cisco_acl.types_ import LDAny, LInt, LStr, DAny
from cisco_acl.wildcard import init_max_ncwb

UAddress = Union[Address, AddressAg]


# noinspection PyIncorrectDocstring,DuplicatedCode
def acls(config: str, **kwargs) -> LAcl:
    """Create Acl objects based on the "show running-config" output.

    Support address group objects.
    Each ACE line is treated as an independent Ace (default) or ACE lines can be
    grouped to AceGroup by text in remarks (param `group_by`).

    :param config: Cisco config, "show running-config" output.
    :type config: str

    :param platform: Platform: "asa", "ios", "nxos". Default "ios".
    :type platform: str

    :param version: Software version, default is "0".
    :type version: str

    :param names: Parses only ACLs with specified names, skips any other.
    :type names: List[str]

    :param max_ncwb: Max count of non-contiguous wildcard bits.
    :type max_ncwb: int

    :param indent: ACE lines indentation (default "  ").
    :type indent: str

    :param protocol_nr: Well-known ip protocols as numbers.
        True  - all ip protocols as numbers,
        False - well-known ip protocols as names (default).
    :type protocol_nr: bool

    :param port_nr: Well-known TCP/UDP ports as numbers,
        True  - all tcp/udp ports as numbers.
        False - well-known tcp/udp ports as names (default).
    :type port_nr: bool

    :param group_by: Startswith in remark line. ACEs group, starting from the Remark,
        where line startswith `group_by`, will be applied to the same AceGroup,
        until next Remark that also startswith `group_by`.
    :type group_by: str

    :return: List of Acl objects.
    :rtype: List[Acl]
    """
    platform = h.init_platform(**kwargs)
    version = str(kwargs.get("version") or "")
    group_by = str(kwargs.get("group_by") or "")
    names = kwargs.get("names")
    indent: str = h.init_indent(**kwargs)
    max_ncwb: int = init_max_ncwb(**kwargs)
    protocol_nr = bool(kwargs.get("protocol_nr"))
    port_nr = bool(kwargs.get("port_nr"))

    parser = ConfigParser(config=config, platform=platform, version=version)
    parser.parse_config()
    parsed_acls: LDAny = parser.acls(names=names)

    acl_kwargs = dict(version=version, indent=indent, max_ncwb=max_ncwb,
                      protocol_nr=protocol_nr, port_nr=port_nr)
    acls_: LAcl = [Acl(**acl_kwargs, **d) for d in parsed_acls]  # type: ignore
    _add_addgr_to_aces(acls_, parser)
    if group_by:
        for acl_o in acls_:
            acl_o.group(group_by=group_by)
    return acls_


# noinspection PyIncorrectDocstring,DuplicatedCode
def aces(config: str, **kwargs) -> LUAceg:
    """Create Ace objects based on the "show running-config" output.

    :param config: Cisco config, "show running-config" output.
    :type config: str

    :param platform: Platform: "asa", "ios", "nxos". Default "ios".
    :type platform: str

    :param version: Software version, default is "0".
    :type version: str

    :param max_ncwb: Max count of non-contiguous wildcard bits.
    :type max_ncwb: int

    :param protocol_nr: Well-known ip protocols as numbers.
        True  - all ip protocols as numbers,
        False - well-known ip protocols as names (default).
    :type protocol_nr: bool

    :param port_nr: Well-known TCP/UDP ports as numbers.
        True  - all tcp/udp ports as numbers,
        False - well-known tcp/udp ports as names (default).
    :type port_nr: bool

    :param group_by: Startswith in remark line. ACEs group, starting from the Remark,
        where line startswith `group_by`, will be applied to the same AceGroup,
        until next Remark that also startswith `group_by`.
    :type group_by: str

    :return: List of Ace objects.
    :rtype: List[Ace]
    """
    platform = h.init_platform(**kwargs)
    version = str(kwargs.get("version") or "")
    group_by = str(kwargs.get("group_by") or "")
    max_ncwb: int = init_max_ncwb(**kwargs)
    protocol_nr = bool(kwargs.get("protocol_nr"))
    port_nr = bool(kwargs.get("port_nr"))

    parser = ConfigParser(config=config, platform=platform, version=version)
    parser.parse_config()

    acl_kwargs = dict(version=version, max_ncwb=max_ncwb, protocol_nr=protocol_nr, port_nr=port_nr)
    acl_o = Acl(platform=platform, **acl_kwargs)  # type: ignore
    for line in parser.lines:
        # noinspection PyProtectedMember
        if ace_o := acl_o._line_to_oace(line):
            acl_o.items.append(ace_o)

    if group_by:
        acl_o.group(group_by=group_by)
    return acl_o.items


# noinspection PyIncorrectDocstring
def addrgroups(config: str, **kwargs) -> LAddrGroup:
    """Create AddrGroup objects based on the "show running-config" output.

    :param config: Cisco config, "show running-config" output.
    :type config: str

    :param platform: Platform: "asa", "ios", "nxos". Default "ios".
    :type platform: str

    :param version: Software version, default is "0".
    :type version: str

    :param max_ncwb: Max count of non-contiguous wildcard bits.
    :type max_ncwb: int

    :param indent: Address lines indentation (default "  ").
    :type indent: str

    :return: List of AddrGroup objects.
    :rtype: List[AddrGroup]
    """
    platform = h.init_platform(**kwargs)
    version = str(kwargs.get("version") or "")
    max_ncwb: int = init_max_ncwb(**kwargs)
    indent: str = h.init_indent(**kwargs)

    parser = ConfigParser(config=config, platform=platform, version=version)
    parser.parse_config()

    parsed_addgrs: LDAny = parser.addgrs()
    ag_kwargs = dict(version=version, max_ncwb=max_ncwb, indent=indent)
    addgrs: LAddrGroup = [AddrGroup(**ag_kwargs, **d) for d in parsed_addgrs]  # type: ignore
    return addgrs


# noinspection PyIncorrectDocstring
def range_ports(
        srcports: str = "",
        dstports: str = "",
        line: str = "permit tcp any any",
        platform: str = "",
        port_nr: bool = False,
        port_count: int = 1,
        port_range: bool = True,
        **kwargs,
) -> LStr:
    """Generate ACEs in required range of TCP/UDP source/destination ports.

    :param srcports: Range of TCP/UDP source ports.
    :type srcports: str

    :param dstports: Range of TCP/UDP destination ports.
    :type dstports: str

    :param line: ACE pattern, on whose basis new ACEs will be generated
        (default "permit tcp any any", operator "eq").
    :type line: str

    :param platform: Platform: "asa", "ios", "nxos". Default "ios".
    :type platform: str

    :param port_nr: Well-known TCP/UDP ports as numbers.
        True  - all tcp/udp ports as numbers,
        False - well-known tcp/udp ports as names (default).
    :type port_nr: bool

    :param port_count: Count of ports in ACE lines. Default is 1.
    :type port_count: int

    :param port_range: Transform ACE lines with match-operator "range" to lines with "eq".
        True - Split match-operator "range" and "eq" to different ACE lines, default is True,
        False - Transform all ACEs with "range" to ACEs with "eq" (each port in separate ACE).
    :type port_range: bool

    :return: List of newly generated ACE lines.
    :rtype: List[str]

    :example:
        range_ports("21-23,80") -> ["permit tcp any eq ftp any",
                                    "permit tcp any eq 22 any",
                                    "permit tcp any eq telnet any",
                                    "permit tcp any eq www any"]
    """
    platform = h.init_platform(platform=platform)
    port_count = int(h.init_number(port_count or 1))
    _check_operator_eq_range(line, platform, port_range)

    aces_: LAce = []  # result

    params = {
        "line": line,
        "platform": platform,
        "port_nr": port_nr,
        "port_count": port_count,
        "port_range": port_range,
    }
    for sdst, ports_range in [("src", srcports), ("dst", dstports)]:
        _aces = _range__port(ports_range=ports_range, sdst=sdst, **params)
        aces_.extend(_aces)

    return [o.line for o in aces_]


# noinspection PyIncorrectDocstring
def range_protocols(**kwargs) -> LStr:
    """Generate ACEs in required range of IP protocols.

    :param protocols: Range of IP protocols.
    :type protocols: str

    :param line: ACE pattern, on whose basis new ACEs will be generated.
        (default "permit ip any any")
    :type line: str

    :param platform: Platform: "asa", "ios", "nxos". Default "ios".
    :type platform: str

    :param version: Software version, default is "0".
    :type version: str

    :param protocol_nr: Well-known ip protocols as numbers.
        True  - all ip protocols as numbers,
        False - well-known ip protocols as names (default).
    :type protocol_nr: bool

    :return: List of newly generated ACE lines.
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
    protocol_nr = bool(kwargs.get("protocol_nr"))

    aces_: LAce = []  # result
    protocols: LInt = netports.iip(range_)
    for proto in protocols:
        ace_o = Ace(line, platform=platform, protocol_nr=protocol_nr)
        ace_o._protocol = Protocol(str(proto), platform=platform, protocol_nr=protocol_nr)
        ace_o.platform = platform
        aces_.append(ace_o)
    return [o.line for o in aces_]


def subnet_of(top: UAddress, bottom: UAddress) -> bool:
    """Check `bottom` address (all ipnets) is subnet of `top` address (any of ipnet).

    :param top: Other address object to check with self address.
    :type top: Union[Address, AddressAg]

    :param bottom: Other address object to check with self address.
    :type bottom: Union[Address, AddressAg]

    :return: True - if address is subnet of `other` address.
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


# ============================= helper ===============================


def _check_addgr(ace_o, addgrs, address_o, parser) -> bool:
    """Check addresses in address group.

    :return: True - Single Address group present in config.
        False - Address group not found in config or detected multiple groups,
        with the same name.
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


def _check_operator_eq_range(line: str, platform: str, port_range: bool) -> None:
    """Check if the operator is one of allowed: "eq", "neq", "range".

    :param line: ACE line with interested match-operators to check.

    :param platform: Platform

    :return: None. Raise a ValueError if the operator is invalid.
    """
    ace_o = Ace(line, platform=platform)
    operators = [ace_o.srcport.operator, ace_o.dstport.operator]
    operators = [s for s in operators if s]

    expected = ["eq", "neq", "range"]
    for operator in operators:
        if operator not in expected:
            raise ValueError(f"invalid {operator=}, {expected=}")


def _create_acls_w_acegs(parser: ConfigParser, group_by: str) -> LAcl:
    """Create Acls with AceGroups. Groups ACEs to AceGroup by `group_by` in startswith remarks.

    :param parser: Semi-parsed config.

    :param group_by: Startswith in remark line. ACEs group, starting from the Remark,
        where line startswith `group_by`, will be applied to the same AceGroup,
        until next Remark that also startswith `group_by`.

    :return: List of parsed ACLs.
    """
    parsed_acls = parser.acls()
    acls_w_aceg: LAcl = [Acl(**d) for d in parsed_acls]

    for acl_o in acls_w_aceg:
        acl_o.group(group_by=group_by)

    _add_addgr_to_aces(acls_w_aceg, parser)
    return acls_w_aceg


def _add_addgr_to_aces(acls_: LAcl, parser: ConfigParser) -> None:
    """Add address groups to Ace.srcaddr Ace.dstaddr.

    :param acls_: Side effect.
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
                    _convert_ios_addr(address_ag_d)
                    addr_item_o = Address(**address_ag_d)
                    addr_ace_o.items.append(addr_item_o)


def _convert_ios_addr(address_ag_d: DAny) -> None:
    """Convert data of IOS AddressAg to data ready for Address.

    :result: Side effect `address_ag_d`.
    """
    if address_ag_d["platform"] != "ios":
        return
    ipnet = address_ag_d["ipnet"]
    if not isinstance(ipnet, IPv4Network):
        raise TypeError(f"invalid {ipnet=} {IPv4Network} expected")
    wildcard = f"{ipnet.network_address} {ipnet.hostmask}"
    address_ag_d["line"] = wildcard


def _range__port(
        ports_range: str,
        sdst: str,
        line: str,
        platform: str,
        port_nr: bool,
        port_count: int,
        port_range: bool,
) -> LAce:
    """Generate range of TCP/UDP ports with match-operator.

    :param ports_range: Range of TCP/UDP source/destination ports.
    :type ports_range: str

    :param sdst: "src", "dst".
    :type sdst: str

    :param line: ACE line with interested protocol and match operator.
    :type line: str

    :param platform: Platform: "asa", "ios", "nxos". Default "ios".
    :type platform: str

    :param port_nr: Well-known TCP/UDP ports as numbers.
        True  - all tcp/udp ports as numbers,
        False - well-known tcp/udp ports as names (default).
    :type port_nr: bool

    :param port_count: Count of ports in ACE lines. Default is 1.
    :type port_count: int

    :return: List of newly generated Ace objects.
    :rtype: List[Ace]
    """
    aces_: LAce = []  # result

    # ports for one ACE
    if port_range:
        ports_l: LStr = ports_range.split(",")
    else:
        ports_l = [str(i) for i in netports.itcp(ports_range)]
    ports_l = [s for s in ports_l if s]
    ports_for_ace = [ports_l]
    if port_count:
        ports_for_ace = vlist.to_multi(ports_l, count=port_count)
    ports_for_ace = [li for li in ports_for_ace if li]

    for ports_ in ports_for_ace:
        port = " ".join([f"{i}" for i in ports_])
        ace_o = Ace(line, platform=platform, port_nr=port_nr)
        ace_o.protocol.has_port = True

        # operator
        attr = f"{sdst}port"
        port_o: Port = getattr(ace_o, attr)
        operator = port_o.operator
        if not operator:
            operator = "eq"
            if port.find("-") > -1:
                operator = "range"

        port_o = Port(
            line=f"{operator} {port}",
            platform=ace_o.platform,
            protocol=ace_o.protocol.name,
            port_nr=ace_o.port_nr,
        )
        attr = f"_{sdst}port"
        setattr(ace_o, attr, port_o)
        aces_.append(ace_o)

    return aces_
