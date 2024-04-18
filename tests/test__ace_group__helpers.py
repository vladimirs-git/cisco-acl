"""Unittest ace_group.py"""

from ipaddress import IPv4Network

REQ_NO_LINE = dict(
    line="",
    platform="ios",
    version="0",
    type="extended",
    name="",
    items=[],
    group_by="",
    note="",
    sequence=0,
    protocol_nr=False,
    port_nr=False,
)

REQ_LINE = dict(
    line="1 permit 0 any any\n2 deny 1 any any",
    platform="nxos",
    version="0",
    type="extended",
    name="",
    items=[dict(line="1 permit 0 any any",
                platform="nxos",
                version="0",
                type="extended",
                protocol_nr=True,
                port_nr=True,
                sequence=1,
                action="permit",
                protocol=dict(line="0",
                              platform="nxos",
                              version="0",
                              note="",
                              protocol_nr=True,
                              has_port=False,
                              name="ip",
                              number=0),
                srcaddr=dict(line="any",
                             platform="nxos",
                             version="0",
                             items=[],
                             note="",
                             max_ncwb=16,
                             type="any",
                             addrgroup="",
                             ipnet=IPv4Network("0.0.0.0/0"),
                             prefix="0.0.0.0/0",
                             subnet="0.0.0.0 0.0.0.0",
                             wildcard="0.0.0.0 255.255.255.255"),
                srcport=dict(line="",
                             platform="nxos",
                             version="0",
                             protocol="",
                             note="",
                             port_nr=True,
                             items=[],
                             operator="",
                             ports=[],
                             sport=""),
                dstaddr=dict(line="any",
                             platform="nxos",
                             version="0",
                             items=[],
                             note="",
                             max_ncwb=16,
                             type="any",
                             addrgroup="",
                             ipnet=IPv4Network("0.0.0.0/0"),
                             prefix="0.0.0.0/0",
                             subnet="0.0.0.0 0.0.0.0",
                             wildcard="0.0.0.0 255.255.255.255"),
                dstport=dict(line="",
                             platform="nxos",
                             version="0",
                             protocol="",
                             note="",
                             port_nr=True,
                             items=[],
                             operator="",
                             ports=[],
                             sport=""),
                option=dict(line="",
                            platform="nxos",
                            version="0",
                            note="",
                            flags=[],
                            logs=[]),
                note="",
                max_ncwb=16),
           dict(line="2 deny 1 any any",
                platform="nxos",
                version="0",
                type="extended",
                protocol_nr=True,
                port_nr=True,
                sequence=2,
                action="deny",
                protocol=dict(line="1",
                              platform="nxos",
                              version="0",
                              note="",
                              protocol_nr=True,
                              has_port=False,
                              name="icmp",
                              number=1),
                srcaddr=dict(line="any",
                             platform="nxos",
                             version="0",
                             items=[],
                             note="",
                             max_ncwb=16,
                             type="any",
                             addrgroup="",
                             ipnet=IPv4Network("0.0.0.0/0"),
                             prefix="0.0.0.0/0",
                             subnet="0.0.0.0 0.0.0.0",
                             wildcard="0.0.0.0 255.255.255.255"),
                srcport=dict(line="",
                             platform="nxos",
                             version="0",
                             protocol="",
                             note="",
                             port_nr=True,
                             items=[],
                             operator="",
                             ports=[],
                             sport=""),
                dstaddr=dict(line="any",
                             platform="nxos",
                             version="0",
                             items=[],
                             note="",
                             max_ncwb=16,
                             type="any",
                             addrgroup="",
                             ipnet=IPv4Network("0.0.0.0/0"),
                             prefix="0.0.0.0/0",
                             subnet="0.0.0.0 0.0.0.0",
                             wildcard="0.0.0.0 255.255.255.255"),
                dstport=dict(line="",
                             platform="nxos",
                             version="0",
                             protocol="",
                             note="",
                             port_nr=True,
                             items=[],
                             operator="",
                             ports=[],
                             sport=""),
                option=dict(line="",
                            platform="nxos",
                            version="0",
                            note="",
                            flags=[],
                            logs=[]),
                note="",
                max_ncwb=16)],
    group_by="",
    note="a",
    protocol_nr=True,
    port_nr=True,
    sequence=1,
)
