"""Static settings"""

DEFAULT_PLATFORM = "ios"
MAX_LINE_LENGTH = 100
SEQUENCE_MAX = 4294967295
INDENTATION = 2

PLATFORMS = ("ios", "cnx")
ACTIONS = ("remark", "permit", "deny")
OPERATORS = ("eq", "gt", "lt", "neq", "range")

OPTIONS = (
    "ack",
    "dscp",
    "fin",
    "log",
    "log-input",
    "match-all",
    "match-any",
    "precedence",
    "psh",
    "rst",
    "time-range",
    "tos",
    "ttl",
    "urg",
)
IOS_PROTOCOLS = {
    "ah": 51,
    "ahp": 51,
    "egp": 8,
    "eigrp": 88,
    "esp": 50,
    "gre": 47,
    "icmp": 1,
    "igmp": 2,
    "ip": 0,
    "ipip": 4,
    "ipv6": 41,
    "nos": 94,
    "ospf": 89,
    "pcp": 108,
    "pim": 103,
    "tcp": 6,
    "udp": 17,
}
CNX_PROTOCOLS = {
    "ahp": 51,
    "eigrp": 88,
    "esp": 50,
    "gre": 47,
    "icmp": 1,
    "igmp": 2,
    "ip": 0,
    "nos": 94,
    "ospf": 89,
    "pcp": 108,
    "pim": 103,
    "tcp": 6,
    "udp": 17,
}
ANY_PROTOCOLS = {**IOS_PROTOCOLS, **CNX_PROTOCOLS}
PROTOCOL_TO_NR = dict(
    ios=IOS_PROTOCOLS,
    cnx=CNX_PROTOCOLS,
)
NR_TO_PROTOCOL = dict(
    ios={i: s for s, i in IOS_PROTOCOLS.items()},
    cnx={i: s for s, i in CNX_PROTOCOLS.items()},
)
