"""Static settings"""

DEFAULT_PLATFORM = "ios"
MAX_LINE_LENGTH = 100
SEQUENCE_MAX = 4294967295
INDENTATION = 2

PLATFORMS = ("ios", "cnx")
ACTIONS = ("remark", "permit", "deny")
OPERATORS = ("eq", "gt", "lt", "neq", "range")

PORTS = {
    "bgp": 179,
    "biff": 512,
    "bootpc": 68,
    "bootps": 67,
    "chargen": 19,
    "cmd": 514,
    "daytime": 13,
    "discard": 9,
    "dns": 53,
    "dnsix": 90,
    "domain": 53,
    "echo": 7,
    "exec": 512,
    "finger": 79,
    "ftp": 21,
    "ftp-data": 20,
    "gopher": 70,
    "hostname": 101,
    "ident": 113,
    "irc": 194,
    "isakmp": 500,
    "klogin": 543,
    "kshell": 544,
    "lpd": 515,
    "mobile-ip": 434,
    "nameserver": 42,
    "netbios-dgm": 138,
    "netbios-ns": 137,
    "nntp": 119,
    "ntp": 123,
    "pop2": 109,
    "pop3": 110,
    "radius": 1812,
    "rip": 520,
    "smtp": 25,
    "snmp": 161,
    "snmp-trap": 162,
    "snmptrap": 162,
    "sunrpc": 111,
    "syslog": 514,
    "tacacs": 49,
    "tacacs-ds": 49,
    "talk": 517,
    "telnet": 23,
    "tftp": 69,
    "time": 37,
    "uucp": 540,
    "who": 513,
    "whois": 43,
    "www": 80,
    "xdmcp": 177,
}
PORTS_NAMES = {i: s for s, i in PORTS.items()}
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
PROTOCOL_TO_NR = dict(
    ios=IOS_PROTOCOLS,
    cnx=CNX_PROTOCOLS,
)
NR_TO_PROTOCOL = dict(
    ios={i: s for s, i in IOS_PROTOCOLS.items()},
    cnx={i: s for s, i in CNX_PROTOCOLS.items()},
)
