"""TCP/UDP ports and names mapping for Cisco ACL."""

from netports import SwVersion

from cisco_acl import helpers as h
from cisco_acl.types_ import DInt, DiStr, LStr, UVersion

# cisco Nexus 3172T, NXOS: version 9.3(8)
# cisco ISR4331/K9, Cisco IOS XE Software, Version 16.09.06
TCP_NAME_PORT__BASE = {
    "echo": 7,
    "discard": 9,
    "daytime": 13,
    "chargen": 19,
    "ftp-data": 20,
    "ftp": 21,
    "telnet": 23,
    "smtp": 25,
    "time": 37,
    "whois": 43,
    "tacacs": 49,
    "domain": 53,
    "gopher": 70,
    "finger": 79,
    "www": 80,
    "hostname": 101,
    "pop2": 109,
    "pop3": 110,
    "sunrpc": 111,
    "ident": 113,
    "nntp": 119,
    "bgp": 179,
    "irc": 194,
    "pim-auto-rp": 496,
    "exec": 512,
    "login": 513,
    "cmd": 514,
    "lpd": 515,
    "talk": 517,
    "uucp": 540,
    "klogin": 543,
    "kshell": 544,
}

# cisco ASA-5585 9.12(4)37
TCP_NAME_PORT__ASA = {
    "echo": 7,
    "discard": 9,
    "daytime": 13,
    "chargen": 19,
    "ftp-data": 20,
    "ftp": 21,
    "ssh": 22,
    "telnet": 23,
    "smtp": 25,
    "whois": 43,
    "tacacs": 49,
    "domain": 53,
    "gopher": 70,
    "finger": 79,
    "www": 80,
    "hostname": 101,
    "pop2": 109,
    "pop3": 110,
    "sunrpc": 111,
    "ident": 113,
    "nntp": 119,
    "netbios-ssn": 139,
    "imap4": 143,
    "bgp": 179,
    "irc": 194,
    "ldap": 389,
    "https": 443,
    "pim-auto-rp": 496,
    "exec": 512,
    "login": 513,
    "rsh": 514,
    "lpd": 515,
    "talk": 517,
    "uucp": 540,
    "klogin": 543,
    "kshell": 544,
    "rtsp": 554,
    "ldaps": 636,
    "kerberos": 750,
    "lotusnotes": 1352,
    "citrix-ica": 1494,
    "sqlnet": 1521,
    "h323": 1720,
    "pptp": 1723,
    "nfs": 2049,
    "ctiqbe": 2748,
    "cifs": 3020,
    "sip": 5060,
    "aol": 5190,
    "pcanywhere-data": 5631,
}

# cisco Nexus 3172T, NXOS: version 9.3(8)
TCP_NAME_PORT__NXOS = {
    "drip": 3949,
}
TCP_NAME_PORT__NXOS = {**TCP_NAME_PORT__BASE, **TCP_NAME_PORT__NXOS}

# cisco C6816-X-LE, Cisco IOS Software, Version 15.2(02)SY
TCP_NAME_PORT__IOS_15 = {
    "syslog": 514,  # alias of cmd
}
TCP_NAME_PORT__IOS_15 = {**TCP_NAME_PORT__BASE, **TCP_NAME_PORT__IOS_15}

# cisco ISR4331/K9, Cisco IOS XE Software, Version 16.09.06
TCP_NAME_PORT__IOS_16 = {
    "msrpc": 135,
    "syslog": 514,  # alias of cmd
    "onep-plain": 15001,
    "onep-tls": 15002,
}
TCP_NAME_PORT__IOS_16 = {**TCP_NAME_PORT__BASE, **TCP_NAME_PORT__IOS_16}

# cisco Nexus 3172T, NXOS: version 9.3(8)
# cisco ISR4331/K9, Cisco IOS XE Software, Version 16.09.06
UDP_NAME_PORT__BASE = {
    "echo": 7,
    "discard": 9,
    "time": 37,
    "nameserver": 42,
    "tacacs": 49,
    "domain": 53,
    "bootps": 67,
    "bootpc": 68,
    "tftp": 69,
    "sunrpc": 111,
    "ntp": 123,
    "netbios-ns": 137,
    "netbios-dgm": 138,
    "netbios-ss": 139,
    "snmp": 161,
    "snmptrap": 162,
    "xdmcp": 177,
    "dnsix": 195,
    "mobile-ip": 434,
    "pim-auto-rp": 496,
    "isakmp": 500,
    "biff": 512,
    "who": 513,
    "syslog": 514,
    "talk": 517,
    "rip": 520,
    "non500-isakmp": 4500,
}
# ASA
UDP_NAME_PORT__ASA = {
    "echo": 7,
    "discard": 9,
    "time": 37,
    "nameserver": 42,
    "tacacs": 49,
    "domain": 53,
    "bootps": 67,
    "bootpc": 68,
    "tftp": 69,
    "www": 80,
    "sunrpc": 111,
    "ntp": 123,
    "netbios-ns": 137,
    "netbios-dgm": 138,
    "snmp": 161,
    "snmptrap": 162,
    "xdmcp": 177,
    "dnsix": 195,
    "mobile-ip": 434,
    "pim-auto-rp": 496,
    "isakmp": 500,
    "biff": 512,
    "who": 513,
    "syslog": 514,
    "talk": 517,
    "rip": 520,
    "kerberos": 750,
    "radius": 1645,
    "radius-acct": 1646,
    "nfs": 2049,
    "cifs": 3020,
    "vxlan": 4789,
    "sip": 5060,
    "secureid-udp": 5510,
    "pcanywhere-status": 5632,
}
# cisco Nexus 3172T, NXOS: version 9.3(8)
UDP_NAME_PORT__NXOS = UDP_NAME_PORT__BASE

# cisco C6816-X-LE, Cisco IOS Software, Version 15.2(02)SY
UDP_NAME_PORT__IOS_15 = {**UDP_NAME_PORT__BASE}

# cisco ISR4331/K9, Cisco IOS XE Software, Version 16.09.06
UDP_NAME_PORT__IOS_16 = {
    "ripv6": 521,
}
UDP_NAME_PORT__IOS_16 = {**UDP_NAME_PORT__BASE, **UDP_NAME_PORT__IOS_16}


class PortName:
    """TCP/UDP ports and names mapping for Cisco ACL."""

    def __init__(
        self,
        protocol: str = "tcp",
        platform: str = "",
        version: UVersion = "",
    ):
        """Init PortName.

        :param protocol: Protocol: "tcp", "udp".
        :type protocol: str

        :param platform: Platform: "asa", "ios", "nxos". Default "ios".
        :type platform: str

        :param version: Software version.
        :type version: str
        """
        self.protocol: str = _init_protocol(protocol)
        self.platform: str = h.init_platform(platform=platform)
        self.version: SwVersion = h.init_version(version=version)

    def __repr__(self):
        """__repr__."""
        name = self.__class__.__name__
        params = [
            f"protocol={self.protocol!r}",
            f"platform={self.platform!r}",
        ]
        if str(self.version) != "0":
            params.append(f"version={str(self.version)!r}")
        params_s = ", ".join(params)
        return f"{name}({params_s})"

    # noinspection DuplicatedCode
    def names(self) -> DInt:
        """Return TCP/UDP protocol names and ports based on the platform and software version.

        :return: Dictionary with protocol names and ports (platform-specific).
        :example: {"echo": 7, "discard": 9, ...}
        """
        names_d: DInt = {}
        if self._is_tcp():
            if self.platform == "asa":
                names_d = TCP_NAME_PORT__ASA.copy()
            elif self.platform == "ios":
                if self.version.major == 15:
                    names_d = TCP_NAME_PORT__IOS_15.copy()
                else:
                    names_d = TCP_NAME_PORT__IOS_16.copy()
            elif self.platform == "nxos":
                names_d = TCP_NAME_PORT__NXOS.copy()

        elif self._is_udp():
            if self.platform == "asa":
                names_d = UDP_NAME_PORT__ASA.copy()
            elif self.platform == "ios":
                if self.version.major == 15:
                    names_d = UDP_NAME_PORT__IOS_15.copy()
                else:
                    names_d = UDP_NAME_PORT__IOS_16.copy()
            elif self.platform == "nxos":
                names_d = UDP_NAME_PORT__NXOS.copy()

        return names_d

    # noinspection DuplicatedCode
    def ports(self) -> DiStr:
        """Return TCP/UDP protocol ports and names based on the platform and software version.

        :return: Dictionary with protocol ports and ports (platform-specific).
        :example: {7: "echo", 9: "discard", ...}
        """
        names_d: DInt = self.names()
        ports_d: DiStr = _swap(names_d)
        return ports_d

    def _is_tcp(self) -> bool:
        """Check if the protocol is TCP.

        :return: True if the protocol is TCP, False otherwise.
        """
        return bool(self.protocol in ["tcp", "6"])

    def _is_udp(self) -> bool:
        """Check if the protocol is UDP.

        :return: True if the protocol is UDP, False otherwise.
        """
        return bool(self.protocol in ["udp", "17"])


# ============================ functions =============================


def all_known_names() -> LStr:
    """Return all known names, that can be used in Cisco ACL (platform does not matter)."""
    items = set()
    # tcp
    items.update(set(TCP_NAME_PORT__BASE))
    items.update(set(TCP_NAME_PORT__ASA))
    items.update(set(TCP_NAME_PORT__IOS_16))
    items.update(set(TCP_NAME_PORT__NXOS))
    items.update(set(UDP_NAME_PORT__BASE))
    # udp
    items.update(set(UDP_NAME_PORT__BASE))
    items.update(set(UDP_NAME_PORT__ASA))
    items.update(set(UDP_NAME_PORT__IOS_16))
    items.update(set(UDP_NAME_PORT__NXOS))
    return sorted(items)


# ============================= helpers ==============================


def _init_protocol(protocol: str) -> str:
    """Init protocol.

    Convert TCP/UDP numbers to names.
    :param protocol: Protocol: "tcp", "udp".
    :return: Protocol: "tcp", "udp".
    """
    protocol = str(protocol).lower()
    expected = ["tcp", "udp"]
    if protocol in expected:
        return protocol
    if str(protocol) == "6":
        return "tcp"
    if str(protocol) == "17":
        return "udp"
    raise ValueError(f"invalid {protocol=}, {expected=}")


def _swap(name_port: DInt) -> DiStr:
    """Swap names and ports in dict."""
    data: DiStr = {}
    for name, port in name_port.items():
        if port not in data:
            data[port] = name
    return data
