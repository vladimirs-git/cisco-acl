"""TCP/UDP ports and names mapping for Cisco ACL"""

from cisco_acl.static import DEFAULT_PLATFORM, PLATFORMS
from cisco_acl.types_ import DInt, DiStr, LStr

# cisco Nexus 3172T, NXOS: version 9.3(8)
# cisco ISR4331/K9, Cisco IOS XE Software, Version 16.09.06
TCP_NAME_PORT__BASE = {
    "bgp": 179,
    "chargen": 19,
    "cmd": 514,
    "daytime": 13,
    "discard": 9,
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
    "klogin": 543,
    "kshell": 544,
    "login": 513,
    "lpd": 515,
    "nntp": 119,
    "pim-auto-rp": 496,
    "pop2": 109,
    "pop3": 110,
    "smtp": 25,
    "sunrpc": 111,
    "tacacs": 49,
    "talk": 517,
    "telnet": 23,
    "time": 37,
    "uucp": 540,
    "whois": 43,
    "www": 80,
}

# cisco Nexus 3172T, NXOS: version 9.3(8)
TCP_NAME_PORT__NXOS = {
    "drip": 3949,
}
TCP_NAME_PORT__NXOS = {**TCP_NAME_PORT__BASE, **TCP_NAME_PORT__NXOS}

# cisco ISR4331/K9, Cisco IOS XE Software, Version 16.09.06
TCP_NAME_PORT__IOS = {
    "msrpc": 135,
    "onep-plain": 15001,
    "onep-tls": 15002,
    "syslog": 514,  # alias of cmd
}
TCP_NAME_PORT__IOS = {**TCP_NAME_PORT__BASE, **TCP_NAME_PORT__IOS}

# cisco Nexus 3172T, NXOS: version 9.3(8)
# cisco ISR4331/K9, Cisco IOS XE Software, Version 16.09.06
UDP_NAME_PORT__BASE = {
    "biff": 512,
    "bootpc": 68,
    "bootps": 67,
    "discard": 9,
    "dnsix": 195,
    "domain": 53,
    "echo": 7,
    "isakmp": 500,
    "mobile-ip": 434,
    "nameserver": 42,
    "netbios-dgm": 138,
    "netbios-ns": 137,
    "netbios-ss": 139,
    "non500-isakmp": 4500,
    "ntp": 123,
    "pim-auto-rp": 496,
    "rip": 520,
    "snmp": 161,
    "snmptrap": 162,
    "sunrpc": 111,
    "syslog": 514,
    "tacacs": 49,
    "talk": 517,
    "tftp": 69,
    "time": 37,
    "who": 513,
    "xdmcp": 177,
}
# cisco Nexus 3172T, NXOS: version 9.3(8)
UDP_NAME_PORT__NXOS = UDP_NAME_PORT__BASE

# cisco ISR4331/K9, Cisco IOS XE Software, Version 16.09.06
UDP_NAME_PORT__IOS = {
    "ripv6": 521,
}
UDP_NAME_PORT__IOS = {**UDP_NAME_PORT__BASE, **UDP_NAME_PORT__IOS}


class PortName:
    """TCP/UDP ports and names mapping for Cisco ACL"""

    def __init__(self, protocol: str = "tcp", platform: str = DEFAULT_PLATFORM, version: str = ""):
        """TCP/UDP ports and names
        :param protocol: Protocol: "tcp", "udp"
        :param platform: Platform: "ios", "nxos"
        :param version: Software version (not implemented, planned for compatability)
        """
        self.protocol = self._init_protocol(protocol)
        self.platform = self._init_platform(platform)
        self.version = str(version).lower()

    def __repr__(self):
        name = self.__class__.__name__
        params = [
            f"protocol={self.protocol!r}",
            f"platform={self.platform!r}",
            f"version={self.version!r}",
        ]
        params_s = ", ".join(params)
        return f"{name}({params_s})"

    @staticmethod
    def _init_platform(platform: str) -> str:
        """Init device platform type: "ios", "nxos" """
        platform = str(platform).lower()
        if platform == "cnx":
            platform = "nxos"
        if platform not in PLATFORMS:
            raise ValueError(f"invalid {platform=}, expected={PLATFORMS}")
        return platform

    @staticmethod
    def _init_protocol(protocol: str) -> str:
        """Init protocol, converts tcp, udp numbers to names"""
        protocol = str(protocol).lower()
        expected = ["tcp", "udp"]
        if protocol in expected:
            return protocol
        if str(protocol) == "6":
            return "tcp"
        if str(protocol) == "17":
            return "udp"
        raise ValueError(f"invalid {protocol=}, {expected=}")

    def names(self) -> DInt:
        """Returns TCP/UDP names and ports based on Cisco platform and software version"""
        if self.protocol in ["tcp", "6"]:
            if self.platform == "ios":
                return TCP_NAME_PORT__IOS
            if self.platform == "nxos":
                return TCP_NAME_PORT__NXOS
            return {}
        if self.protocol in ["udp", "17"]:
            if self.platform == "ios":
                return UDP_NAME_PORT__IOS
            if self.platform == "nxos":
                return UDP_NAME_PORT__NXOS
            return {}
        return {}

    def ports(self) -> DiStr:
        """Returns TCP/UDP ports and names based on Cisco platform and software version"""
        if self.protocol in ["tcp", "6"]:
            if self.platform == "ios":
                name_port = {**TCP_NAME_PORT__BASE, **TCP_NAME_PORT__IOS}
                return self._swap(name_port)
            if self.platform == "nxos":
                name_port = {**TCP_NAME_PORT__BASE, **TCP_NAME_PORT__NXOS}
                return self._swap(name_port)
            return {}
        if self.protocol in ["udp", "17"]:
            if self.platform == "ios":
                name_port = {**UDP_NAME_PORT__BASE, **UDP_NAME_PORT__IOS}
                return self._swap(name_port)
            if self.platform == "nxos":
                name_port = {**UDP_NAME_PORT__BASE, **UDP_NAME_PORT__NXOS}
                return self._swap(name_port)
            return {}
        return {}

    @staticmethod
    def _swap(name_port: DInt) -> DiStr:
        """Swaps names and ports in dict"""
        data: DiStr = {}
        for name, port in name_port.items():
            if port not in data:
                data[port] = name
        return data


# ============================ functions =============================

def all_known_names() -> LStr:
    """Returns all known names, that can be used in Cisco ACL (platform does not matter)"""
    items = set()
    items.update(set(TCP_NAME_PORT__BASE))
    items.update(set(TCP_NAME_PORT__NXOS))
    items.update(set(TCP_NAME_PORT__IOS))
    items.update(set(UDP_NAME_PORT__BASE))
    items.update(set(UDP_NAME_PORT__NXOS))
    items.update(set(UDP_NAME_PORT__IOS))
    return sorted(items)
