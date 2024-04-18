"""Unittest port_name.py"""

import unittest

from cisco_acl import port_name
from cisco_acl.port_name import PortName, all_known_names
from tests.helpers_test import Helpers


# noinspection DuplicatedCode
class Test(Helpers):
    """PortName"""

    def test_valid__names(self):
        """PortName.names()"""
        for kwargs, req_d, absent in [
            ({}, dict(cmd=514, syslog=514, msrpc=135), ["drip", "ripv6"]),
            # name tcp
            (dict(protocol="tcp", platform="asa"), dict(www=80, https=443), ["syslog", "ripv6"]),
            (dict(protocol="tcp", platform="ios"),
             dict(cmd=514, syslog=514, msrpc=135), ["drip", "ripv6"]),
            (dict(protocol="tcp", platform="ios", version="15.2(02)SY"),
             dict(cmd=514, syslog=514), ["msrpc", "drip", "ripv6"]),
            (dict(protocol="tcp", platform="ios", version="16.09.06"),
             dict(cmd=514, syslog=514, msrpc=135), ["drip", "ripv6"]),
            (dict(protocol="tcp", platform="nxos"), dict(cmd=514, drip=3949), ["syslog", "ripv6"]),
            # name udp
            (dict(protocol="udp", platform="asa"), dict(www=80), ["cmd", "ripv6", "drip"]),
            (dict(protocol="udp", platform="ios"), dict(syslog=514, ripv6=521), ["cmd", "drip"]),
            (dict(protocol="udp", platform="ios", version="15.2(02)SY"),
             dict(syslog=514), ["ripv6", "cmd", "drip"]),
            (dict(protocol="udp", platform="ios", version="16.09.06"),
             dict(syslog=514, ripv6=521), ["cmd", "drip"]),
            (dict(protocol="udp", platform="nxos"), dict(syslog=514), ["cmd", "ripv6", "drip"]),
            # int tcp
            (dict(protocol=6, platform="asa"), dict(www=80, https=443), ["syslog", "ripv6"]),
            (dict(protocol=6, platform="ios"),
             dict(cmd=514, syslog=514, msrpc=135), ["drip", "ripv6"]),
            (dict(protocol=6, platform="ios", version="15.2(02)SY"),
             dict(cmd=514, syslog=514), ["msrpc", "drip", "ripv6"]),
            (dict(protocol=6, platform="ios", version="16.09.06"),
             dict(cmd=514, syslog=514, msrpc=135), ["drip", "ripv6"]),
            (dict(protocol=6, platform="nxos"), dict(cmd=514, drip=3949), ["syslog", "ripv6"]),
            # int udp
            (dict(protocol=17, platform="asa"), dict(www=80), ["cmd", "ripv6", "drip"]),
            (dict(protocol=17, platform="ios"), dict(syslog=514, ripv6=521), ["cmd", "drip"]),
            (dict(protocol=17, platform="ios", version="15.2(02)SY"),
             dict(syslog=514), ["ripv6", "cmd", "drip"]),
            (dict(protocol=17, platform="ios", version="16.09.06"),
             dict(syslog=514, ripv6=521), ["cmd", "drip"]),
            (dict(protocol=17, platform="nxos"), dict(syslog=514), ["cmd", "ripv6", "drip"]),
        ]:
            obj = PortName(**kwargs)
            result = obj.names()
            self._test_keys(result, req_d, f"{kwargs=}")
            self._test_no_keys(result, absent, f"{kwargs=}")

    def test_valid__ports(self):
        """PortName.ports()"""
        for kwargs, req_d, absent in [
            ({}, {514: "cmd", 135: "msrpc"}, [521, 3949]),
            # name tcp
            (dict(protocol="tcp", platform="asa"), {443: "https"}, [521, 3949]),
            (dict(protocol="tcp", platform="ios"), {514: "cmd", 135: "msrpc"}, [521, 3949]),
            (dict(protocol="tcp", platform="ios", version="15.2(02)SY"),
             {514: "cmd"}, [135, 521, 3949]),
            (dict(protocol="tcp", platform="ios", version="16.09.06"),
             {514: "cmd", 135: "msrpc"}, [521, 3949]),
            (dict(protocol="tcp", platform="nxos"), {514: "cmd", 3949: "drip"}, [135, 521]),
            # name udp
            (dict(protocol="udp", platform="ios"), {514: "syslog", 521: "ripv6"}, [135, 3949]),
            (dict(protocol="udp", platform="ios", version="15.2(02)SY"),
             {514: "syslog"}, [135, 521, 3949]),
            (dict(protocol="udp", platform="ios", version="16.09.06"),
             {514: "syslog", 521: "ripv6"}, [135, 3949]),
            (dict(protocol="udp", platform="nxos"), {514: "syslog"}, [135, 521, 3949]),
            # int tcp
            (dict(protocol=6, platform="asa"), {443: "https"}, [521, 3949]),
            (dict(protocol=6, platform="ios"), {514: "cmd", 135: "msrpc"}, [521, 3949]),
            (dict(protocol=6, platform="ios", version="15.2(02)SY"),
             {514: "cmd"}, [135, 521, 3949]),
            (dict(protocol=6, platform="ios", version="16.09.06"),
             {514: "cmd", 135: "msrpc"}, [521, 3949]),
            (dict(protocol=6, platform="nxos"), {514: "cmd", 3949: "drip"}, [135, 521]),
            # int udp
            (dict(protocol=17, platform="ios"), {514: "syslog", 521: "ripv6"}, [135, 3949]),
            (dict(protocol=17, platform="ios", version="15.2(02)SY"),
             {514: "syslog"}, [135, 521, 3949]),
            (dict(protocol=17, platform="ios", version="16.09.06"),
             {514: "syslog", 521: "ripv6"}, [135, 3949]),
            (dict(protocol=17, platform="nxos"), {514: "syslog"}, [135, 521, 3949]),
        ]:
            obj = PortName(**kwargs)
            result = obj.ports()
            self._test_keys(result, req_d, f"{kwargs=}")
            self._test_no_keys(result, absent, f"{kwargs=}")

    # ========================== functions ===========================

    def test_valid__all_known_names(self):
        """all_known_names()"""
        results = all_known_names()
        req = {
            "cmd",  # TCP_NAME_PORT__BASE
            "https",  # TCP_NAME_PORT__ASA
            "syslog",  # TCP_NAME_PORT__IOS
            "drip",  # TCP_NAME_PORT__NXOS
            "ripv6",  # UDP_NAME_PORT__IOS
            "pcanywhere-status",  # UDP_NAME_PORT__ASA
        }
        result = set(results).intersection(req)
        self.assertEqual(result, req, msg="all_known_names")

    # ============================= helpers ==============================

    def test_valid__init_protocol(self):
        """port_name._init_protocol()"""
        for protocol, req in [
            ("tcp", "tcp"),
            ("TCP", "tcp"),
            ("udp", "udp"),
            ("UDP", "udp"),
            ("6", "tcp"),
            ("17", "udp"),
            (6, "tcp"),
            (17, "udp"),
        ]:
            result = port_name._init_protocol(protocol=protocol)
            self.assertEqual(result, req, msg=f"{protocol=}")

    def test_invalid__init_protocol(self):
        """PortName._init_protocol()"""
        for protocol, error in [
            ("", ValueError),
            ("typo", ValueError),
        ]:
            with self.assertRaises(error, msg=f"{protocol=}"):
                port_name._init_protocol(protocol=protocol)


if __name__ == "__main__":
    unittest.main()
