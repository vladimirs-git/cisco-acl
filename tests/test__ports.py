"""Unittest port_name.py"""

import unittest

from cisco_acl.port_name import PortName, all_known_names
from tests.helpers_test import Helpers


# noinspection DuplicatedCode
class Test(Helpers):
    """PortName"""

    def test_valid__names(self):
        """PortName.names()"""
        for kwargs, req_d, absent in [
            ({}, dict(cmd=514, syslog=514, msrpc=135), ["drip", "ripv6"]),
            (dict(protocol="tcp", platform="ios"),
             dict(cmd=514, syslog=514, msrpc=135), ["drip", "ripv6"]),
            (dict(protocol="tcp", platform="cnx"), dict(cmd=514, drip=3949), ["syslog", "ripv6"]),
            (dict(protocol="udp", platform="ios"), dict(syslog=514, ripv6=521), ["cmd", "drip"]),
            (dict(protocol="udp", platform="cnx"), dict(syslog=514), ["cmd", "ripv6", "drip"]),
        ]:
            obj = PortName(**kwargs)
            result = obj.names()
            self._test_keys(result, req_d, f"{kwargs=}")
            self._test_no_keys(result, absent, f"{kwargs=}")

    def test_valid__ports(self):
        """PortName.ports()"""
        for kwargs, req_d, absent in [
            ({}, {514: "cmd", 135: "msrpc"}, [3949, 521]),
            (dict(protocol="tcp", platform="ios"), {514: "cmd", 135: "msrpc"}, [3949, 521]),
            (dict(protocol="tcp", platform="cnx"), {514: "cmd", 3949: "drip"}, [135, 521]),
            (dict(protocol="udp", platform="ios"), {514: "syslog", 521: "ripv6"}, [135, 3949]),
            (dict(protocol="udp", platform="cnx"), {514: "syslog"}, [135, 521, 3949]),
        ]:
            obj = PortName(**kwargs)
            result = obj.ports()
            self._test_keys(result, req_d, f"{kwargs=}")
            self._test_no_keys(result, absent, f"{kwargs=}")

    # ========================== functions ===========================

    def test_valid__all_known_names(self):
        """all_known_names()"""
        results = all_known_names()
        req = {"cmd", "syslog", "drip", "ripv6", "msrpc"}
        result = set(results).intersection(req)
        self.assertEqual(result, req, msg="all_known_names")


if __name__ == "__main__":
    unittest.main()
