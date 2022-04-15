"""unittest protocol.py"""

import unittest

from cisco_acl.protocol import Protocol
from helpers_test import Helpers


# noinspection DuplicatedCode
class Test(Helpers):
    """Protocol"""

    # =========================== property ===========================

    def test_valid__line(self):
        """Protocol.line()"""
        ip_d = dict(line="ip", name="ip", number=0)
        for line, req_d in [
            ("", ip_d),
            ("ahp", dict(line="ahp", name="ahp", number=51)),
            ("egp", dict(line="egp", name="egp", number=8)),
            ("eigrp", dict(line="eigrp", name="eigrp", number=88)),
            ("esp", dict(line="esp", name="esp", number=50)),
            ("gre", dict(line="gre", name="gre", number=47)),
            ("icmp", dict(line="icmp", name="icmp", number=1)),
            ("igmp", dict(line="igmp", name="igmp", number=2)),
            ("ip", ip_d),
            ("ipip", dict(line="ipip", name="ipip", number=4)),
            ("ipv6", dict(line="ipv6", name="ipv6", number=41)),
            ("nos", dict(line="nos", name="nos", number=94)),
            ("ospf", dict(line="ospf", name="ospf", number=89)),
            ("pcp", dict(line="pcp", name="pcp", number=108)),
            ("pim", dict(line="pim", name="pim", number=103)),
            ("tcp", dict(line="tcp", name="tcp", number=6)),
            ("udp", dict(line="udp", name="udp", number=17)),

            ("0", ip_d),
            ("1", dict(line="icmp", name="icmp", number=1)),
            ("255", dict(line="255", name="", number=255)),

            (0, ip_d),
            (1, dict(line="icmp", name="icmp", number=1)),
            (255, dict(line="255", name="", number=255)),
        ]:
            # getter
            proto_o = Protocol(line)
            self._test_attrs(obj=proto_o, req_d=req_d, msg=f"getter {line=}")

            # setter
            proto_o.line = line
            self._test_attrs(obj=proto_o, req_d=req_d, msg=f"setter {line=}")

        # deleter
        proto_o = Protocol(line="ahp")
        # noinspection PyPropertyAccess
        del proto_o.line
        self._test_attrs(obj=proto_o, req_d=ip_d, msg="deleter line")

    def test_invalid__line(self):
        """Protocol.line()"""
        for line, error in [
            ("typo", ValueError),
            (-1, ValueError),
            (256, ValueError),
            ("-1", ValueError),
            ("256", ValueError),
        ]:
            with self.assertRaises(error, msg=f"{line=}"):
                Protocol(line)

    def test_valid__name(self):
        """Protocol.name()"""
        for name, req_d in [
            ("", dict(line="ip", name="ip", number=0)),
            ("0", dict(line="ip", name="ip", number=0)),
            ("ahp", dict(line="ahp", name="ahp", number=51)),
            ("51", dict(line="ahp", name="ahp", number=51)),
        ]:
            # getter
            proto_o = Protocol(req_d["line"])
            self._test_attrs(obj=proto_o, req_d=req_d, msg=f"getter {name=}")

            # setter
            proto_o.name = name
            self._test_attrs(obj=proto_o, req_d=req_d, msg=f"setter {name=}")

        # deleter
        proto_o = Protocol("ip")
        with self.assertRaises(AttributeError, msg=f"deleter name"):
            # noinspection PyPropertyAccess
            del proto_o.name

    def test_invalid__name(self):
        """Protocol.name()"""
        proto_o = Protocol("icmp")
        for name, error in [
            ("typo", ValueError),
            (-1, TypeError),
            (256, TypeError),
            ("-1", ValueError),
            ("256", ValueError),
        ]:
            with self.assertRaises(error, msg=f"{name=}"):
                proto_o.name = name

    def test_valid__number(self):
        """Protocol.number()"""
        for number, req_d in [
            ("0", dict(line="ip", name="ip", number=0)),
            (0, dict(line="ip", name="ip", number=0)),
            ("1", dict(line="icmp", name="icmp", number=1)),
            (1, dict(line="icmp", name="icmp", number=1)),
            ("255", dict(line="255", name="", number=255)),
            (255, dict(line="255", name="", number=255)),
        ]:
            # getter
            proto_o = Protocol(req_d["line"])
            self._test_attrs(obj=proto_o, req_d=req_d, msg=f"getter {number=}")

            # setter
            proto_o.number = number
            self._test_attrs(obj=proto_o, req_d=req_d, msg=f"setter {number=}")

            # deleter
        proto_o = Protocol("ip")
        with self.assertRaises(AttributeError, msg=f"deleter number"):
            # noinspection PyPropertyAccess
            del proto_o.number

    def test_invalid__number(self):
        """Protocol.number()"""
        proto_o = Protocol("icmp")
        for number, error in [
            ("ip", TypeError),
            (-1, ValueError),
            (256, ValueError),
            ("-1", TypeError),
            ("256", ValueError),
        ]:
            with self.assertRaises(error, msg=f"{number=}"):
                proto_o.number = number

    def test_valid__platform(self):
        """Protocol.platform()"""
        for platform, to_platform, line, req_d in [
            ("ios", "ios", "icmp", dict(line="icmp")),
            ("ios", "ios", "egp", dict(line="egp")),
            ("ios", "ios", "255", dict(line="255")),

            ("ios", "cnx", "icmp", dict(line="icmp")),
            ("ios", "cnx", "egp", dict(line="8")),
            ("ios", "cnx", "255", dict(line="255")),

            ("cnx", "ios", "icmp", dict(line="icmp")),
            ("cnx", "ios", "8", dict(line="egp")),
            ("cnx", "ios", "255", dict(line="255")),

            ("cnx", "cnx", "icmp", dict(line="icmp")),
            ("cnx", "cnx", "8", dict(line="8")),
            ("cnx", "cnx", "255", dict(line="255")),
        ]:
            # getter
            proto_o = Protocol(line, platform=platform)
            req_d_ = dict(line=line)
            self._test_attrs(obj=proto_o, req_d=req_d_, msg=f"getter {platform=}")

            # setter
            proto_o.platform = to_platform
            self._test_attrs(obj=proto_o, req_d=req_d, msg=f"setter {platform=}")

            # deleter
        proto_o = Protocol("ip")
        with self.assertRaises(AttributeError, msg=f"deleter platform"):
            # noinspection PyPropertyAccess
            del proto_o.platform

    def test_invalid__platform(self):
        """Ace.platform"""
        proto_o = Protocol("ip")
        with self.assertRaises(ValueError, msg="platform"):
            proto_o.platform = "typo"
        with self.assertRaises(ValueError, msg="platform"):
            Protocol("ip", platform="typo")


if __name__ == "__main__":
    unittest.main()
