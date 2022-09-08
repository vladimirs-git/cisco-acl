"""Unittest protocol.py"""

import unittest

from cisco_acl import Protocol
from tests.helpers_test import Helpers


# noinspection DuplicatedCode
class Test(Helpers):
    """Protocol"""

    # ========================== redefined ===========================

    def test_valid__hash__(self):
        """Protocol.__hash__()"""
        tcp = "tcp"
        proto_o = Protocol(tcp)
        result = proto_o.__hash__()
        req = tcp.__hash__()
        self.assertEqual(result, req, msg=f"{tcp=}")

    def test_valid__eq__(self):
        """Protocol.__eq__() __ne__()"""
        proto_o = Protocol("tcp")
        for other_o, req, in [
            ("tcp", True),
            (Protocol("tcp"), True),
            (Protocol("udp"), False),
        ]:
            result = proto_o.__eq__(other_o)
            self.assertEqual(result, req, msg=f"{proto_o=} {other_o=}")
            result = proto_o.__ne__(other_o)
            self.assertEqual(result, not req, msg=f"{proto_o=} {other_o=}")

    def test_valid__lt__(self):
        """Protocol.__lt__() __le__() __gt__() __ge__()"""
        tcp, udp = "tcp", "udp"
        for proto_o, other_o, req_lt, req_le, req_gt, req_ge in [
            (Protocol(tcp), Protocol(tcp), False, True, False, True),
            (Protocol(tcp), Protocol(udp), True, True, False, False),
        ]:
            result = proto_o.__lt__(other_o)
            self.assertEqual(result, req_lt, msg=f"{proto_o=} {other_o=}")
            result = proto_o.__le__(other_o)
            self.assertEqual(result, req_le, msg=f"{proto_o=} {other_o=}")
            result = proto_o.__gt__(other_o)
            self.assertEqual(result, req_gt, msg=f"{proto_o=} {other_o=}")
            result = proto_o.__ge__(other_o)
            self.assertEqual(result, req_ge, msg=f"{proto_o=} {other_o=}")

    # =========================== property ===========================

    def test_valid__line(self):
        """Protocol.line()"""
        for line, req_d in [
            ("", dict(line="ip", name="ip", number=0)),
            ("ahp", dict(line="ahp", name="ahp", number=51)),
            ("egp", dict(line="egp", name="egp", number=8)),
            ("eigrp", dict(line="eigrp", name="eigrp", number=88)),
            ("esp", dict(line="esp", name="esp", number=50)),
            ("gre", dict(line="gre", name="gre", number=47)),
            ("icmp", dict(line="icmp", name="icmp", number=1)),
            ("igmp", dict(line="igmp", name="igmp", number=2)),
            ("ip", dict(line="ip", name="ip", number=0)),
            ("ipip", dict(line="ipip", name="ipip", number=4)),
            ("ipv6", dict(line="ipv6", name="ipv6", number=41)),
            ("nos", dict(line="nos", name="nos", number=94)),
            ("ospf", dict(line="ospf", name="ospf", number=89)),
            ("pcp", dict(line="pcp", name="pcp", number=108)),
            ("pim", dict(line="pim", name="pim", number=103)),
            ("tcp", dict(line="tcp", name="tcp", number=6)),
            ("udp", dict(line="udp", name="udp", number=17)),

            ("0", dict(line="ip", name="ip", number=0)),
            ("1", dict(line="icmp", name="icmp", number=1)),
            ("3", dict(line="3", name="", number=3)),
            ("255", dict(line="255", name="", number=255)),

            (0, dict(line="ip", name="ip", number=0)),
            (1, dict(line="icmp", name="icmp", number=1)),
            (3, dict(line="3", name="", number=3)),
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
        req_d = dict(line="ip", name="ip", number=0)
        self._test_attrs(obj=proto_o, req_d=req_d, msg="deleter line")

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
            ("ip", dict(line="ip", name="ip", number=0)),
            ("0", dict(line="ip", name="ip", number=0)),
            ("icmp", dict(line="icmp", name="icmp", number=1)),
            ("1", dict(line="icmp", name="icmp", number=1)),
            ("ahp", dict(line="ahp", name="ahp", number=51)),
            ("51", dict(line="ahp", name="ahp", number=51)),
            ("255", dict(line="255", name="", number=255)),
        ]:
            # getter
            proto_o = Protocol(req_d["line"])
            self._test_attrs(obj=proto_o, req_d=req_d, msg=f"getter {name=}")

            # setter
            proto_o.name = name
            self._test_attrs(obj=proto_o, req_d=req_d, msg=f"setter {name=}")

        # deleter
        proto_o = Protocol("ip")
        with self.assertRaises(AttributeError, msg="deleter name"):
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
        with self.assertRaises(AttributeError, msg="deleter number"):
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

    def test_valid__protocol_nr(self):
        """Protocol.protocol_nr"""
        for protocol_nr, line, req_d in [
            # number
            (True, "", dict(line="0", name="ip", number=0)),
            (True, "ip", dict(line="0", name="ip", number=0)),
            (True, "0", dict(line="0", name="ip", number=0)),
            (True, 0, dict(line="0", name="ip", number=0)),
            (True, "icmp", dict(line="1", name="icmp", number=1)),
            (True, "1", dict(line="1", name="icmp", number=1)),
            (True, 1, dict(line="1", name="icmp", number=1)),
            (True, "3", dict(line="3", name="", number=3)),
            (True, 3, dict(line="3", name="", number=3)),
            (True, "tcp", dict(line="6", name="tcp", number=6)),
            (True, "6", dict(line="6", name="tcp", number=6)),
            (True, 6, dict(line="6", name="tcp", number=6)),
            (True, "255", dict(line="255", name="", number=255)),
            (True, 255, dict(line="255", name="", number=255)),
            # name
            (False, "", dict(line="ip", name="ip", number=0)),
            (False, "ip", dict(line="ip", name="ip", number=0)),
            (False, "0", dict(line="ip", name="ip", number=0)),
            (False, 0, dict(line="ip", name="ip", number=0)),
            (False, "icmp", dict(line="icmp", name="icmp", number=1)),
            (False, "1", dict(line="icmp", name="icmp", number=1)),
            (False, 1, dict(line="icmp", name="icmp", number=1)),
            (False, "3", dict(line="3", name="", number=3)),
            (False, 3, dict(line="3", name="", number=3)),
            (False, "tcp", dict(line="tcp", name="tcp", number=6)),
            (False, "6", dict(line="tcp", name="tcp", number=6)),
            (False, 6, dict(line="tcp", name="tcp", number=6)),
            (False, "255", dict(line="255", name="", number=255)),
            (False, 255, dict(line="255", name="", number=255)),
        ]:
            # getter
            proto_o = Protocol(line=line, protocol_nr=protocol_nr)
            self._test_attrs(obj=proto_o, req_d=req_d, msg=f"getter {line=}")

            # setter
            proto_o = Protocol(line=line)
            proto_o.protocol_nr = protocol_nr
            self._test_attrs(obj=proto_o, req_d=req_d, msg=f"setter {line=}")

        # deleter
        proto_o = Protocol(line="ahp", protocol_nr=True)
        # noinspection PyPropertyAccess
        del proto_o.line
        req_d = dict(line="0", name="ip", number=0)
        self._test_attrs(obj=proto_o, req_d=req_d, msg="deleter line")

    def test_valid__platform(self):
        """Protocol.platform()"""
        for platform, to_platform, line, req_d in [
            ("ios", "ios", "icmp", dict(line="icmp")),
            ("ios", "ios", "egp", dict(line="egp")),
            ("ios", "ios", "255", dict(line="255")),

            ("ios", "nxos", "icmp", dict(line="icmp")),
            ("ios", "nxos", "egp", dict(line="8")),
            ("ios", "nxos", "255", dict(line="255")),

            ("nxos", "ios", "icmp", dict(line="icmp")),
            ("nxos", "ios", "8", dict(line="egp")),
            ("nxos", "ios", "255", dict(line="255")),

            ("nxos", "nxos", "icmp", dict(line="icmp")),
            ("nxos", "nxos", "8", dict(line="8")),
            ("nxos", "nxos", "255", dict(line="255")),

            ("cnx", "ios", "icmp", dict(line="icmp")),
            ("cnx", "ios", "8", dict(line="egp")),
            ("cnx", "ios", "255", dict(line="255")),

            ("cnx", "nxos", "icmp", dict(line="icmp")),
            ("cnx", "nxos", "8", dict(line="8")),
            ("cnx", "nxos", "255", dict(line="255")),
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
        with self.assertRaises(AttributeError, msg="deleter platform"):
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
