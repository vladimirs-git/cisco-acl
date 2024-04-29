"""Unittest protocol.py"""

import unittest

import dictdiffer

from cisco_acl import Protocol
from tests.helpers_test import Helpers, UUID, UUID_R


# noinspection DuplicatedCode
class Test(Helpers):
    """Protocol"""

    # ========================== redefined ===========================

    def test_valid__hash__(self):
        """Protocol.__hash__()"""
        tcp = "tcp"
        obj = Protocol(tcp)
        result = obj.__hash__()
        req = tcp.__hash__()
        self.assertEqual(result, req, msg=f"{tcp=}")

    def test_valid__eq__(self):
        """Protocol.__eq__() __ne__()"""
        obj1 = Protocol("tcp")
        for obj2, req, in [
            ("tcp", True),
            (Protocol("tcp"), True),
            (Protocol("udp"), False),
        ]:
            result = obj1.__eq__(obj2)
            self.assertEqual(result, req, msg=f"{obj1=} {obj2=}")
            result = obj1.__ne__(obj2)
            self.assertEqual(result, not req, msg=f"{obj1=} {obj2=}")

    def test_valid__lt__(self):
        """Protocol.__lt__() __le__() __gt__() __ge__()"""
        tcp, udp = "tcp", "udp"
        for obj1, obj2, req_lt, req_le, req_gt, req_ge in [
            (Protocol(tcp), Protocol(tcp), False, True, False, True),
            (Protocol(tcp), Protocol(udp), True, True, False, False),
        ]:
            result = obj1.__lt__(obj2)
            self.assertEqual(result, req_lt, msg=f"{obj1=} {obj2=}")
            result = obj1.__le__(obj2)
            self.assertEqual(result, req_le, msg=f"{obj1=} {obj2=}")
            result = obj1.__gt__(obj2)
            self.assertEqual(result, req_gt, msg=f"{obj1=} {obj2=}")
            result = obj1.__ge__(obj2)
            self.assertEqual(result, req_ge, msg=f"{obj1=} {obj2=}")

    def test_valid__repr__(self):
        """Protocol.__repr__()"""
        for kwargs, req in [
            (dict(line="tcp", platform="asa", note="a", protocol_nr=True, has_port=True, typo="b"),
             "Protocol(\"tcp\", platform=\"asa\", note=\"a\", protocol_nr=True, has_port=True)"),
            (dict(line="tcp", platform="ios", note=""), "Protocol(\"tcp\")"),
            (dict(line="tcp", platform="nxos", note="a", protocol_nr=True, has_port=True, typo="b"),
             "Protocol(\"tcp\", platform=\"nxos\", note=\"a\", protocol_nr=True, has_port=True)"),
        ]:
            obj = Protocol(**kwargs)
            result = obj.__repr__()
            result = self._quotation(result)
            self.assertEqual(result, req, msg=f"{result=}")

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
            obj1 = Protocol(line)
            self._test_attrs(obj=obj1, req_d=req_d, msg=f"{line=}")
            # setter
            obj1.line = line
            self._test_attrs(obj=obj1, req_d=req_d, msg=f"{line=}")

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
            obj = Protocol(req_d["line"])
            self._test_attrs(obj=obj, req_d=req_d, msg=f"{name=}")
            # setter
            obj.name = name
            self._test_attrs(obj=obj, req_d=req_d, msg=f"{name=}")

    def test_invalid__name(self):
        """Protocol.name()"""
        obj = Protocol("icmp")
        for name, error in [
            ("typo", ValueError),
            (-1, TypeError),
            (256, TypeError),
            ("-1", ValueError),
            ("256", ValueError),
        ]:
            with self.assertRaises(error, msg=f"{name=}"):
                obj.name = name

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
            obj = Protocol(req_d["line"])
            self._test_attrs(obj=obj, req_d=req_d, msg=f"{number=}")
            # setter
            obj.number = number
            self._test_attrs(obj=obj, req_d=req_d, msg=f"{number=}")

    def test_invalid__number(self):
        """Protocol.number()"""
        obj = Protocol("icmp")
        for number, error in [
            ("ip", ValueError),
            (-1, ValueError),
            (256, ValueError),
            ("-1", ValueError),
            ("256", ValueError),
        ]:
            with self.assertRaises(error, msg=f"{number=}"):
                obj.number = number

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
            obj = Protocol(line=line, protocol_nr=protocol_nr)
            self._test_attrs(obj=obj, req_d=req_d, msg=f"{line=}")
            # setter
            obj = Protocol(line=line)
            obj.protocol_nr = protocol_nr
            self._test_attrs(obj=obj, req_d=req_d, msg=f"{line=}")

    def test_valid__platform(self):
        """Protocol.platform()"""
        for platform, platform_new, line, req_d in [
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
        ]:
            msg = f"{platform=} {platform_new=} {line=}"
            obj = Protocol(line, platform=platform)
            req_d_ = dict(line=line)
            self._test_attrs(obj=obj, req_d=req_d_, msg=msg)
            # setter
            obj.platform = platform_new
            self._test_attrs(obj=obj, req_d=req_d, msg=msg)

    def test_invalid__platform(self):
        """Protocol.platform"""
        obj = Protocol("ip")
        with self.assertRaises(ValueError, msg="platform"):
            obj.platform = "typo"
        with self.assertRaises(ValueError, msg="platform"):
            Protocol("ip", platform="typo")

    # =========================== method =============================

    def test_valid__copy(self):
        """Protocol.copy()"""
        obj1 = Protocol(line="tcp", platform="ios", note="a", protocol_nr=True, has_port=True)
        obj2 = obj1.copy()

        # change obj1 to check obj1 does not depend on obj2
        new_obj1_kwargs = dict(line="udp", platform="nxos", note="b",
                               protocol_nr=False, has_port=False)
        for arg, value in new_obj1_kwargs.items():
            setattr(obj1, arg, value)

        req1_d = dict(line="udp", platform="nxos", note="b", protocol_nr=False, has_port=False)
        req2_d = dict(line="tcp", platform="ios", note="a", protocol_nr=True, has_port=True)
        self._test_attrs(obj1, req1_d, msg="obj1 does not depend on obj2")
        self._test_attrs(obj2, req2_d, msg="obj2 copied from obj1")

    def test_valid__data(self):
        """Protocol.data()"""
        kwargs1 = dict(line="tcp", platform="ios", note="a")
        req1 = dict(line="tcp",
                    platform="ios",
                    version="0",
                    note="a",
                    protocol_nr=False,
                    has_port=False,
                    name="tcp",
                    number=6)

        for kwargs, req_d in [
            (kwargs1, req1),
        ]:
            obj = Protocol(**kwargs)
            obj.uuid = UUID

            result = obj.data()
            diff = list(dictdiffer.diff(first=result, second=req_d))
            self.assertEqual(diff, [], msg=f"{kwargs=}")

            result = obj.data(uuid=True)
            diff = list(dictdiffer.diff(first=result, second=req_d))
            self.assertEqual(diff, UUID_R, msg=f"{kwargs=}")


if __name__ == "__main__":
    unittest.main()
