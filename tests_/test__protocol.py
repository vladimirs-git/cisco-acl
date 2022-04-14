"""unittest protocol.py"""

import unittest

from cisco_acl.protocol import Protocol


# noinspection DuplicatedCode
class Test(unittest.TestCase):
    """Protocol"""

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
            ("255", dict(line="255", name="", number=255)),

            (0, dict(line="ip", name="ip", number=0)),
            (1, dict(line="icmp", name="icmp", number=1)),
            (255, dict(line="255", name="", number=255)),
        ]:
            # getter
            proto_o = Protocol(line)
            result = str(proto_o)
            req = req_d["line"]
            self.assertEqual(result, req, msg=f"{line=}")

            # setter
            proto_o.line = line
            result = proto_o.line
            self.assertEqual(result, req, msg=f"setter {line=}")
            for attr, req in req_d.items():
                result = getattr(proto_o, attr)
                self.assertEqual(result, req, msg=f"{line=} {attr=}")

        # deleter
        proto_o = Protocol("icmp")
        del proto_o.line
        result = proto_o.line
        self.assertEqual(result, "ip", msg="deleter line")
        result = proto_o.name
        self.assertEqual(result, "ip", msg="deleter name")
        result = proto_o.number
        self.assertEqual(result, 0, msg="deleter number")

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
            ("ahp", dict(line="ahp", name="ahp", number=51)),
        ]:
            # setter
            proto_o = Protocol("icmp")
            proto_o.name = name
            result = proto_o.name
            req = req_d["name"]
            self.assertEqual(result, req, msg=f"setter {name=}")
            for attr, req in req_d.items():
                result = getattr(proto_o, attr)
                self.assertEqual(result, req, msg=f"{name=} {attr=}")

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
            (0, dict(line="ip", name="ip", number=0)),
            ("0", dict(line="ip", name="ip", number=0)),
            (1, dict(line="icmp", name="icmp", number=1)),
            ("1", dict(line="icmp", name="icmp", number=1)),
            (255, dict(line="255", name="", number=255)),
            ("255", dict(line="255", name="", number=255)),
        ]:
            # setter
            proto_o = Protocol("icmp")
            proto_o.number = number
            result = proto_o.number
            req = req_d["number"]
            self.assertEqual(result, req, msg=f"setter {number=}")
            for attr, req in req_d.items():
                result = getattr(proto_o, attr)
                self.assertEqual(result, req, msg=f"{number=} {attr=}")

    def test_invalid__number(self):
        """Protocol.number()"""
        proto_o = Protocol("icmp")
        for number, error in [
            ("typo", TypeError),
            (-1, ValueError),
            (256, ValueError),
            ("-1", TypeError),
            ("256", ValueError),
        ]:
            with self.assertRaises(error, msg=f"{number=}"):
                proto_o.number = number


if __name__ == "__main__":
    unittest.main()
