"""unittest acl.py"""

import unittest

from cisco_acl import Ace, AceGroup, Acl, Remark
from tests_.helpers_test import (
    ACL_CNX,
    ACL_IOS,
    ACL_NAME_CNX,
    ACL_NAME_IOS,
    ACL_NAME_RP_CNX,
    ACL_NAME_RP_IOS,
    ACL_RP_CNX,
    ACL_RP_IOS,
    DENY_IP,
    DENY_IP_1,
    DENY_IP_2,
    ETH1,
    ETH2,
    PERMIT_ADDR_GR,
    PERMIT_ICMP,
    PERMIT_IP,
    PERMIT_IP_1,
    PERMIT_IP_2,
    PERMIT_OBJ_GR,
    REMARK,
    REMARK_1,
)

REMARK_10 = Remark(f"10 {REMARK}")
REMARK_20 = Remark(f"20 {REMARK}")
ACE_10 = Ace(f"10 {PERMIT_IP}")
ACE_20 = Ace(f"20 {PERMIT_IP}")
ACE_GR_10 = AceGroup([Ace(f"10 {DENY_IP}"), Ace(PERMIT_IP)])
ACE_GR_20 = AceGroup([Ace(f"20 {DENY_IP}"), Ace(PERMIT_IP)])


# noinspection DuplicatedCode
class Test(unittest.TestCase):
    """Acl"""

    # ============================= init =============================

    def test_valid__init_items(self):
        """Acl._init_items()"""
        acl_o_ = Acl()
        for items, req in [
            # str
            (None, []),
            ("", []),
            (REMARK, [REMARK]),
            (REMARK_1, [REMARK_1]),
            (PERMIT_IP, [PERMIT_IP]),
            (PERMIT_IP_1, [PERMIT_IP_1]),

            # List[str]
            ([], []),
            ([REMARK, PERMIT_IP], [REMARK, PERMIT_IP]),
            ([REMARK_1, PERMIT_IP_2], [REMARK_1, PERMIT_IP_2]),
            ([PERMIT_IP_2, REMARK_1], [PERMIT_IP_2, REMARK_1]),

            # object
            (Remark(REMARK), [REMARK]),
            (Ace(PERMIT_IP), [PERMIT_IP]),
            (Ace(PERMIT_ADDR_GR, platform="ios"), [PERMIT_OBJ_GR]),

            # List[object]
            ([Remark(REMARK_1), Ace(PERMIT_IP_1)], [REMARK_1, PERMIT_IP_1]),
            ([Ace(PERMIT_IP_1), Ace(DENY_IP_2)], [PERMIT_IP_1, DENY_IP_2]),
            ([Ace(DENY_IP_2), Ace(PERMIT_IP_1)], [DENY_IP_2, PERMIT_IP_1]),
        ]:
            if items:
                result_items = acl_o_._convert_any_to_aces(items=items)
                result = [str(o) for o in result_items]
                self.assertEqual(result, req, msg=f"{items=}")

            acl_o = Acl(items=items)
            result = [str(o) for o in acl_o.items]
            self.assertEqual(result, req, msg=f"{items=}")

        # input ios, output cnx
        acl_o = Acl(items=[PERMIT_OBJ_GR], platform="cnx")
        result = [str(o) for o in acl_o]
        self.assertEqual(result, [PERMIT_ADDR_GR], msg=f"{items=}")

    def test_invalid__init_items(self):
        """Acl._init_items()"""
        acl_o = Acl()
        for items, error, in [
            (None, TypeError),
            ("", ValueError),
            (1, TypeError),
            ([1], TypeError),
            (["typo"], ValueError),
            ([Ace(PERMIT_IP, platform="cnx")], ValueError),
        ]:
            with self.assertRaises(error, msg=f"{items=}"):
                acl_o._convert_any_to_aces(items=items)
            if not items:
                continue
            with self.assertRaises(error, msg=f"{items=}"):
                Acl(items=items, platform="ios")

    # =========================== property ===========================
    def test_valid__line(self):
        """Acl.line"""
        for platform, line, req_d, in [
            ("ios", "\n", dict(line=f"{ACL_IOS}\n", name="")),
            ("ios", ACL_IOS, dict(line=f"{ACL_IOS}\n", name="")),
            ("ios", ACL_NAME_IOS, dict(line=f"{ACL_NAME_IOS}\n", name="A")),
            ("ios", PERMIT_IP, dict(line=f"{ACL_IOS}\n  {PERMIT_IP}", name="")),
            ("ios", ACL_RP_IOS, dict(line=ACL_RP_IOS, name="")),
            ("ios", ACL_NAME_RP_IOS, dict(line=ACL_NAME_RP_IOS, name="A")),

            ("cnx", "\n", dict(line=f"{ACL_CNX}\n", name="")),
            ("cnx", ACL_CNX, dict(line=f"{ACL_CNX}\n", name="")),
            ("cnx", ACL_NAME_CNX, dict(line=f"{ACL_NAME_CNX}\n", name="A")),
            ("cnx", PERMIT_IP, dict(line=f"{ACL_CNX}\n  {PERMIT_IP}", name="")),
            ("cnx", ACL_RP_CNX, dict(line=ACL_RP_CNX, name="")),
            ("cnx", ACL_NAME_RP_CNX, dict(line=ACL_NAME_RP_CNX, name="A")),
        ]:
            # getter
            acl_o = Acl(line, platform=platform)
            result = str(acl_o)
            req = req_d["line"]
            self.assertEqual(result, req, msg=f"{line=}")
            for attr, req in req_d.items():
                result = getattr(acl_o, attr)
                self.assertEqual(result, req, msg=f"{line=}")

            # setter
            acl_o.line = line
            result = str(acl_o)
            req = req_d["line"]
            self.assertEqual(result, req, msg=f"{line=}")
            for attr, req in req_d.items():
                result = getattr(acl_o, attr)
                self.assertEqual(result, req, msg=f"{line=}")

            # deleter
            del acl_o.line
            result = str(acl_o)
            req = f"{ACL_CNX}\n" if acl_o.platform == "cnx" else f"{ACL_IOS}\n"
            # noinspection PyUnboundLocalVariable
            self.assertEqual(result, req, msg=f"{line=}")

    def test_invalid__line(self):
        """Acl.line"""
        acl_o = Acl()
        for line, error, in [
            ("typo", ValueError),
            (f"{ACL_NAME_RP_IOS}\ntypo", ValueError),
        ]:
            with self.assertRaises(error, msg=f"{line=}"):
                acl_o.line = line

    def test_valid__indent(self):
        """Acl.indent"""
        for indent, req in [
            (None, "  "),
            (0, ""),
            (1, " "),
        ]:
            # getter
            acl_o = Acl(indent=indent)
            result = acl_o.indent
            self.assertEqual(result, req, msg=f"getter {indent=}")

            # setter
            acl_o.indent = indent
            result = acl_o.indent
            self.assertEqual(result, req, msg=f"setter {indent=}")

            # deleter
            del acl_o.indent
            result = acl_o.indent
            # noinspection PyUnboundLocalVariable
            self.assertEqual(result, "", msg=f"deleter {indent=}")

    def test_invalid__indent(self):
        """Acl.indent"""
        for indent, error in [
            ("", TypeError),
            ([], TypeError),
            (-1, ValueError),
        ]:
            with self.assertRaises(error, msg=f"{indent=}"):
                Acl(indent=indent)

    def test_valid__ip_acl_name(self):
        """Acl.ip_acl_name"""
        for platform, req in [
            ("ios", "ip access-list extended NAME"),
            ("cnx", "ip access-list NAME"),
        ]:
            # getter
            acl_o = Acl(name="NAME", platform=platform)
            result = acl_o.ip_acl_name
            self.assertEqual(result, req, msg=f"getter {platform=}")

        # setter
        with self.assertRaises(AttributeError, msg="setter ip_acl_name"):
            # noinspection PyPropertyAccess
            acl_o.ip_acl_name = "a"

        # deleter
        with self.assertRaises(AttributeError, msg="deleter ip_acl_name"):
            # noinspection PyPropertyAccess
            del acl_o.ip_acl_name

    def test_valid__items(self):
        """Acl.items"""
        acl_o = Acl()
        for items, req, in [
            ([], []),
            ([Remark(REMARK)], [REMARK]),
            ([Ace(PERMIT_IP)], [PERMIT_IP]),
            ([AceGroup(PERMIT_IP)], [PERMIT_IP]),
            ([Remark(REMARK), AceGroup(PERMIT_IP), Ace(DENY_IP)], [REMARK, PERMIT_IP, DENY_IP]),
            ([Remark(REMARK), AceGroup([PERMIT_IP, DENY_IP])], [REMARK, f"{PERMIT_IP}\n{DENY_IP}"]),
        ]:
            acl_o.items = items
            result = [str(o) for o in acl_o]
            self.assertEqual(result, req, msg=f"{items=}")

    def test_invalid__items(self):
        """Acl.items"""
        acl_o = Acl()
        for items, error, in [
            (1, TypeError),
            (PERMIT_IP, TypeError),
            ([PERMIT_IP], TypeError),
        ]:
            with self.assertRaises(error, msg=f"{items=}"):
                acl_o.items = items

    def test_valid__name(self):
        """Acl.name"""
        for name, req in [
            (None, ""),
            ("", ""),
            ("A1", "A1"),
            ("a_", "a_"),
            ("\tab\n", "ab"),
        ]:
            # getter
            acl_o = Acl(name=name, line_length=2)
            result = acl_o.name
            self.assertEqual(result, req, msg=f"getter {name=}")

            # setter
            acl_o.name = name
            result = acl_o.name
            self.assertEqual(result, req, msg=f"setter {name=}")

            # deleter
            del acl_o.name
            result = acl_o.name
            # noinspection PyUnboundLocalVariable
            self.assertEqual(result, "", msg=f"deleter {name=}")

    def test_valid__platform(self):
        """Ace.platform()"""
        acl_ios = "ip access-list extended NAME\n" \
                  "  remark text\n" \
                  "  permit ip object-group A object-group B log\n" \
                  "  permit ip host 1.1.1.1 host 2.2.2.2\n" \
                  "  permit ip 1.1.1.0 0.0.0.255 2.2.2.0 0.0.0.255\n" \
                  "  permit ip 1.1.0.0 0.0.3.3 2.2.0.0 0.0.3.3\n" \
                  "  permit tcp any eq 1 any neq 3\n" \
                  "  permit tcp any gt 65533 any lt 3"
        acl_cnx = "ip access-list NAME\n" \
                  "  remark text\n" \
                  "  permit ip addrgroup A addrgroup B log\n" \
                  "  permit ip 1.1.1.1/32 2.2.2.2/32\n" \
                  "  permit ip 1.1.1.0/24 2.2.2.0/24\n" \
                  "  permit ip 1.1.0.0 0.0.3.3 2.2.0.0 0.0.3.3\n" \
                  "  permit tcp any eq 1 any neq 3\n" \
                  "  permit tcp any gt 65533 any lt 3"
        for platform, to_platform, line, req in [
            ("ios", "ios", acl_ios, acl_ios),
            ("ios", "cnx", acl_ios, acl_cnx),
            ("cnx", "ios", acl_cnx, acl_ios),
            ("cnx", "cnx", acl_cnx, acl_cnx),
        ]:
            # getter
            acl_o = Acl(line, platform=platform)
            result = acl_o.line
            self.assertEqual(result, line, msg=f"{platform=} {to_platform=} {line=}")

            acl_o.platform = to_platform
            result = str(acl_o)
            req_l = req.split("\n")
            result_l = result.split("\n")
            for idx, result_ in enumerate(result_l):
                req_ = req_l[idx]
                if result_ != req_:
                    self.assertEqual(result_, req_, msg=f"{idx=} {req_=}")
            self.assertEqual(result, req, msg=f"{platform=} {to_platform=} {line=}")

    # =========================== methods ============================


    def test_valid__copy(self):
        """Acl.copy()"""
        acl_o1 = Acl(items=[PERMIT_IP, DENY_IP], input=[ETH1, ETH2])
        acl_o2 = acl_o1.copy()
        # mix data
        acl_o2.items[0], acl_o2.items[1] = acl_o2.items[1], acl_o2.items[0]
        intf = acl_o2.interface
        intf.input[0], intf.input[1] = intf.input[1], intf.input[0]

        for acl_o, req, intf_req in [
            (acl_o1, [PERMIT_IP, DENY_IP], [ETH1, ETH2]),
            (acl_o2, [DENY_IP, PERMIT_IP], [ETH2, ETH1]),
        ]:
            result = [str(o) for o in acl_o]
            self.assertEqual(result, req, msg=f"{acl_o=}")
            result = acl_o.interface.input
            self.assertEqual(result, intf_req, msg=f"{acl_o=}")

    def test_valid__resequence(self):
        """Acl.resequence()"""
        aces = [Ace(PERMIT_IP_2), Ace(DENY_IP_1), Remark(REMARK)]
        aces_req1 = [Ace(f"10 {PERMIT_IP}"), Ace(f"20 {DENY_IP}"), Remark(f"30 {REMARK}")]
        aces_req2 = [Ace(f"2 {PERMIT_IP}"), Ace(f"5 {DENY_IP}"), Remark(f"8 {REMARK}")]

        group = [Ace(PERMIT_IP_2), AceGroup([Ace(DENY_IP_1), Remark(REMARK)]), Ace(PERMIT_ICMP)]
        group_req1 = [
            Ace(f"10 {PERMIT_IP}"),
            AceGroup([Ace(f"20 {DENY_IP}"), Remark(f"30 {REMARK}")]),
            Ace(f"40 {PERMIT_ICMP}"),
        ]
        for items, kwargs, req in [
            (aces, {}, aces_req1),
            (aces, dict(start=2, step=3), aces_req2),
            (group, {}, group_req1),
        ]:
            acl_o = Acl(items=items)
            acl_o.resequence(**kwargs)
            result = acl_o.items
            self.assertEqual(result, req, msg=f"{items=} {kwargs=}")

    def test_invalid__resequence(self):
        """Acl.resequence()"""
        items1 = [PERMIT_IP_2, DENY_IP_1]
        for items, kwargs, error in [
            (items1, dict(start=0), ValueError),
            (items1, dict(start=4294967296), ValueError),
            (items1, dict(step=0), ValueError),
            (items1, dict(step=4294967296), ValueError),
        ]:
            acl_o = Acl(items=items)
            with self.assertRaises(error, msg=f"{items=} {kwargs=}"):
                acl_o.resequence(**kwargs)

    def test_valid__sort(self):
        """Acl.sort()"""
        for items, req in [
            ([DENY_IP, PERMIT_IP], [DENY_IP, PERMIT_IP]),
            ([PERMIT_IP, DENY_IP], [DENY_IP, PERMIT_IP]),
        ]:
            acl_o = Acl(items=items)
            acl_o.sort()
            result = [str(o) for o in acl_o]
            self.assertEqual(result, req, msg=f"{acl_o=}")

    def test_invalid__delete_sequence(self):
        """Acl.delete_sequence()"""
        acl_o = Acl(items=[REMARK, PERMIT_IP, AceGroup([DENY_IP, REMARK])])
        acl_o.resequence()
        result = sum([o.sequence for o in acl_o])
        self.assertEqual(result, 70, msg="before sorting")

        acl_o.delete_sequence()
        result = sum([o.sequence for o in acl_o])
        self.assertEqual(result, 0, msg="after sorting")


if __name__ == "__main__":
    unittest.main()
