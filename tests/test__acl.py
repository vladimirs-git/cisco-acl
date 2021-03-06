"""Unittest acl.py"""

import unittest

from cisco_acl import Ace, AceGroup, Acl, Remark
from tests.helpers_test import (
    Helpers,
    ACL_NXOS,
    ACL_IOS,
    ACL_NAME_NXOS,
    ACL_NAME_IOS,
    ACL_NAME_RP_NXOS,
    ACL_NAME_RP_IOS,
    ACL_NUM_IOS,
    ACL_RP_NXOS,
    ACL_RP_IOS,
    DENY_IP,
    DENY_IP_1,
    DENY_IP_2,
    ETH1,
    ETH2,
    PERMIT_ICMP,
    PERMIT_IP,
    PERMIT_IP_1,
    PERMIT_IP_2,
    REMARK,
    REMARK_1,
    ACL_NAM_IOS,
)

REMARK_10 = Remark(f"10 {REMARK}")
REMARK_20 = Remark(f"20 {REMARK}")
ACE_10 = Ace(f"10 {PERMIT_IP}")
ACE_20 = Ace(f"20 {PERMIT_IP}")
ACE_GR_10 = AceGroup(f"10 {DENY_IP}\n{PERMIT_IP}")
ACE_GR_20 = AceGroup(f"20 {DENY_IP}\n{PERMIT_IP}")


# noinspection DuplicatedCode
class Test(Helpers):
    """Acl"""

    # ============================= init =============================

    def test_valid__init_items(self):
        """Acl._init_items()"""
        acl_o_ = Acl()
        for items, req in [
            ([Remark(REMARK_1), Ace(PERMIT_IP_1)], [REMARK_1, PERMIT_IP_1]),
            ([Ace(PERMIT_IP_1), Ace(DENY_IP_2)], [PERMIT_IP_1, DENY_IP_2]),
            ([Ace(DENY_IP_2), Ace(PERMIT_IP_1)], [DENY_IP_2, PERMIT_IP_1]),
        ]:
            if items:
                acl_o_._init_items(items=items)
                result = [str(o) for o in acl_o_.items]
                self.assertEqual(result, req, msg=f"{items=}")

            acl_o = Acl(items=items)
            result = [str(o) for o in acl_o.items]
            self.assertEqual(result, req, msg=f"{items=}")

    def test_invalid__init_items(self):
        """Acl._init_items()"""
        acl_o = Acl(platform="ios")
        for items, error, in [
            (1, TypeError),
            ([1], TypeError),
            (REMARK, TypeError),
            ([Ace(PERMIT_IP, platform="nxos")], ValueError),
        ]:
            with self.assertRaises(error, msg=f"{items=}"):
                acl_o._init_items(items=items)
            if not items:
                continue
            with self.assertRaises(error, msg=f"{items=}"):
                Acl(items=items, platform="ios")

    # =========================== property ===========================
    def test_valid__line(self):
        """Acl.line"""
        for kwargs, req_d, in [
            # ios
            (dict(line="\n", platform="ios"), dict(line=f"{ACL_IOS}\n", name="")),
            (dict(line=ACL_IOS, platform="ios"), dict(line=f"{ACL_IOS}\n", name="")),
            (dict(line=ACL_NAME_IOS, platform="ios"), dict(line=f"{ACL_NAME_IOS}\n", name="A")),
            (dict(line=PERMIT_IP, platform="ios"), dict(line=f"{ACL_IOS}\n  {PERMIT_IP}", name="")),
            (dict(line=ACL_RP_IOS, platform="ios"), dict(line=ACL_RP_IOS, name="")),
            (dict(line=ACL_NAME_RP_IOS, platform="ios"), dict(line=ACL_NAME_RP_IOS, name="A")),
            # nxos
            (dict(line="\n", platform="nxos"), dict(line=f"{ACL_NXOS}\n", name="")),
            (dict(line=ACL_NXOS, platform="nxos"), dict(line=f"{ACL_NXOS}\n", name="")),
            (dict(line=ACL_NAME_NXOS, platform="nxos"), dict(line=f"{ACL_NAME_NXOS}\n", name="A")),
            (dict(line=PERMIT_IP, platform="nxos"),
             dict(line=f"{ACL_NXOS}\n  {PERMIT_IP}", name="")),
            (dict(line=ACL_RP_NXOS, platform="nxos"), dict(line=ACL_RP_NXOS, name="")),
            (dict(line=ACL_NAME_RP_NXOS, platform="nxos"), dict(line=ACL_NAME_RP_NXOS, name="A")),
            # input output
            (dict(line=ACL_IOS, input="port1"), dict(line=f"{ACL_IOS}\n", input=["port1"])),
            (dict(line=ACL_IOS, input=["port1"]), dict(line=f"{ACL_IOS}\n", input=["port1"])),
            (dict(line=ACL_IOS, output="port1"), dict(line=f"{ACL_IOS}\n", output=["port1"])),
            (dict(line=ACL_IOS, output=["port1"]), dict(line=f"{ACL_IOS}\n", output=["port1"])),
            # numerically
            (dict(line=ACL_NUM_IOS, platform="ios", numerically=False), dict(line=ACL_NAM_IOS)),
            (dict(line=ACL_NAM_IOS, platform="ios", numerically=True), dict(line=ACL_NUM_IOS)),
        ]:
            # getter
            acl_o = Acl(**kwargs)
            self._test_attrs(obj=acl_o, req_d=req_d, msg=f"getter {kwargs=}")

            # setter
            acl_o.line = kwargs["line"]
            self._test_attrs(obj=acl_o, req_d=req_d, msg=f"getter {kwargs=}")

        # deleter
        acl_o = Acl(ACL_NUM_IOS)
        del acl_o.line
        self._test_attrs(obj=acl_o, req_d=dict(line=f"{ACL_IOS}\n"), msg=f"getter {kwargs=}")

    def test_invalid__line(self):
        """Acl.line"""
        acl_o = Acl()
        for line, error, in [
            (1, TypeError),
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
            ("nxos", "ip access-list NAME"),
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
            ([Remark(REMARK), AceGroup(f"{PERMIT_IP}\n{DENY_IP}")],
             [REMARK, f"{PERMIT_IP}\n{DENY_IP}"]),
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
        # multiple ports in single line
        acl1_ios = "ip access-list extended NAME\n" \
                   "  permit tcp any eq 1 2 any neq 3 4"
        acl2_ios = "ip access-list extended NAME\n" \
                   "  permit tcp any eq 1 any neq 3\n" \
                   "  permit tcp any eq 1 any neq 4\n" \
                   "  permit tcp any eq 2 any neq 3\n" \
                   "  permit tcp any eq 2 any neq 4"
        # one ports in single line
        acl1_nxos = "ip access-list NAME\n" \
                    "  permit tcp any eq 1 any neq 3\n" \
                    "  permit tcp any eq 1 any neq 4\n" \
                    "  permit tcp any eq 2 any neq 3\n" \
                    "  permit tcp any eq 2 any neq 4"
        # combo
        acl3_ios = "ip access-list extended NAME\n" \
                   "  remark text\n" \
                   "  permit ip object-group A object-group B log\n" \
                   "  permit ip host 1.1.1.1 host 2.2.2.2\n" \
                   "  permit ip 1.1.1.0 0.0.0.255 2.2.2.0 0.0.0.255\n" \
                   "  permit udp 1.1.0.0 0.0.3.3 2.2.0.0 0.0.3.3 range 1 3\n" \
                   "  permit tcp any eq 1 2 any neq 3 4\n" \
                   "  permit tcp any gt 65533 any lt 3"
        acl3_nxos = "ip access-list NAME\n" \
                    "  remark text\n" \
                    "  permit ip addrgroup A addrgroup B log\n" \
                    "  permit ip 1.1.1.1/32 2.2.2.2/32\n" \
                    "  permit ip 1.1.1.0/24 2.2.2.0/24\n" \
                    "  permit udp 1.1.0.0 0.0.3.3 2.2.0.0 0.0.3.3 range 1 3\n" \
                    "  permit tcp any eq 1 any neq 3\n" \
                    "  permit tcp any eq 1 any neq 4\n" \
                    "  permit tcp any eq 2 any neq 3\n" \
                    "  permit tcp any eq 2 any neq 4\n" \
                    "  permit tcp any gt 65533 any lt 3"
        for platform, to_platform, line, req in [
            ("ios", "ios", acl1_ios, acl1_ios),
            ("ios", "nxos", acl1_ios, acl1_nxos),
            ("nxos", "ios", acl1_nxos, acl2_ios),
            ("nxos", "nxos", acl1_nxos, acl1_nxos),

            ("ios", "nxos", acl3_ios, acl3_nxos),
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
        acl_o1 = Acl(f"{PERMIT_IP}\n{DENY_IP}", input=[ETH1, ETH2])
        acl_o2 = acl_o1.copy()
        # mix data
        acl_o2.items[0], acl_o2.items[1] = acl_o2.items[1], acl_o2.items[0]
        acl_o2.input[0], acl_o2.input[1] = acl_o2.input[1], acl_o2.input[0]

        for acl_o, req, intf_req in [
            (acl_o1, [PERMIT_IP, DENY_IP], [ETH1, ETH2]),
            (acl_o2, [DENY_IP, PERMIT_IP], [ETH2, ETH1]),
        ]:
            result = [str(o) for o in acl_o]
            self.assertEqual(result, req, msg=f"{acl_o=}")
            result = acl_o.input
            self.assertEqual(result, intf_req, msg=f"{acl_o=}")

    def test_valid__resequence(self):
        """Acl.resequence()"""
        aces_0 = [Ace(PERMIT_IP), Ace(DENY_IP), Remark(REMARK)]
        aces_10_10 = [Ace(f"10 {PERMIT_IP}"), Ace(f"20 {DENY_IP}"), Remark(f"30 {REMARK}")]
        aces_2_3 = [Ace(f"2 {PERMIT_IP}"), Ace(f"5 {DENY_IP}"), Remark(f"8 {REMARK}")]

        group_0 = [Ace(PERMIT_IP), AceGroup(f"{DENY_IP}\n{REMARK}"), Ace(PERMIT_ICMP)]
        group_10_10 = [
            Ace(f"10 {PERMIT_IP}"),
            AceGroup(f"20 {DENY_IP}\n30 {REMARK}"),
            Ace(f"40 {PERMIT_ICMP}"),
        ]

        for items, kwargs, req in [
            (aces_0, {}, aces_10_10),
            (aces_0, dict(start=2, step=3), aces_2_3),
            (aces_10_10, dict(start=0), aces_0),
            (aces_10_10, dict(start=0, step=3), aces_0),
            (group_0, {}, group_10_10),
            (group_10_10, dict(start=0), group_0),
        ]:
            acl_o = Acl(items=items)
            acl_o = acl_o.copy()
            acl_o.resequence(**kwargs)
            result = acl_o.items
            self.assertEqual(result, req, msg=f"{items=} {kwargs=}")

    def test_invalid__resequence(self):
        """Acl.resequence()"""
        line = f"{PERMIT_IP_2}\n{DENY_IP_1}"
        for kwargs, error in [
            (dict(start=4294967296), ValueError),
            (dict(step=0), ValueError),
            (dict(step=4294967296), ValueError),
        ]:
            acl_o = Acl(line)
            with self.assertRaises(error, msg=f"{line=} {kwargs=}"):
                acl_o.resequence(**kwargs)

    def test_valid__sort(self):
        """Acl.sort()"""
        for line, req in [
            (f"{DENY_IP}\n{PERMIT_IP}", [DENY_IP, PERMIT_IP]),
            (f"{PERMIT_IP}\n{DENY_IP}", [DENY_IP, PERMIT_IP]),
        ]:
            acl_o = Acl(line)
            acl_o.sort()
            result = [str(o) for o in acl_o]
            self.assertEqual(result, req, msg=f"{acl_o=}")


if __name__ == "__main__":
    unittest.main()
