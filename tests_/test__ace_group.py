"""unittest ace_group.py"""

import unittest

from cisco_acl import Ace, AceGroup, Remark
from tests_.helpers_test import (
    DENY_IP,
    DENY_IP_2,
    PERMIT_ADDR_GR,
    PERMIT_IP,
    PERMIT_IP_1,
    PERMIT_IP_2,
    PERMIT_OBJ_GR,
    REMARK,
    REMARK_1,
)


# noinspection DuplicatedCode
class Test(unittest.TestCase):
    """AceGroup"""

    # ========================== redefined ===========================

    def test_valid__lt__sort(self):
        """AceGroup.__lt__(), AceGroup.__le__()"""
        aceg_o = AceGroup([Ace("permit icmp any any"), Ace("deny ip any any")])
        for items in [
            [AceGroup([Ace("deny ip any any"), Ace("permit icmp any any")]), aceg_o],
            [Remark("remark text"), aceg_o],
            [Ace("permit ip any any"), aceg_o],
        ]:
            req = items.copy()
            result = sorted(items)
            self.assertEqual(result, req, msg=f"{items=}")
            items[0], items[1] = items[1], items[0]
            result = sorted(items)
            self.assertEqual(result, req, msg=f"{items=}")

    # =========================== property ===========================

    def test_valid__line_length(self):
        """AceGroup._line_length"""
        for items, req in [
            ([PERMIT_IP], 50),
            ([Ace(PERMIT_IP, line_length=40)], 50),
        ]:
            aceg_o = AceGroup(items=items, line_length=req)
            result = aceg_o[0].line_length
            self.assertLessEqual(result, req, msg=f"acl_length={req}")

    def test_invalid__line_length(self):
        """AceGroup._line_length"""
        for items, error in [
            ([Ace(PERMIT_IP, line_length=100)], ValueError),
        ]:
            with self.assertRaises(error, msg=f"{items=}"):
                AceGroup(items=items, line_length=50)

    def test_valid__items(self):
        """AceGroup.items"""
        aceg_o = AceGroup()
        for items, req, in [
            ([], []),
            ([Ace(PERMIT_IP), Ace(DENY_IP)], [PERMIT_IP, DENY_IP]),
            ([Remark(REMARK), Ace(DENY_IP)], [REMARK, DENY_IP]),
        ]:
            aceg_o.items = items
            result = [str(o) for o in aceg_o]
            self.assertEqual(result, req, msg=f"{items=}")

    def test_invalid__items(self):
        """AceGroup.items"""
        aceg_o = AceGroup()
        for items, error, in [
            (1, TypeError),
            (PERMIT_IP, TypeError),
            ([PERMIT_IP], TypeError),
        ]:
            with self.assertRaises(error, msg=f"{items=}"):
                aceg_o.items = items

    def test_valid__line(self):
        """AceGroup.line"""

        for line, req, in [
            ("\n", ""),
            (PERMIT_IP, PERMIT_IP),
            (f"{PERMIT_IP}\n \n{DENY_IP}\n \n{REMARK}", f"{PERMIT_IP}\n{DENY_IP}\n{REMARK}"),
        ]:
            aceg_o = AceGroup()

            # setter
            aceg_o.line = line
            result = aceg_o.line
            self.assertEqual(result, req, msg=f"setter {line=}")
            result = str(aceg_o)
            self.assertEqual(result, req, msg=f"__str__ {line=}")

            # deleter
            del aceg_o.line
            result = aceg_o.line
            # noinspection PyUnboundLocalVariable
            self.assertEqual(result, "", msg=f"deleter {line=}")

    def test_invalid__line(self):
        """AceGroup.line"""
        aceg_o = AceGroup()
        for line, error, in [
            ("typo", ValueError),
            (f"{PERMIT_IP}\ntypo", ValueError),
        ]:
            with self.assertRaises(error, msg=f"{line=}"):
                aceg_o.line = line

    # =========================== helpers ============================

    def test_valid__convert_any_to_aces(self):
        """AceGroup._convert_any_to_aces()"""
        idx_0_d = dict(idx=0, sidx="")
        idx_1_d = dict(idx=1, sidx="1")
        idx_2_d = dict(idx=2, sidx="2")
        aceg_o_ = AceGroup()
        for items, req, req_d in [
            # str
            (REMARK, [REMARK], idx_0_d),
            (REMARK_1, [REMARK_1], idx_1_d),
            (PERMIT_IP, [PERMIT_IP], idx_0_d),
            (PERMIT_IP_1, [PERMIT_IP_1], idx_1_d),

            # List[str]
            ([], [], idx_0_d),
            ([REMARK, PERMIT_IP], [REMARK, PERMIT_IP], idx_0_d),
            ([REMARK_1, PERMIT_IP_2], [REMARK_1, PERMIT_IP_2], idx_1_d),
            ([PERMIT_IP_2, REMARK_1], [PERMIT_IP_2, REMARK_1], idx_2_d),

            # object
            (Remark(REMARK), [REMARK], idx_0_d),
            (Ace(PERMIT_IP), [PERMIT_IP], idx_0_d),
            (Ace(PERMIT_ADDR_GR, platform="ios"), [PERMIT_OBJ_GR], idx_0_d),

            # List[object]
            ([Remark(REMARK_1), Ace(PERMIT_IP_1)], [REMARK_1, PERMIT_IP_1], idx_1_d),
            ([Ace(PERMIT_IP_1), Ace(DENY_IP_2)], [PERMIT_IP_1, DENY_IP_2], idx_1_d),
            ([Ace(DENY_IP_2), Ace(PERMIT_IP_1)], [DENY_IP_2, PERMIT_IP_1], idx_2_d),
        ]:
            result_items = aceg_o_._convert_any_to_aces(items)
            result = [str(o) for o in result_items]
            self.assertEqual(result, req, msg=f"{items=}")

            aceg_o = AceGroup(items=items)
            for attr, req_ in req_d.items():
                result_ = getattr(aceg_o, attr)
                self.assertEqual(result_, req_, msg=f"{aceg_o=} {attr=}")

        # input ios, output cnx
        aceg_o = AceGroup(items=[PERMIT_OBJ_GR], platform="cnx")
        result = [str(o) for o in aceg_o]
        self.assertEqual(result, [PERMIT_ADDR_GR], msg=f"{items=}")

    def test_invalid__convert_any_to_aces(self):
        """AceGroup._convert_any_to_aces()"""
        acl_o = AceGroup()
        for items, error, in [
            ("", ValueError),
            (None, TypeError),
            (1, TypeError),
            ([1], TypeError),
            ([""], ValueError),
            (["typo"], ValueError),
            ([Ace(PERMIT_IP, platform="cnx")], ValueError),
        ]:
            with self.assertRaises(error, msg=f"{items=}"):
                acl_o._convert_any_to_aces(items=items)
            if not items:
                continue
            with self.assertRaises(error, msg=f"{items=}"):
                AceGroup(items=items, platform="ios")

    def test_valid__convert_str_to_ace(self):
        """AceGroup._convert_str_to_ace()"""
        aceg_o = AceGroup()
        for line in [
            REMARK,
            PERMIT_IP,
            DENY_IP,
        ]:
            req = line
            ace_o = aceg_o._convert_str_to_ace(line)
            result = str(ace_o)
            self.assertEqual(result, req, msg=f"{line=}")

    def test_invalid__convert_str_to_ace(self):
        """AceGroup._convert_str_to_ace()"""
        aceg_o = AceGroup()
        for items, error, in [
            ("", ValueError),
            ("typo", ValueError),
        ]:
            with self.assertRaises(error, msg=f"{items=}"):
                aceg_o._convert_str_to_ace(items)

    def test_valid__check_platform(self):
        """AceGroup._check_platform()"""
        for platform, ace_o, req in [
            ("ios", Ace(PERMIT_IP, platform="ios"), True),
            ("cnx", Ace(PERMIT_IP, platform="cnx"), True),
        ]:
            aceg_o = AceGroup(platform=platform)
            result = aceg_o._check_platform(ace_o)
            self.assertEqual(result, req, msg=f"{platform=} {ace_o=}")

    def test_invalid__check_platform(self):
        """AceGroup._check_platform()"""
        for platform, ace_o, error in [
            ("ios", Ace(PERMIT_IP, platform="cnx"), ValueError),
            ("cnx", Ace(PERMIT_IP, platform="ios"), ValueError),
        ]:
            aceg_o = AceGroup(platform=platform)
            with self.assertRaises(error, msg=f"{platform=} {ace_o=}"):
                aceg_o._check_platform(ace_o)

    def test_valid__check_line_length(self):
        """AceGroup._check_line_length()"""
        for line_length, ace_o, req in [
            (50, Ace(PERMIT_IP, line_length=40), True),
        ]:
            aceg_o = AceGroup(line_length=line_length)
            result = aceg_o._check_line_length(ace_o)
            self.assertEqual(result, req, msg=f"{line_length=} {ace_o=}")

    def test_invalid__check_line_length(self):
        """AceGroup._check_line_length()"""
        for line_length, ace_o, error in [
            (40, Ace(PERMIT_IP, line_length=50), ValueError),
        ]:
            aceg_o = AceGroup(line_length=line_length)
            with self.assertRaises(error, msg=f"{line_length=} {ace_o=}"):
                aceg_o._check_line_length(ace_o)


if __name__ == "__main__":
    unittest.main()
