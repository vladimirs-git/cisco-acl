"""Unittest ace_group.py"""

import unittest

import dictdiffer  # type: ignore

from cisco_acl import Ace, AceGroup, Remark
from tests.helpers_test import (
    DENY_IP,
    DENY_IP_2,
    Helpers,
    PERMIT_IP,
    PERMIT_IP_1,
    PERMIT_IP_2,
    REMARK,
)


# noinspection DuplicatedCode
class Test(Helpers):
    """AceGroup"""

    # ========================== redefined ===========================

    def test_valid__hash__(self):
        """AceGroup.__hash__()"""
        line = f"{PERMIT_IP}\n{DENY_IP}"
        aceg_o = AceGroup(line)
        result = aceg_o.__hash__()
        req = line.__hash__()
        self.assertEqual(result, req, msg=f"{line=}")

    def test_valid__eq__(self):
        """AceGroup.__eq__() __ne__()"""
        line = f"{PERMIT_IP}\n{DENY_IP}"
        aceg_o = AceGroup(line)
        for other_o, req, in [
            (AceGroup(line), True),
            (AceGroup(f"{PERMIT_IP_1}\n{DENY_IP}"), False),
            (AceGroup(PERMIT_IP), False),
            (Remark(REMARK), False),
            (line, False),
        ]:
            result = aceg_o.__eq__(other_o)
            self.assertEqual(result, req, msg=f"{aceg_o=} {other_o=}")
            result = aceg_o.__ne__(other_o)
            self.assertEqual(result, not req, msg=f"{aceg_o=} {other_o=}")

    def test_valid__lt__sort(self):
        """AceGroup.__lt__(), AceGroup.__le__()"""
        line = f"{PERMIT_IP}\n{DENY_IP}"
        aceg_o = AceGroup(line)
        for items in [
            [AceGroup(line), aceg_o],
            [AceGroup(f"{DENY_IP}\n{PERMIT_IP}"), aceg_o],
            [aceg_o, AceGroup(f"{PERMIT_IP_1}\n{PERMIT_IP}")],
            [Remark("remark text"), aceg_o],
            [Ace("permit ip any any"), aceg_o],
            [line, aceg_o],
        ]:
            req = items.copy()
            result = sorted(items)
            self.assertEqual(result, req, msg=f"{items=}")
            items[0], items[1] = items[1], items[0]
            result = sorted(items)
            self.assertEqual(result, req, msg=f"{items=}")

    # =========================== property ===========================

    def test_valid__items(self):
        """AceGroup.items"""
        aceg_o = AceGroup()
        for items, req, in [
            ([], []),
            ([Ace(PERMIT_IP), Ace(DENY_IP)], [PERMIT_IP, DENY_IP]),
            ([Remark(REMARK), Ace(DENY_IP)], [REMARK, DENY_IP]),
        ]:
            # setter
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
        acl1 = f"{PERMIT_IP}\n \n{DENY_IP}\n \n{REMARK}"
        acl1_name = f"ip access-list NAME\n{acl1}"
        acl2 = f"2 {acl1}"
        group1 = f"{PERMIT_IP}\n{DENY_IP}\n{REMARK}"
        group2 = f"2 {group1}"

        for line, req_d, in [
            ("", dict(line="", sequence="")),
            ("typo", dict(line="", sequence="")),
            (PERMIT_IP, dict(line=PERMIT_IP, sequence="")),
            (PERMIT_IP_1, dict(line=PERMIT_IP_1, sequence="1")),
            (acl1, dict(line=group1, sequence="")),
            (acl1_name, dict(line=group1, sequence="")),
            (acl2, dict(line=group2, sequence="2")),
        ]:
            # getter
            aceg_o = AceGroup(line)
            self._test_attrs(obj=aceg_o, req_d=req_d, msg=f"getter {line=}")

            # setter
            aceg_o.line = line
            self._test_attrs(obj=aceg_o, req_d=req_d, msg=f"setter {line=}")

        # deleter
        aceg_o = AceGroup(PERMIT_IP)
        del aceg_o.line
        self._test_attrs(obj=aceg_o, req_d=dict(line="", sequence=""), msg="deleter line")

    # =========================== methods ============================

    def test_valid__data(self):
        """AceGroup.data()"""
        acl1 = f"{PERMIT_IP}\n \n{DENY_IP}\n \n{REMARK}"
        acl2 = f"2 {acl1}"
        items1 = [PERMIT_IP, DENY_IP, REMARK]
        items2 = [PERMIT_IP_2, DENY_IP, REMARK]
        data0 = dict(platform="ios", note="", sequence=0, items=[""])
        data1 = dict(platform="ios", note="", sequence=0, items=[PERMIT_IP])
        data_ip1 = dict(platform="ios", note="", sequence=1, items=[PERMIT_IP_1])
        data_gr1 = dict(platform="ios", note="", sequence=0, items=items1)
        data_gr2 = dict(platform="ios", note="", sequence=2, items=items2)

        for line, req_d, in [
            ("", data0),
            (PERMIT_IP, data1),
            (PERMIT_IP_1, data_ip1),
            (acl1, data_gr1),
            (acl2, data_gr2),
        ]:
            for aceg_o in [
                AceGroup(line),
                AceGroup(data=req_d),
            ]:
                result = aceg_o.data()
                diff = list(dictdiffer.diff(first=result, second=req_d))
                self.assertEqual(diff, [], msg=f"{line=}")

    # =========================== helpers ============================

    def test_valid__convert_any_to_aces(self):
        """AceGroup._convert_any_to_aces()"""
        items0 = [Remark(REMARK), Ace(PERMIT_IP_1)]
        items1 = [Ace(PERMIT_IP_1), Ace(DENY_IP_2)]
        items2 = [Ace(DENY_IP_2), Ace(PERMIT_IP_1)]
        for items, req_d in [
            (items0, dict(line=f"{REMARK}\n{PERMIT_IP_1}", sequence="")),
            (items1, dict(line=f"{PERMIT_IP_1}\n{DENY_IP_2}", sequence="1")),
            (items2, dict(line=f"{DENY_IP_2}\n{PERMIT_IP_1}", sequence="2")),
        ]:
            # getter
            aceg_o = AceGroup(items=items)
            self._test_attrs(obj=aceg_o, req_d=req_d, msg=f"getter {items=}")

            # setter
            aceg_o.items = items
            self._test_attrs(obj=aceg_o, req_d=req_d, msg=f"setter {items=}")

        # deleter
        aceg_o = AceGroup(items=[Remark(REMARK)])
        del aceg_o.items
        self._test_attrs(obj=aceg_o, req_d=dict(line="", sequence=""), msg="deleter items")

    def test_invalid__init_items(self):
        """AceGroup._init_items()"""
        acl_o = AceGroup()
        for items, error, in [
            (1, TypeError),
            ([1], TypeError),
            ([""], TypeError),
            ([REMARK], TypeError),
            (Remark(REMARK), TypeError),
        ]:
            with self.assertRaises(error, msg=f"{items=}"):
                acl_o._init_items(items=items)
            if not items:
                continue
            with self.assertRaises(error, msg=f"{items=}"):
                AceGroup(items=items)

    def test_valid__line_to_ace(self):
        """AceGroup._line_to_ace()"""
        aceg_o = AceGroup()
        for line, req in [
            (REMARK, Remark(REMARK)),
            (PERMIT_IP, Ace(PERMIT_IP)),
            (DENY_IP, Ace(DENY_IP)),
            ("", None),
            ("typo", None),
        ]:
            result = aceg_o._line_to_ace(line)
            self.assertEqual(result, req, msg=f"{line=}")

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


if __name__ == "__main__":
    unittest.main()
