"""Unittest wildcard.py"""

import unittest

import dictdiffer  # type: ignore

from cisco_acl import wildcard
from cisco_acl.wildcard import Wildcard
from tests.helpers_test import (
    Helpers,
    IOS_ADDGR,
    IPNET00,
    IPNET00_32,
    IPNET30,
    IPNET32,
    PREFIX00,
    PREFIX00_32,
    PREFIX30,
    PREFIX32,
    UUID,
    UUID_R,
    WILD30,
    WILD_NC3,
    SUBNET00,
    SUBNET30,
    SUBNET32,
    WILD00,
    WILD32,
)

WILD_ANY_D = dict(
    line="0.0.0.0 255.255.255.255",
    max_ncwb=16,
    platform="ios",
    note="",
    ipnet=IPNET00,
    prefix="0.0.0.0",
    wildmask="255.255.255.255",
)
WILD30_D = dict(
    line="10.0.0.0 0.0.0.3",
    max_ncwb=16,
    platform="ios",
    note="",
    ipnet=IPNET30,
    prefix="10.0.0.0",
    wildmask="0.0.0.3",
)
WILD32_D = dict(
    line="10.0.0.1 0.0.0.0",
    max_ncwb=16,
    platform="ios",
    note="",
    ipnet=IPNET32,
    prefix="10.0.0.1",
    wildmask="0.0.0.0",
)
WILD00_32_D = dict(
    line="0.0.0.0 0.0.0.0",
    max_ncwb=16,
    platform="ios",
    note="",
    ipnet=IPNET00_32,
    prefix="0.0.0.0",
    wildmask="0.0.0.0",
)
WILD_NC3_D = dict(
    line="10.0.0.0 0.0.3.3",
    max_ncwb=16,
    platform="ios",
    note="",
    ipnet=None,
    prefix="10.0.0.0",
    wildmask="0.0.3.3",
)


# noinspection DuplicatedCode
class Test(Helpers):
    """Wildcard"""

    def test_valid__init__(self):
        """Wildcard.__init__()"""
        req0 = dict(line="0.0.0.0 0.0.0.0", prefix="0.0.0.0", wildmask="0.0.0.0", max_ncwb=16)
        req1 = dict(line="10.0.0.0 0.0.0.0", prefix="10.0.0.0", wildmask="0.0.0.0", max_ncwb=16)
        req2 = dict(line="0.0.0.0 0.0.0.3", prefix="0.0.0.0", wildmask="0.0.0.3", max_ncwb=16)
        req3 = dict(line="0.0.0.0 0.0.1.3", prefix="0.0.0.0", wildmask="0.0.1.3", max_ncwb=1)
        req4 = dict(line="0.0.0.0 255.255.255.253", prefix='0.0.0.0', wildmask="255.255.255.253",
                    max_ncwb=30)
        req5 = dict(line="0.0.0.2 255.255.255.253", prefix="0.0.0.2", wildmask="255.255.255.253",
                    max_ncwb=30)
        req6 = dict(line="0.0.0.0 255.255.255.255", prefix="0.0.0.0", wildmask="255.255.255.255",
                    max_ncwb=0)
        for kwargs, req_d, in [
            (dict(line="0.0.0.0 0.0.0.0"), req0),
            (dict(line="10.0.0.0 0.0.0.0"), req1),
            (dict(line="0.0.0.0 0.0.0.3"), req2),
            (dict(line="0.0.0.0 0.0.1.3", max_ncwb=1), req3),
            (dict(line="0.0.0.0 255.255.255.253", max_ncwb=30), req4),
            (dict(line="255.255.255.255 255.255.255.253", max_ncwb=30), req5),
            (dict(line="0.0.0.0 255.255.255.255", max_ncwb=0), req6),
            (dict(line="1.1.1.1 255.255.255.255", max_ncwb=0), req6),
            (dict(line="255.255.255.255 255.255.255.255", max_ncwb=0), req6),
        ]:
            obj = Wildcard(**kwargs)
            self._test_attrs(obj=obj, req_d=req_d, msg=f"{kwargs=}")

    def test_invalid__init__(self):
        """Wildcard.__init__()"""
        for kwargs, error, in [
            (dict(line="0.0.0.0 0.0.0.3", max_ncwb=-1), ValueError),
            (dict(line="0.0.0.0 0.0.0.3", max_ncwb=31), ValueError),
        ]:
            with self.assertRaises(error, msg=f"{kwargs=}"):
                Wildcard(**kwargs)

    # =========================== property ===========================

    def test_valid__line(self):
        """Wildcard.line"""
        wild0_0 = "0.0.0.0 0.0.0.0"
        wild0_3 = "0.0.0.0 3.3.3.3"
        wild1_0 = "255.255.255.255 0.0.0.0"
        wild1_3 = "255.255.255.255 3.3.3.3"
        req0_0 = dict(line="0.0.0.0 0.0.0.0", prefix="0.0.0.0", wildmask="0.0.0.0")
        req0_3 = dict(line="0.0.0.0 3.3.3.3", prefix="0.0.0.0", wildmask="3.3.3.3")
        req1_0 = dict(line="255.255.255.255 0.0.0.0", prefix="255.255.255.255", wildmask="0.0.0.0")
        req1_3 = dict(line="252.252.252.252 3.3.3.3", prefix="252.252.252.252", wildmask="3.3.3.3")

        for line, req_d, in [
            (wild0_0, req0_0),
            (wild0_3, req0_3),
            (wild1_0, req1_0),
            (wild1_3, req1_3),
        ]:
            obj = Wildcard(line)
            self._test_attrs(obj=obj, req_d=req_d, msg=f"{line=}")
            # setter
            obj.line = line
            self._test_attrs(obj=obj, req_d=req_d, msg=f"{line=}")

    def test_invalid__line(self):
        """Wildcard.line"""
        for line, error, in [
            ("a", ValueError),
            ("10.0.0.0/24", ValueError),
        ]:
            with self.assertRaises(error, msg=f"{line=}"):
                Wildcard(line)
            # setter
            obj = Wildcard("0.0.0.0 0.0.0.0")
            with self.assertRaises(error, msg=f"{line=}"):
                obj.line = line

    # =========================== classmethod ============================

    def test_valid__fprefix(self):
        """Wildcard.fprefix()"""
        for kwargs, req_d in [
            (dict(prefix=PREFIX00), WILD_ANY_D),
            (dict(prefix=PREFIX30), WILD30_D),
            (dict(prefix=PREFIX32), WILD32_D),
            (dict(prefix=PREFIX00_32), WILD00_32_D),
        ]:
            obj = Wildcard.fprefix(**kwargs)
            result = obj.data()
            diff = list(dictdiffer.diff(first=result, second=req_d))
            self.assertEqual(diff, [], msg=f"{kwargs=}")

    def test_invalid__fprefix(self):
        """Wildcard.fprefix()"""
        for kwargs, error in [
            (dict(prefix=PREFIX30, max_ncwb=31), ValueError),
        ]:
            with self.assertRaises(error, msg=f"{kwargs=}"):
                Wildcard.fprefix(**kwargs)

    def test_valid__fsubnet(self):
        """Wildcard.fsubnet()"""
        for kwargs, req_d in [
            (dict(subnet=SUBNET00), WILD_ANY_D),
            (dict(subnet=SUBNET30), WILD30_D),
            (dict(subnet=SUBNET32), WILD32_D),
            (dict(subnet=WILD00), WILD00_32_D),
            (dict(subnet=WILD32), WILD_ANY_D),
        ]:
            obj = Wildcard.fsubnet(**kwargs)
            result = obj.data()
            diff = list(dictdiffer.diff(first=result, second=req_d))
            self.assertEqual(diff, [], msg=f"{kwargs=}")

    def test_invalid__fsubnet(self):
        """Wildcard.fsubnet()"""
        for kwargs, error in [
            (dict(subnet=PREFIX30, max_ncwb=31), ValueError),
            (dict(subnet=WILD30), ValueError),
            (dict(subnet=WILD_NC3), ValueError),
            (dict(subnet=PREFIX30), ValueError),
            (dict(subnet=IOS_ADDGR), ValueError),
        ]:
            with self.assertRaises(error, msg=f"{kwargs=}"):
                Wildcard.fsubnet(**kwargs)

    # =========================== methods ============================

    def test_valid__data(self):
        """Wildcard.data()"""
        kwargs1 = dict(line="10.0.0.0 0.0.3.3")
        for kwargs, req_d, req_uuid in [
            (kwargs1, WILD_NC3_D, UUID_R),
        ]:
            obj = Wildcard(**kwargs)
            obj.uuid = UUID

            result = obj.data()
            diff = list(dictdiffer.diff(first=result, second=req_d))
            self.assertEqual(diff, [], msg=f"{kwargs=}")

            result = obj.data(uuid=True)
            diff = list(dictdiffer.diff(first=result, second=req_d))
            self.assertEqual(diff, req_uuid, msg=f"{kwargs=}")

    def test_valid__ipnets(self):
        """Wildcard.ipnets()"""
        wild0 = "0.0.0.0 0.0.0.0"
        wild1 = "0.0.0.0 1.1.1.3"
        wild2 = "0.0.0.0 1.1.3.255"
        wild10_0 = "10.0.0.0 0.0.0.0"
        for line, req, in [
            (wild0, ["0.0.0.0/32"]),
            (wild10_0, ["10.0.0.0/32"]),
            (wild1, ["0.0.0.0/30", "0.0.1.0/30", "0.1.0.0/30", "0.1.1.0/30",
                     "1.0.0.0/30", "1.0.1.0/30", "1.1.0.0/30", "1.1.1.0/30"]),
            (wild2, ["0.0.0.0/22", "0.1.0.0/22", "1.0.0.0/22", "1.1.0.0/22"]),
        ]:
            obj = Wildcard(line)
            ipnets = obj.ipnets()
            result = [str(o) for o in ipnets]
            self.assertEqual(result, req, msg=f"{line=}")

    # =========================== functions ============================

    def test_valid__invert_mask(self):
        """wildcard.invert_mask()"""
        for subnet, req in [
            ("255.0.0.0", "0.255.255.255"),
            ("0.0.3.3", "255.255.252.252"),
        ]:
            result = wildcard.invert_mask(subnet)
            self.assertEqual(result, req, msg=f"{subnet=}")

    def test_invalid__invert_mask(self):
        """wildcard.invert_mask()"""
        for subnet, error in [
            (1, AttributeError),
            ("", ValueError),
            ("10.0.0.0 255.0.0.0", ValueError),
            ("10.0.0.0/24", ValueError),
        ]:
            with self.assertRaises(error, msg=f"{subnet=}"):
                wildcard.invert_mask(subnet)

    def test_valid__is_contiguous_wildmask(self):
        """wildcard.is_contiguous_wildmask()"""
        for line, req in [
            # ("0.0.0.0", True),
            ("0.0.0.1", True),
            ("0.0.0.2", False),
            ("0.0.0.3", True),
            ("0.0.1.0", False),
            ("0.0.1.255", True),
            ("0.0.2.255", False),
            ("0.0.3.255", True),
            ("127.255.255.255", True),
            ("255.255.255.252", False),
            ("255.255.255.255", True),
        ]:
            result = wildcard.is_contiguous_wildmask(line)
            self.assertEqual(result, req, msg=f"{line=}")

    def test_invalid__is_contiguous_wildmask(self):
        """wildcard.is_contiguous_wildmask()"""
        for line, error in [
            ("typo", ValueError),
            ("0.0.0", ValueError),
            ("0.0.0.0.0", ValueError),
            ("0.0.0.0 0.0.0.0", ValueError),
        ]:
            with self.assertRaises(error, msg=f"{line=}"):
                wildcard.is_contiguous_wildmask(line)

    def test_valid__is_mask(self):
        """wildcard.is_mask()"""
        for line, req in [
            ("255.255.255.255", True),
            ("255.255.255.254", True),
            ("255.255.255.253", False),
            ("255.255.255.252", True),
            ("128.0.0.1", False),
            ("128.0.0.0", True),
            ("127.0.0.0", False),
            ("0.0.0.2", False),
            ("0.0.0.1", False),
            ("0.0.0.0", True),
        ]:
            result = wildcard.is_mask(line)
            self.assertEqual(result, req, msg=f"{line=}")


if __name__ == "__main__":
    unittest.main()
