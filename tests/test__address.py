"""Unittest address.py"""

import unittest
from ipaddress import IPv4Network
from logging import WARNING

import dictdiffer  # type: ignore

from cisco_acl import Address
from tests.helpers_test import (
    ANY,
    ANY_D,
    CNX_ADDGR,
    CNX_ADDGR_D,
    HOST,
    HOST_0_D,
    HOST_D,
    Helpers,
    IOS_ADDGR,
    IOS_ADDGR_D,
    PREFIX00,
    PREFIX00_32_D,
    PREFIX00_D,
    PREFIX24,
    PREFIX30,
    PREFIX30_D,
    PREFIX32,
    PREFIX32_D,
    SUBNET00,
    SUBNET30,
    SUBNET32,
    WILD00,
    WILD00_32_D,
    WILD30,
    WILD30_D,
    WILD32,
    WILD32_D,
    WILD_252,
    WILD_252_D,
    WILD_33_D,
    WILD_3_3,
    WILD_ANY_D,
)


# noinspection DuplicatedCode
class Test(Helpers):
    """Address"""

    # =========================== property ===========================

    def test_valid__items(self):
        """Address.items"""
        kw_str = dict(line=IOS_ADDGR, platform="ios", items=WILD30)
        kw_str_l = dict(line=IOS_ADDGR, platform="ios", items=[WILD30])
        kw_dict = dict(line=IOS_ADDGR, platform="ios", items=dict(line=WILD30))
        kw_dict_l = dict(line=IOS_ADDGR, platform="ios", items=[dict(line=WILD30)])
        kw_obj = dict(line=IOS_ADDGR, platform="ios", items=Address(WILD30))
        kw_obj2 = dict(line=IOS_ADDGR, platform="ios", items=Address(PREFIX30, platform="nxos"))
        kw_obj_l = dict(line=IOS_ADDGR, platform="ios", items=[Address(WILD30)])
        kw_obj2_l = dict(line=IOS_ADDGR, platform="ios", items=[Address(PREFIX30, platform="nxos")])
        req1 = dict(line="object-group NAME",
                    platform="ios",
                    items=[Address(WILD30)],
                    note="",
                    addrgroup="NAME",
                    ipnet=None,
                    prefix="",
                    subnet="",
                    wildcard="")
        addr1 = dict(line="10.0.0.0 0.0.0.3",
                     platform="ios",
                     items=[],
                     note="",
                     addrgroup="",
                     ipnet=IPv4Network("10.0.0.0/30"),
                     prefix="10.0.0.0/30",
                     subnet="10.0.0.0 255.255.255.252",
                     wildcard="10.0.0.0 0.0.0.3")
        for kwargs, req_d, req_addr_d in [
            (kw_str, req1, addr1),
            (kw_str_l, req1, addr1),
            (kw_dict, req1, addr1),
            (kw_dict_l, req1, addr1),
            (kw_obj, req1, addr1),
            (kw_obj2, req1, addr1),
            (kw_obj_l, req1, addr1),
            (kw_obj2_l, req1, addr1),
        ]:
            obj = Address(**kwargs)
            self._test_attrs(obj=obj, req_d=req_d, msg=f"{kwargs=}")
            addr_o = obj.items[0]
            self._test_attrs(obj=addr_o, req_d=req_addr_d, msg=f"{kwargs=}")

    def test_valid__line(self):
        """Address.line Address.platform"""
        for platform, line, req_d in [
            # ios
            ("ios", PREFIX00, WILD_ANY_D),
            ("ios", PREFIX30, WILD30_D),
            ("ios", PREFIX32, WILD32_D),
            ("ios", SUBNET00, WILD00_32_D),
            ("ios", SUBNET30, WILD_252_D),
            ("ios", SUBNET32, WILD_ANY_D),
            ("ios", WILD00, WILD_ANY_D),
            ("ios", WILD30, WILD30_D),
            ("ios", WILD32, WILD32_D),
            ("ios", WILD_3_3, WILD_33_D),
            ("ios", WILD_252, WILD_252_D),
            ("ios", ANY, ANY_D),
            ("ios", HOST, HOST_D),
            ("ios", IOS_ADDGR, IOS_ADDGR_D),
            # nxos
            ("nxos", PREFIX00, PREFIX00_D),
            ("nxos", PREFIX30, PREFIX30_D),
            ("nxos", PREFIX32, PREFIX32_D),
            ("nxos", SUBNET00, WILD00_32_D),
            ("nxos", SUBNET30, WILD_252_D),
            ("nxos", SUBNET32, WILD_ANY_D),
            ("nxos", WILD00, WILD_ANY_D),
            ("nxos", WILD30, WILD30_D),
            ("nxos", WILD32, WILD32_D),
            ("nxos", WILD_3_3, WILD_33_D),
            ("nxos", WILD_252, WILD_252_D),
            ("nxos", ANY, ANY_D),
            ("nxos", HOST, HOST_D),
            ("nxos", CNX_ADDGR, CNX_ADDGR_D),
        ]:
            obj = Address(line=line, platform=platform)
            self._test_attrs(obj=obj, req_d=req_d, msg=f"{line=} {platform=}")
            # setter
            obj = Address(line="any", platform=platform)
            obj.line = line
            self._test_attrs(obj=obj, req_d=req_d, msg=f"{line=} {platform=}")

    def test_valid__line__change_invalid_mask(self):
        """Address.line Address.platform change invalid mask"""
        for line, req_d, req_log in [
            ("10.0.0.1/30", PREFIX30_D, [WARNING]),
            ("10.0.0.0/0", PREFIX00_D, [WARNING]),
        ]:
            with self.assertLogs() as logs:
                obj = Address(line, platform="nxos")
                self._test_attrs(obj=obj, req_d=req_d, msg=f"{line=}")
                result_log = [o.levelno for o in logs.records]
                self.assertEqual(result_log, req_log, msg=f"{line=}")

            # setter
            obj = Address("any", platform="nxos")
            with self.assertLogs() as logs:
                obj.line = line
                self._test_attrs(obj=obj, req_d=req_d, msg=f"{line=}")
                result_log = [o.levelno for o in logs.records]
                self.assertEqual(result_log, req_log, msg=f"{line=}")

    def test_invalid__line(self):
        """Address.line"""
        for kwargs, error in [
            (dict(line="10.0.0.0", platform="nxos"), ValueError),
            (dict(line="10.0.0.0/24/24", platform="nxos"), ValueError),
            (dict(line="10.0.0.0/33", platform="nxos"), ValueError),
            (dict(line=IOS_ADDGR, platform="nxos"), ValueError),
            (dict(line=CNX_ADDGR, platform="ios"), ValueError),
            (dict(line="", platform="ios"), ValueError),
            (dict(line="typo", platform="ios"), ValueError),
            (dict(line=1, platform="ios"), TypeError),
            (dict(line=[ANY], platform="ios"), TypeError),
        ]:
            with self.assertRaises(error, msg=f"{kwargs=}"):
                Address(**kwargs)

    def test_valid__platform(self):
        """Address.platform"""
        for platform, line, req_d, platform_new, req_new_d in [
            # ios to ios
            ("ios", PREFIX00, WILD_ANY_D, "ios", ANY_D),
            ("ios", PREFIX30, WILD30_D, "ios", WILD30_D),
            ("ios", PREFIX32, WILD32_D, "ios", HOST_D),
            ("ios", SUBNET00, WILD00_32_D, "ios", HOST_0_D),
            ("ios", SUBNET30, WILD_252_D, "ios", WILD_252_D),
            ("ios", SUBNET32, WILD_ANY_D, "ios", ANY_D),
            ("ios", WILD00, WILD_ANY_D, "ios", ANY_D),
            ("ios", WILD30, WILD30_D, "ios", WILD30_D),
            ("ios", WILD32, WILD32_D, "ios", HOST_D),
            ("ios", WILD_3_3, WILD_33_D, "ios", WILD_33_D),
            ("ios", WILD_252, WILD_252_D, "ios", WILD_252_D),
            ("ios", ANY, ANY_D, "ios", ANY_D),
            ("ios", HOST, HOST_D, "ios", HOST_D),
            ("ios", IOS_ADDGR, IOS_ADDGR_D, "ios", IOS_ADDGR_D),
            # ios to nxos
            ("ios", PREFIX00, WILD_ANY_D, "nxos", ANY_D),
            ("ios", PREFIX30, WILD30_D, "nxos", PREFIX30_D),
            ("ios", PREFIX32, WILD32_D, "nxos", PREFIX32_D),
            ("ios", SUBNET00, WILD00_32_D, "nxos", PREFIX00_32_D),
            ("ios", SUBNET30, WILD_252_D, "nxos", WILD_252_D),
            ("ios", SUBNET32, WILD_ANY_D, "nxos", ANY_D),
            ("ios", WILD00, WILD_ANY_D, "nxos", ANY_D),
            ("ios", WILD30, WILD30_D, "nxos", PREFIX30_D),
            ("ios", WILD32, WILD32_D, "nxos", PREFIX32_D),
            ("ios", WILD_3_3, WILD_33_D, "nxos", WILD_33_D),
            ("ios", WILD_252, WILD_252_D, "nxos", WILD_252_D),
            ("ios", ANY, ANY_D, "nxos", ANY_D),
            ("ios", HOST, HOST_D, "nxos", PREFIX32_D),
            ("ios", IOS_ADDGR, IOS_ADDGR_D, "nxos", CNX_ADDGR_D),
            # nxos to nxos
            ("nxos", PREFIX00, PREFIX00_D, "nxos", ANY_D),
            ("nxos", PREFIX30, PREFIX30_D, "nxos", PREFIX30_D),
            ("nxos", PREFIX32, PREFIX32_D, "nxos", PREFIX32_D),
            ("nxos", SUBNET00, WILD00_32_D, "nxos", PREFIX00_32_D),
            ("nxos", SUBNET30, WILD_252_D, "nxos", WILD_252_D),
            ("nxos", SUBNET32, WILD_ANY_D, "nxos", ANY_D),
            ("nxos", WILD00, WILD_ANY_D, "nxos", ANY_D),
            ("nxos", WILD30, WILD30_D, "nxos", PREFIX30_D),
            ("nxos", WILD32, WILD32_D, "nxos", PREFIX32_D),
            ("nxos", WILD_3_3, WILD_33_D, "nxos", WILD_33_D),
            ("nxos", WILD_252, WILD_252_D, "nxos", WILD_252_D),
            ("nxos", ANY, ANY_D, "nxos", ANY_D),
            ("nxos", HOST, HOST_D, "nxos", PREFIX32_D),
            ("nxos", CNX_ADDGR, CNX_ADDGR_D, "nxos", CNX_ADDGR_D),
            # nxos to ios
            ("nxos", PREFIX00, PREFIX00_D, "ios", ANY_D),
            ("nxos", PREFIX30, PREFIX30_D, "ios", WILD30_D),
            ("nxos", PREFIX32, PREFIX32_D, "ios", HOST_D),
            ("nxos", SUBNET00, WILD00_32_D, "ios", HOST_0_D),
            ("nxos", SUBNET30, WILD_252_D, "ios", WILD_252_D),
            ("nxos", SUBNET32, WILD_ANY_D, "ios", ANY_D),
            ("nxos", WILD00, WILD_ANY_D, "ios", ANY_D),
            ("nxos", WILD30, WILD30_D, "ios", WILD30_D),
            ("nxos", WILD32, WILD32_D, "ios", HOST_D),
            ("nxos", WILD_3_3, WILD_33_D, "ios", WILD_33_D),
            ("nxos", WILD_252, WILD_252_D, "ios", WILD_252_D),
            ("nxos", ANY, ANY_D, "ios", ANY_D),
            ("nxos", HOST, HOST_D, "ios", HOST_D),
            ("nxos", CNX_ADDGR, CNX_ADDGR_D, "ios", IOS_ADDGR_D),
        ]:
            obj = Address(line=line, platform=platform)
            self._test_attrs(obj=obj, req_d=req_d, msg=f"{line=} {platform=}")

            obj.platform = platform_new
            self._test_attrs(obj=obj, req_d=req_new_d, msg=f"{line=} {platform=}")

    # =========================== methods ============================

    def test_valid__copy(self):
        """AddrGroup.copy()"""
        # address group
        obj1 = Address(line=IOS_ADDGR, platform="ios", items=[SUBNET30], note="a")
        obj2 = obj1.copy()

        # change obj1 to check obj1 does not depend on obj2
        new_obj1_kwargs = dict(_addrgroup="NAME2", items=[PREFIX24], note="b", platform="nxos")
        for arg, value in new_obj1_kwargs.items():
            setattr(obj1, arg, value)

        req1_d = dict(line="addrgroup NAME2",
                      platform="nxos",
                      addrgroup="NAME2",
                      items=[Address(line=PREFIX24, platform="nxos")],
                      note="b")
        req2_d = dict(line="object-group NAME",
                      platform="ios",
                      addrgroup="NAME",
                      items=[Address(line=SUBNET30, platform="ios")],
                      note="a")
        self._test_attrs(obj1, req1_d, msg="obj1 does not depend on obj2")
        self._test_attrs(obj2, req2_d, msg="obj2 copied from obj1")

        # prefix
        obj1 = Address(line=PREFIX30, platform="nxos", note="a")
        obj2 = obj1.copy()

        # change obj1 to check obj1 does not depend on obj2
        new_obj1_kwargs = dict(line=HOST, note="b", platform="ios")
        for arg, value in new_obj1_kwargs.items():
            setattr(obj1, arg, value)

        req1_d = dict(line="host 10.0.0.1",
                      platform="ios",
                      addrgroup="",
                      items=[],
                      note="b")
        req2_d = dict(line="10.0.0.0/30",
                      platform="nxos",
                      addrgroup="",
                      items=[],
                      note="a")
        self._test_attrs(obj1, req1_d, msg="obj1 does not depend on obj2")
        self._test_attrs(obj2, req2_d, msg="obj2 copied from obj1")

    def test_valid__data(self):
        """Address.data()"""
        kwargs1 = dict(line=IOS_ADDGR, platform="ios", items=[WILD30])
        req1 = dict(line="object-group NAME",
                    platform="ios",
                    items=[
                        dict(line="10.0.0.0 0.0.0.3",
                             platform="ios",
                             items=[],
                             note="",
                             type="wildcard",
                             addrgroup="",
                             ipnet=IPv4Network("10.0.0.0/30"),
                             prefix="10.0.0.0/30",
                             subnet="10.0.0.0 255.255.255.252",
                             wildcard="10.0.0.0 0.0.0.3"),
                    ],
                    note="",
                    type="addrgroup",
                    addrgroup="NAME",
                    ipnet=None,
                    prefix="",
                    subnet="",
                    wildcard="")

        kwargs2 = dict(line=PREFIX30, platform="nxos")
        req2 = dict(line="10.0.0.0/30",
                    platform="nxos",
                    items=[],
                    note="",
                    type="prefix",
                    addrgroup="",
                    ipnet=IPv4Network("10.0.0.0/30"),
                    prefix="10.0.0.0/30",
                    subnet="10.0.0.0 255.255.255.252",
                    wildcard="10.0.0.0 0.0.0.3")

        for kwargs, req_d in [
            (kwargs1, req1),
            (kwargs2, req2),
        ]:
            obj = Address(**kwargs)
            result = obj.data()
            diff = list(dictdiffer.diff(first=result, second=req_d))
            self.assertEqual(diff, [], msg=f"{kwargs=}")

    def test_valid__ipnets(self):
        """Address.ipnets()"""
        for kwargs, req in [
            (dict(line=WILD30), [PREFIX30]),
            (dict(line=IOS_ADDGR, items=[WILD32]), [PREFIX32]),
        ]:
            obj = Address(platform="ios", **kwargs)
            ipnets = obj.ipnets()
            result = [str(o) for o in ipnets]
            self.assertEqual(result, req, msg=f"{kwargs=}")

    def test_valid__prefixes(self):
        """Address.prefixes()"""
        for kwargs, req in [
            (dict(line=WILD30), [PREFIX30]),
            (dict(line=IOS_ADDGR, items=[WILD32]), [PREFIX32]),
        ]:
            obj = Address(platform="ios", **kwargs)
            result = obj.prefixes()
            self.assertEqual(result, req, msg=f"{kwargs=}")

    def test_valid__subnets(self):
        """Address.subnets()"""
        for kwargs, req in [
            (dict(line=WILD30), [SUBNET30]),
            (dict(line=IOS_ADDGR, items=[WILD32]), [SUBNET32]),
        ]:
            obj = Address(platform="ios", **kwargs)
            result = obj.subnets()
            self.assertEqual(result, req, msg=f"{kwargs=}")

    def test_valid__wildcards(self):
        """Address.wildcards()"""
        for kwargs, req in [
            (dict(line=WILD30), [WILD30]),
            (dict(line=IOS_ADDGR, items=[WILD32]), [WILD32]),
        ]:
            obj = Address(platform="ios", **kwargs)
            result = obj.wildcards()
            self.assertEqual(result, req, msg=f"{kwargs=}")


if __name__ == "__main__":
    unittest.main()
