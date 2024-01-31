"""Unittest address.py"""

import unittest
from ipaddress import IPv4Network, NetmaskValueError
from logging import WARNING

import dictdiffer  # type: ignore

from cisco_acl import Address, AddressAg, address
from tests.helpers_test import (
    ANY,
    ANY_D,
    CNX_ADDGR,
    CNX_ADDGR_D,
    HOST,
    HOST_,
    HOST_0_D,
    HOST_D,
    Helpers,
    IOS_ADDGR,
    IOS_ADDGR_D,
    PREFIX00,
    PREFIX24,
    PREFIX30,
    PREFIX30_D,
    PREFIX32,
    SUBNET00,
    SUBNET30,
    SUBNET32,
    UUID,
    UUID_R,
    UUID_R2,
    WILD00,
    WILD30,
    WILD30_D,
    WILD32,
    WILD_NC252,
    WILD_NC252_D,
    WILD_NC3_D,
    WILD_NC3,
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
            ("ios", PREFIX32, HOST_D),
            ("ios", SUBNET00, HOST_0_D),
            ("ios", SUBNET30, NetmaskValueError),
            ("ios", SUBNET32, ANY_D),
            ("ios", WILD00, ANY_D),
            ("ios", WILD30, WILD30_D),
            ("ios", WILD32, HOST_D),
            ("ios", WILD_NC3, WILD_NC3_D),
            ("ios", WILD_NC252, NetmaskValueError),
            ("ios", ANY, ANY_D),
            ("ios", HOST, HOST_D),
            ("ios", HOST_, HOST_D),
            ("ios", IOS_ADDGR, IOS_ADDGR_D),
            # nxos
            ("nxos", PREFIX00, ANY_D),
            ("nxos", PREFIX30, PREFIX30_D),
            ("nxos", PREFIX32, HOST_D),
            ("nxos", SUBNET00, HOST_0_D),
            ("nxos", SUBNET30, NetmaskValueError),
            ("nxos", SUBNET32, ANY_D),
            ("nxos", WILD00, ANY_D),
            ("nxos", WILD30, PREFIX30_D),
            ("nxos", WILD32, HOST_D),
            ("nxos", WILD_NC3, WILD_NC3_D),
            ("nxos", WILD_NC252, NetmaskValueError),
            ("nxos", ANY, ANY_D),
            ("nxos", HOST, HOST_D),
            ("nxos", CNX_ADDGR, CNX_ADDGR_D),
        ]:
            msg = f"{line=} {platform=}"
            # error
            if not isinstance(req_d, dict):
                error = req_d
                with self.assertRaises(error, msg=msg):
                    Address(line=line, platform=platform)
                continue
            # init
            obj = Address(line=line, platform=platform)
            self._test_attrs(obj=obj, req_d=req_d, msg=msg)
            # setter
            obj = Address(line="any", platform=platform)
            obj.line = line
            self._test_attrs(obj=obj, req_d=req_d, msg=msg)

    def test_valid__line__change_invalid_mask(self):
        """Address.line Address.platform change invalid mask"""
        for line, req_d, req_log in [
            ("10.0.0.1/30", PREFIX30_D, [WARNING]),
            ("10.0.0.0/0", ANY_D, [WARNING]),
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
        for kwargs, req_d, platform_new, req_new_d in [
            # ios to ios
            (dict(platform="ios", line=PREFIX00), WILD_ANY_D, "ios", ANY_D),
            (dict(platform="ios", line=PREFIX30), WILD30_D, "ios", WILD30_D),
            (dict(platform="ios", line=PREFIX32), HOST_D, "ios", HOST_D),
            (dict(platform="ios", line=SUBNET00), HOST_0_D, "ios", HOST_0_D),
            (dict(platform="ios", line=SUBNET30), WILD_NC252_D, "ios", WILD_NC252_D),
            (dict(platform="ios", line=SUBNET32), ANY_D, "ios", ANY_D),
            (dict(platform="ios", line=WILD00), ANY_D, "ios", ANY_D),
            (dict(platform="ios", line=WILD30), WILD30_D, "ios", WILD30_D),
            (dict(platform="ios", line=WILD32), HOST_D, "ios", HOST_D),
            (dict(platform="ios", line=WILD_NC3), WILD_NC3_D, "ios", WILD_NC3_D),
            (dict(platform="ios", line=WILD_NC252), WILD_NC252_D, "ios", WILD_NC252_D),
            (dict(platform="ios", line=ANY), ANY_D, "ios", ANY_D),
            (dict(platform="ios", line=HOST), HOST_D, "ios", HOST_D),
            (dict(platform="ios", line=HOST_), HOST_D, "ios", HOST_D),
            (dict(platform="ios", line=IOS_ADDGR), IOS_ADDGR_D, "ios", IOS_ADDGR_D),
            # ios to nxos
            (dict(platform="ios", line=PREFIX00), WILD_ANY_D, "nxos", ANY_D),
            (dict(platform="ios", line=PREFIX30), WILD30_D, "nxos", PREFIX30_D),
            (dict(platform="ios", line=PREFIX32), HOST_D, "nxos", HOST_D),
            (dict(platform="ios", line=SUBNET00), HOST_0_D, "nxos", HOST_0_D),
            (dict(platform="ios", line=SUBNET30), WILD_NC252_D, "nxos", WILD_NC252_D),
            (dict(platform="ios", line=SUBNET32), ANY_D, "nxos", ANY_D),
            (dict(platform="ios", line=WILD00), ANY_D, "nxos", ANY_D),
            (dict(platform="ios", line=WILD30), WILD30_D, "nxos", PREFIX30_D),
            (dict(platform="ios", line=WILD32), HOST_D, "nxos", HOST_D),
            (dict(platform="ios", line=WILD_NC3), WILD_NC3_D, "nxos", WILD_NC3_D),
            (dict(platform="ios", line=WILD_NC252), WILD_NC252_D, "nxos", WILD_NC252_D),
            (dict(platform="ios", line=ANY), ANY_D, "nxos", ANY_D),
            (dict(platform="ios", line=HOST), HOST_D, "nxos", HOST_D),
            (dict(platform="ios", line=HOST_), HOST_D, "nxos", HOST_D),
            (dict(platform="ios", line=IOS_ADDGR), IOS_ADDGR_D, "nxos", CNX_ADDGR_D),
            # nxos to nxos
            (dict(platform="nxos", line=PREFIX00), ANY_D, "nxos", ANY_D),
            (dict(platform="nxos", line=PREFIX30), PREFIX30_D, "nxos", PREFIX30_D),
            (dict(platform="nxos", line=PREFIX32), HOST_D, "nxos", HOST_D),
            (dict(platform="nxos", line=SUBNET00), HOST_0_D, "nxos", HOST_0_D),
            (dict(platform="nxos", line=SUBNET30), WILD_NC252_D, "nxos", WILD_NC252_D),
            (dict(platform="nxos", line=SUBNET32), ANY_D, "nxos", ANY_D),
            (dict(platform="nxos", line=WILD00), ANY_D, "nxos", ANY_D),
            (dict(platform="nxos", line=WILD30), PREFIX30_D, "nxos", PREFIX30_D),
            (dict(platform="nxos", line=WILD32), HOST_D, "nxos", HOST_D),
            (dict(platform="nxos", line=WILD_NC3), WILD_NC3_D, "nxos", WILD_NC3_D),
            (dict(platform="nxos", line=WILD_NC252), WILD_NC252_D, "nxos", WILD_NC252_D),
            (dict(platform="nxos", line=ANY), ANY_D, "nxos", ANY_D),
            (dict(platform="nxos", line=HOST), HOST_D, "nxos", HOST_D),
            (dict(platform="nxos", line=CNX_ADDGR), CNX_ADDGR_D, "nxos", CNX_ADDGR_D),
            # nxos to ios
            (dict(platform="nxos", line=PREFIX00), ANY_D, "ios", ANY_D),
            (dict(platform="nxos", line=PREFIX30), PREFIX30_D, "ios", WILD30_D),
            (dict(platform="nxos", line=PREFIX32), HOST_D, "ios", HOST_D),
            (dict(platform="nxos", line=SUBNET00), HOST_0_D, "ios", HOST_0_D),
            (dict(platform="nxos", line=SUBNET30), WILD_NC252_D, "ios", WILD_NC252_D),
            (dict(platform="nxos", line=SUBNET32), ANY_D, "ios", ANY_D),
            (dict(platform="nxos", line=WILD00), ANY_D, "ios", ANY_D),
            (dict(platform="nxos", line=WILD30), PREFIX30_D, "ios", WILD30_D),
            (dict(platform="nxos", line=WILD32), HOST_D, "ios", HOST_D),
            (dict(platform="nxos", line=WILD_NC3), WILD_NC3_D, "ios", WILD_NC3_D),
            (dict(platform="nxos", line=WILD_NC252), WILD_NC252_D, "ios", WILD_NC252_D),
            (dict(platform="nxos", line=ANY), ANY_D, "ios", ANY_D),
            (dict(platform="nxos", line=HOST), HOST_D, "ios", HOST_D),
            (dict(platform="nxos", line=CNX_ADDGR), CNX_ADDGR_D, "ios", IOS_ADDGR_D),
        ]:
            msg = f"{kwargs=} {platform_new=}"
            kwargs["max_ncwb"] = 30
            obj = Address(**kwargs)
            self._test_attrs(obj=obj, req_d=req_d, msg=msg)
            # setter
            obj.platform = platform_new
            self._test_attrs(obj=obj, req_d=req_new_d, msg=msg)

    def test_valid__platform__addrgroup_items(self):
        """Address.platform Address with addrgroup items"""
        for platform, line, items, platform_new, req_new in [
            ("ios", IOS_ADDGR, [WILD30], "ios", [WILD30]),
            ("ios", IOS_ADDGR, [WILD30], "nxos", [PREFIX30]),
            ("nxos", CNX_ADDGR, [PREFIX30], "nxos", [PREFIX30]),
            ("nxos", CNX_ADDGR, [PREFIX30], "ios", [WILD30]),
        ]:
            msg = f"{line=} {platform=} {items=} {platform_new=}"
            obj = Address(line=line, platform=platform, items=items)
            obj.items[0].uuid = UUID

            result = [o.line for o in obj.items]
            self.assertEqual(result, items, msg=msg)
            # setter
            obj.platform = platform_new
            result = [o.line for o in obj.items]
            self.assertEqual(result, req_new, msg=msg)
            # uuid
            result = obj.items[0].uuid
            self.assertEqual(result, UUID, msg=msg)

    def test_valid__prefix(self):
        """Address.prefix"""
        for platform, prefix, req_d in [
            # ios
            ("ios", PREFIX00, WILD_ANY_D),
            ("ios", PREFIX30, WILD30_D),
            ("ios", PREFIX32, HOST_D),
            # nxos
            ("nxos", PREFIX00, ANY_D),
            ("nxos", PREFIX30, PREFIX30_D),
            ("nxos", PREFIX32, HOST_D),
        ]:
            obj = Address(line="host 10.0.0.2", platform=platform)
            obj.prefix = prefix
            self._test_attrs(obj=obj, req_d=req_d, msg=f"{prefix=} {platform=}")

    # =========================== method =============================

    def test_valid__copy(self):
        """AddrGroup.copy()"""
        # address group
        obj1 = Address(line=IOS_ADDGR, platform="ios", items=[WILD30], note="a")
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
                      items=[Address(line=WILD30, platform="ios")],
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
                             max_ncwb=16,
                             type="wildcard",
                             addrgroup="",
                             ipnet=IPv4Network("10.0.0.0/30"),
                             prefix="10.0.0.0/30",
                             subnet="10.0.0.0 255.255.255.252",
                             wildcard="10.0.0.0 0.0.0.3"),
                    ],
                    note="",
                    max_ncwb=16,
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
                    max_ncwb=16,
                    type="prefix",
                    addrgroup="",
                    ipnet=IPv4Network("10.0.0.0/30"),
                    prefix="10.0.0.0/30",
                    subnet="10.0.0.0 255.255.255.252",
                    wildcard="10.0.0.0 0.0.0.3")

        for kwargs, req_d, req_uuid in [
            (kwargs1, req1, UUID_R2),
            (kwargs2, req2, UUID_R),
        ]:
            obj = Address(**kwargs)
            obj.uuid = UUID
            for item in obj.items:
                item.uuid = UUID

            result = obj.data()
            diff = list(dictdiffer.diff(first=result, second=req_d))
            self.assertEqual(diff, [], msg=f"{kwargs=}")

            result = obj.data(uuid=True)
            diff = list(dictdiffer.diff(first=result, second=req_d))
            self.assertEqual(diff, req_uuid, msg=f"{kwargs=}")

    def test_valid__ipnets(self):
        """Address.ipnets()"""
        wild_ipnets = ['10.0.0.0/30', '10.0.1.0/30', '10.0.2.0/30', '10.0.3.0/30']
        for kwargs, req in [
            (dict(line=WILD30), [PREFIX30]),
            (dict(line=WILD_NC3), wild_ipnets),
            (dict(line=IOS_ADDGR, items=[WILD32]), [PREFIX32]),
            (dict(line=IOS_ADDGR, items=[WILD_NC3]), wild_ipnets),
        ]:
            obj = Address(**kwargs)
            ipnets = obj.ipnets()
            result = [str(o) for o in ipnets]
            self.assertEqual(result, req, msg=f"{kwargs=}")

    def test_invalid__ipnets(self):
        """Address.ipnets()"""
        addgr = Address(line=IOS_ADDGR, items=[WILD30])
        for kwargs, error in [
            (dict(line=IOS_ADDGR, items=[addgr]), TypeError),  # recursive addrgroup
        ]:
            obj = Address(**kwargs)
            with self.assertRaises(error, msg=f"{kwargs=}"):
                obj.ipnets()

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

    def test_valid__is_subnet(self):
        """Address.is_subnet()"""
        any_ = Address("any", platform="nxos")
        host1 = Address("host 10.0.0.1", platform="nxos")
        pr0_24 = Address("10.0.0.0/24", platform="nxos")
        pr4_30 = Address("10.0.0.4/30", platform="nxos")
        pr8_30 = Address("10.0.0.8/30", platform="nxos")
        pr1_30 = Address("10.0.1.0/30", platform="nxos")
        wild_33 = Address("10.0.0.0 0.0.3.3", platform="nxos")
        ag_empty = Address("addrgroup A", platform="nxos")
        ag0_24 = Address("addrgroup B", platform="nxos", items=[pr0_24])
        ag4_30 = Address("addrgroup C", platform="nxos", items=[pr4_30])
        ag1_30 = Address("addrgroup D", platform="nxos", items=[pr1_30])
        ag4_30_1_10 = Address("addrgroup E", platform="nxos", items=[pr4_30, pr1_30])
        ag4_30_8_30 = Address("addrgroup F", platform="nxos", items=[pr4_30, pr8_30])
        for top, bottom, req in [
            # any
            (any_, any_, True),
            (any_, host1, True),
            (any_, pr0_24, True),
            (any_, pr4_30, True),
            (any_, pr1_30, True),
            (any_, wild_33, True),
            (any_, ag_empty, False),
            (any_, ag0_24, True),
            (any_, ag4_30, True),
            (any_, ag1_30, True),
            (any_, ag4_30_1_10, True),
            (any_, ag4_30_8_30, True),
            # host
            (host1, any_, False),
            (host1, host1, True),
            (host1, pr0_24, False),
            (host1, pr4_30, False),
            (host1, pr1_30, False),
            (host1, wild_33, False),
            (host1, ag_empty, False),
            (host1, ag0_24, False),
            (host1, ag4_30, False),
            (host1, ag1_30, False),
            (host1, ag4_30_1_10, False),
            (host1, ag4_30_8_30, False),
            # 10.0.0.0/24
            (pr0_24, any_, False),
            (pr0_24, host1, True),
            (pr0_24, pr0_24, True),
            (pr0_24, pr4_30, True),
            (pr0_24, pr1_30, False),
            (pr0_24, wild_33, False),
            (pr0_24, ag_empty, False),
            (pr0_24, ag0_24, True),
            (pr0_24, ag4_30, True),
            (pr0_24, ag1_30, False),
            (pr0_24, ag4_30_1_10, False),
            (pr0_24, ag4_30_8_30, True),
            # 10.0.0.4/30
            (pr4_30, any_, False),
            (pr4_30, host1, False),
            (pr4_30, pr0_24, False),
            (pr4_30, pr4_30, True),
            (pr4_30, pr1_30, False),
            (pr4_30, wild_33, False),
            (pr4_30, ag_empty, False),
            (pr4_30, ag0_24, False),
            (pr4_30, ag4_30, True),
            (pr4_30, ag1_30, False),
            (pr4_30, ag4_30_1_10, False),
            (pr4_30, ag4_30_8_30, False),
            # 10.0.1.0/30
            (pr1_30, any_, False),
            (pr1_30, host1, False),
            (pr1_30, pr0_24, False),
            (pr1_30, pr4_30, False),
            (pr1_30, pr1_30, True),
            (pr1_30, wild_33, False),
            (pr1_30, ag_empty, False),
            (pr1_30, ag0_24, False),
            (pr1_30, ag4_30, False),
            (pr1_30, ag1_30, True),
            (pr1_30, ag4_30_1_10, False),
            (pr1_30, ag4_30_8_30, False),
            # non-contiguous wildcard
            (wild_33, any_, False),
            (wild_33, host1, True),
            (wild_33, pr0_24, False),
            (wild_33, pr4_30, False),
            (wild_33, pr1_30, True),
            (wild_33, wild_33, True),
            (wild_33, ag_empty, False),
            (wild_33, ag0_24, False),
            (wild_33, ag4_30, False),
            (wild_33, ag1_30, True),
            (wild_33, ag4_30_1_10, False),
            (wild_33, ag4_30_8_30, False),
            # addrgroup with empty
            (ag_empty, any_, False),
            (ag_empty, host1, False),
            (ag_empty, pr0_24, False),
            (ag_empty, pr4_30, False),
            (ag_empty, pr1_30, False),
            (ag_empty, wild_33, False),
            (ag_empty, ag_empty, False),
            (ag_empty, ag0_24, False),
            (ag_empty, ag4_30, False),
            (ag_empty, ag1_30, False),
            (ag_empty, ag4_30_1_10, False),
            (ag_empty, ag4_30_8_30, False),
            # addrgroup with 10.0.0.0/24
            (ag0_24, any_, False),
            (ag0_24, host1, True),
            (ag0_24, pr0_24, True),
            (ag0_24, pr4_30, True),
            (ag0_24, pr1_30, False),
            (ag0_24, wild_33, False),
            (ag0_24, ag_empty, False),
            (ag0_24, ag0_24, True),
            (ag0_24, ag4_30, True),
            (ag0_24, ag1_30, False),
            (ag0_24, ag4_30_1_10, False),
            (ag0_24, ag4_30_8_30, True),
            # addrgroup with 10.0.0.4/30
            (ag4_30, any_, False),
            (ag4_30, host1, False),
            (ag4_30, pr0_24, False),
            (ag4_30, pr4_30, True),
            (ag4_30, pr1_30, False),
            (ag4_30, wild_33, False),
            (ag4_30, ag_empty, False),
            (ag4_30, ag0_24, False),
            (ag4_30, ag4_30, True),
            (ag4_30, ag1_30, False),
            (ag4_30, ag4_30_1_10, False),
            (ag4_30, ag4_30_8_30, False),
            # addrgroup with 10.0.1.0/30
            (ag1_30, any_, False),
            (ag1_30, host1, False),
            (ag1_30, pr0_24, False),
            (ag1_30, pr4_30, False),
            (ag1_30, pr1_30, True),
            (ag1_30, wild_33, False),
            (ag1_30, ag_empty, False),
            (ag1_30, ag0_24, False),
            (ag1_30, ag4_30, False),
            (ag1_30, ag1_30, True),
            (ag1_30, ag4_30_1_10, False),
            (ag1_30, ag4_30_8_30, False),
            # addrgroup with 10.0.0.4/30, 10.0.1.0/30
            (ag4_30_1_10, any_, False),
            (ag4_30_1_10, host1, False),
            (ag4_30_1_10, pr0_24, False),
            (ag4_30_1_10, pr4_30, True),
            (ag4_30_1_10, pr1_30, True),
            (ag4_30_1_10, wild_33, False),
            (ag4_30_1_10, ag_empty, False),
            (ag4_30_1_10, ag0_24, False),
            (ag4_30_1_10, ag4_30, True),
            (ag4_30_1_10, ag1_30, True),
            (ag4_30_1_10, ag4_30_1_10, True),
            (ag4_30_1_10, ag4_30_8_30, False),
            # addrgroup with 10.0.0.0/30, 10.0.0.4/30
            (ag4_30_8_30, any_, False),
            (ag4_30_8_30, host1, False),
            (ag4_30_8_30, pr0_24, False),
            (ag4_30_8_30, pr4_30, True),
            (ag4_30_8_30, pr1_30, False),
            (ag4_30_8_30, wild_33, False),
            (ag4_30_8_30, ag_empty, False),
            (ag4_30_8_30, ag0_24, False),
            (ag4_30_8_30, ag4_30, True),
            (ag4_30_8_30, ag1_30, False),
            (ag4_30_8_30, ag4_30_1_10, False),
            (ag4_30_8_30, ag4_30_8_30, True),
        ]:
            result = bottom.subnet_of(top)
            self.assertEqual(result, req, msg=f"{top=} {bottom=}")

    def test_valid__wildcards(self):
        """Address.wildcards()"""
        for kwargs, req in [
            (dict(line=WILD30), [WILD30]),
            (dict(line=WILD_NC3), [WILD_NC3]),
            (dict(line=IOS_ADDGR, items=[WILD32]), [WILD32]),
            (dict(line=IOS_ADDGR, items=[WILD_NC3]), [WILD_NC3]),
        ]:
            obj = Address(platform="ios", **kwargs)
            result = obj.wildcards()
            self.assertEqual(result, req, msg=f"{kwargs=}")

    # ============================ functions =============================

    def test_valid__collapse(self):
        """address.collapse()"""
        host1 = "host 10.0.0.1"
        pr0_29 = "10.0.0.0/29"
        pr0_30 = "10.0.0.0/30"
        pr4_30 = "10.0.0.4/30"
        pr8_30 = "10.0.0.8/30"
        for lines, req in [
            ([], []),
            # 10.0.0.0/29
            ([pr0_29, pr0_29], [pr0_29]),
            ([pr0_29, pr0_30], [pr0_29]),
            ([pr0_29, pr4_30], [pr0_29]),
            ([pr0_29, pr0_30, pr4_30], [pr0_29]),
            ([pr0_29, pr8_30], [pr0_29, pr8_30]),
            ([pr0_29, host1], [pr0_29]),
            # 10.0.0.0/30
            ([pr0_30, pr0_29], [pr0_29, pr0_30]),
            ([pr0_30, pr0_30], [pr0_30]),
            ([pr0_30, pr4_30], [pr0_29]),
            ([pr0_30, pr0_30, pr4_30], [pr0_29]),
            ([pr0_30, pr8_30], [pr0_30, pr8_30]),
            ([pr0_30, host1], [pr0_30]),
            # 10.0.0.4/30
            ([pr4_30, pr0_29], [pr0_29, pr4_30]),
            ([pr4_30, pr0_30], [pr0_29]),
            ([pr4_30, pr4_30], [pr4_30]),
            ([pr4_30, pr0_30, pr4_30], [pr0_29]),
            ([pr4_30, pr8_30], [pr4_30, pr8_30]),
            ([pr4_30, host1], [host1, pr4_30]),
            # 10.0.0.8/30
            ([pr8_30, pr0_29], [pr0_29, pr8_30]),
            ([pr8_30, pr0_30], [pr0_30, pr8_30]),
            ([pr8_30, pr4_30], [pr4_30, pr8_30]),
            ([pr8_30, pr0_30, pr4_30], [pr0_29, pr8_30]),
            ([pr8_30, pr8_30], [pr8_30]),
            ([pr8_30, host1], [host1, pr8_30]),
        ]:
            addresses = [Address(s, platform="nxos") for s in lines]
            result_ = address.collapse(addresses)
            result = [o.line for o in list(result_)]
            self.assertEqual(result, req, msg=f"{lines=}")

    def test_invalid__collapse(self):
        """address.collapse()"""
        addr = Address("10.0.0.0/30", platform="nxos")
        addr_ag = AddressAg("10.0.0.0/30", platform="nxos")
        nc_wild = Address("10.0.0.0 0.0.3.3", platform="nxos")
        for addrs, error in [
            ([addr, addr_ag], TypeError),  # Address vs AddressAg
            ([addr, nc_wild], TypeError),  # non-contiguous wildcard
        ]:
            with self.assertRaises(error, msg=f"{addrs=}"):
                address.collapse(addrs)


if __name__ == "__main__":
    unittest.main()
