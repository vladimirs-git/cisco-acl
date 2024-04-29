"""Unittest address_ag.py"""

import unittest
from ipaddress import IPv4Network

import dictdiffer

from cisco_acl import AddressAg
from cisco_acl import address_ag
from tests.helpers_test import (
    ANY,
    CNX_ADDGR,
    GROUPOBJ,
    GROUPOBJ_D,
    HOST,
    HOST_,
    HOST_0_D,
    HOST_D,
    Helpers,
    IOS_ADDGR,
    PREFIX00,
    PREFIX00_D,
    PREFIX30,
    PREFIX30_D,
    PREFIX32,
    SUBNET00,
    SUBNET00_D,
    SUBNET30,
    SUBNET30_D,
    SUBNET32,
    UUID,
    UUID_R,
    UUID_R2,
    WILD00,
    WILD30,
    WILD32,
    WILD_NC252,
    WILD_NC252_D,
    WILD_NC3,
    WILD_NC3_D,
)


# noinspection DuplicatedCode
class Test(Helpers):
    """AddressAg"""

    # =========================== property ===========================

    def test_valid__items(self):
        """AddressAg.items"""
        kw_str = dict(line=GROUPOBJ, platform="ios", items=SUBNET30)
        kw_str_l = dict(line=GROUPOBJ, platform="ios", items=[SUBNET30])
        kw_dict = dict(line=GROUPOBJ, platform="ios", items=dict(line=SUBNET30))
        kw_dict_l = dict(line=GROUPOBJ, platform="ios", items=[dict(line=SUBNET30)])
        kw_obj = dict(line=GROUPOBJ, platform="ios", items=AddressAg(SUBNET30))
        kw_obj2 = dict(line=GROUPOBJ, platform="ios", items=AddressAg(PREFIX30, platform="nxos"))

        kw_obj_l = dict(line=GROUPOBJ, platform="ios", items=[AddressAg(SUBNET30)])
        kw_obj2_l = dict(line=GROUPOBJ, platform="ios", items=[AddressAg(PREFIX30,
                                                                         platform="nxos")])
        req1 = dict(line="group-object NAME",
                    platform="ios",
                    items=[AddressAg(SUBNET30)],
                    note="",
                    type="addrgroup",
                    addrgroup="NAME",
                    ipnet=None,
                    prefix="",
                    subnet="",
                    wildcard="")
        addr1 = dict(line="10.0.0.0 255.255.255.252",
                     platform="ios",
                     items=[],
                     note="",
                     type="subnet",
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
            obj = AddressAg(**kwargs)
            self._test_attrs(obj=obj, req_d=req_d, msg=f"{kwargs=}")
            addr_o = obj.items[0]
            self._test_attrs(obj=addr_o, req_d=req_addr_d, msg=f"{kwargs=}")

    def test_valid__line(self):
        """AddressAg.line"""
        for kwargs, req_d in [
            # ios
            (dict(platform="ios", line=PREFIX00), {}),
            (dict(platform="ios", line=PREFIX30), SUBNET30_D),
            (dict(platform="ios", line=PREFIX32), HOST_D),
            (dict(platform="ios", line=SUBNET00), {}),
            (dict(platform="ios", line=SUBNET30), SUBNET30_D),
            (dict(platform="ios", line=SUBNET32), HOST_D),
            (dict(platform="ios", line=WILD00), HOST_0_D),
            (dict(platform="ios", line=WILD30), {}),
            (dict(platform="ios", line=WILD32), SUBNET00_D),
            (dict(platform="ios", line=WILD_NC3), {}),
            (dict(platform="ios", line=WILD_NC252), SUBNET30_D),
            (dict(platform="ios", line=ANY), {}),
            (dict(platform="ios", line=HOST), HOST_D),
            (dict(platform="ios", line=GROUPOBJ), GROUPOBJ_D),
            (dict(platform="ios", line=IOS_ADDGR), {}),
            (dict(platform="ios", line=CNX_ADDGR), {}),
            # nxos
            (dict(platform="nxos", line=PREFIX00), PREFIX00_D),
            (dict(platform="nxos", line=PREFIX30), PREFIX30_D),
            (dict(platform="nxos", line=PREFIX32), HOST_D),
            (dict(platform="nxos", line=SUBNET00), HOST_0_D),
            (dict(platform="nxos", line=SUBNET30), WILD_NC252_D),
            (dict(platform="nxos", line=SUBNET32), PREFIX00_D),
            (dict(platform="nxos", line=WILD00), PREFIX00_D),
            (dict(platform="nxos", line=WILD30), PREFIX30_D),
            (dict(platform="nxos", line=WILD32), HOST_D),
            (dict(platform="nxos", line=WILD_NC3), WILD_NC3_D),
            (dict(platform="nxos", line=WILD_NC252), WILD_NC252_D),
            (dict(platform="nxos", line=ANY), PREFIX00_D),
            (dict(platform="nxos", line=HOST), HOST_D),
            (dict(platform="nxos", line=GROUPOBJ), {}),
            (dict(platform="nxos", line=IOS_ADDGR), {}),
            (dict(platform="nxos", line=CNX_ADDGR), {}),
        ]:
            msg = f"{kwargs=}"
            # error
            if not req_d:
                with self.assertRaises(ValueError, msg=msg):
                    AddressAg(max_ncwb=30, **kwargs)
                continue
            # init
            obj = AddressAg(max_ncwb=30, **kwargs)
            self._test_attrs(obj=obj, req_d=req_d, msg=msg)
            # setter
            obj = AddressAg(line=HOST, platform=kwargs["platform"], max_ncwb=30)
            obj.line = kwargs["line"]
            self._test_attrs(obj=obj, req_d=req_d, msg=msg)

    def test_invalid__line(self):
        """AddressAg.line"""
        for line, error in [
            ("", ValueError),
            ("typo", ValueError),
            (1, TypeError),
            ([ANY], TypeError),
        ]:
            with self.assertRaises(error, msg=f"{line=}"):
                AddressAg(line)

    def test_valid__platform(self):
        """AddressAg.platform"""
        for kwargs, req_d, platform_new, req_new_d in [
            # ios to ios
            (dict(platform="ios", line=PREFIX30), SUBNET30_D, "ios", SUBNET30_D),
            (dict(platform="ios", line=PREFIX32), HOST_D, "ios", HOST_D),
            (dict(platform="ios", line=SUBNET30), SUBNET30_D, "ios", SUBNET30_D),
            (dict(platform="ios", line=SUBNET32), HOST_D, "ios", HOST_D),
            (dict(platform="ios", line=WILD00), HOST_0_D, "ios", HOST_0_D),
            (dict(platform="ios", line=WILD_NC252), SUBNET30_D, "ios", SUBNET30_D),
            (dict(platform="ios", line=HOST), HOST_D, "ios", HOST_D),
            (dict(platform="ios", line=HOST_), HOST_D, "ios", HOST_D),
            (dict(platform="ios", line=GROUPOBJ), GROUPOBJ_D, "ios", GROUPOBJ_D),
            # ios to nxos
            (dict(platform="ios", line=PREFIX30), SUBNET30_D, "nxos", PREFIX30_D),
            (dict(platform="ios", line=PREFIX32), HOST_D, "nxos", HOST_D),
            (dict(platform="ios", line=SUBNET30), SUBNET30_D, "nxos", PREFIX30_D),
            (dict(platform="ios", line=SUBNET32), HOST_D, "nxos", HOST_D),
            (dict(platform="ios", line=WILD00), HOST_0_D, "nxos", HOST_0_D),
            (dict(platform="ios", line=WILD_NC252), SUBNET30_D, "nxos", PREFIX30_D),
            (dict(platform="ios", line=HOST), HOST_D, "nxos", HOST_D),
            (dict(platform="ios", line=HOST_), HOST_D, "nxos", HOST_D),
            (dict(platform="ios", line=GROUPOBJ), GROUPOBJ_D, "nxos", {}),
            # nxos to nxos
            (dict(platform="nxos", line=PREFIX00), PREFIX00_D, "nxos", PREFIX00_D),
            (dict(platform="nxos", line=PREFIX30), PREFIX30_D, "nxos", PREFIX30_D),
            (dict(platform="nxos", line=PREFIX32), HOST_D, "nxos", HOST_D),
            (dict(platform="nxos", line=SUBNET00), HOST_0_D, "nxos", HOST_0_D),
            (dict(platform="nxos", line=SUBNET30), WILD_NC252_D, "nxos", WILD_NC252_D),
            (dict(platform="nxos", line=WILD00), PREFIX00_D, "nxos", PREFIX00_D),
            (dict(platform="nxos", line=WILD30), PREFIX30_D, "nxos", PREFIX30_D),
            (dict(platform="nxos", line=WILD32), HOST_D, "nxos", HOST_D),
            (dict(platform="nxos", line=WILD_NC3), WILD_NC3_D, "nxos", WILD_NC3_D),
            (dict(platform="nxos", line=WILD_NC252), WILD_NC252_D, "nxos", WILD_NC252_D),
            (dict(platform="nxos", line=HOST), HOST_D, "nxos", HOST_D),
            # nxos to ios
            (dict(platform="nxos", line=PREFIX00), PREFIX00_D, "ios", {}),
            (dict(platform="nxos", line=PREFIX30), PREFIX30_D, "ios", SUBNET30_D),
            (dict(platform="nxos", line=PREFIX32), HOST_D, "ios", HOST_D),
            (dict(platform="nxos", line=SUBNET00), HOST_0_D, "ios", HOST_0_D),
            (dict(platform="nxos", line=SUBNET30), WILD_NC252_D, "ios", {}),
            (dict(platform="nxos", line=WILD00), PREFIX00_D, "ios", {}),
            (dict(platform="nxos", line=WILD30), PREFIX30_D, "ios", SUBNET30_D),
            (dict(platform="nxos", line=WILD32), HOST_D, "ios", HOST_D),
            (dict(platform="nxos", line=WILD_NC3), WILD_NC3_D, "ios", {}),
            (dict(platform="nxos", line=WILD_NC252), WILD_NC252_D, "ios", {}),
            (dict(platform="nxos", line=HOST), HOST_D, "ios", HOST_D),
        ]:
            msg = f"{kwargs=} {platform_new=}"
            obj = AddressAg(max_ncwb=30, **kwargs)
            self._test_attrs(obj=obj, req_d=req_d, msg=msg)
            # platform error
            if not req_new_d:
                with self.assertRaises(ValueError, msg=msg):
                    obj.platform = platform_new
                continue
            # setter
            obj.platform = platform_new
            self._test_attrs(obj=obj, req_d=req_new_d, msg=msg)

    def test_valid__platform__addrgroup_items(self):
        """Address.platform Address with addrgroup items"""
        for platform, line, items, platform_new, req_new in [
            ("ios", GROUPOBJ, [SUBNET30], "ios", [SUBNET30]),
        ]:
            msg = f"{line=} {platform=} {items=} {platform_new=}"
            obj = AddressAg(line=line, platform=platform, items=items)
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
        """AddressAg.prefix"""
        for platform, prefix, req_d in [
            # ios
            ("ios", PREFIX00, {}),
            ("ios", PREFIX30, SUBNET30_D),
            ("ios", PREFIX32, HOST_D),
            # nxos
            ("nxos", PREFIX00, PREFIX00_D),
            ("nxos", PREFIX30, PREFIX30_D),
            ("nxos", PREFIX32, HOST_D),
        ]:
            obj = AddressAg(line="host 10.0.0.2", platform=platform)
            # error
            if not req_d:
                with self.assertRaises(ValueError, msg=f"{prefix=} {platform=}"):
                    obj.prefix = prefix
                continue
            obj.prefix = prefix
            self._test_attrs(obj=obj, req_d=req_d, msg=f"{prefix=} {platform=}")

    def test_valid__sequence(self):
        """AddressAg.sequence"""
        for sequence, req in [
            ("", 0),
            ("0", 0),
            ("1", 1),
            (0, 0),
            (1, 1),
        ]:
            if sequence != "":
                obj = AddressAg(f"{sequence} {PREFIX30}", platform="nxos")
                result = obj.sequence
                self.assertEqual(result, req, msg=f"{sequence=}")
            # setter
            obj = AddressAg(PREFIX30, platform="nxos")
            obj.sequence = sequence
            result = obj.sequence
            self.assertEqual(result, req, msg=f"{sequence=}")

    # =========================== method =============================

    def test_valid__copy(self):
        """AddrGroup.copy()"""
        # ios
        obj1 = AddressAg(line=f"1 {GROUPOBJ}", platform="ios", items=[SUBNET30], note="a")
        obj2 = obj1.copy()

        # change obj1 to check obj1 does not depend on obj2
        new_obj1_kwargs = dict(sequence=2, _addrgroup="NAME2", items=[HOST], note="b")
        for arg, value in new_obj1_kwargs.items():
            setattr(obj1, arg, value)

        req1_d = dict(line="2 group-object NAME2",
                      platform="ios",
                      sequence=2,
                      addrgroup="NAME2",
                      items=[AddressAg(line=HOST, platform="ios")],
                      note="b")
        req2_d = dict(line="1 group-object NAME",
                      platform="ios",
                      sequence=1,
                      addrgroup="NAME",
                      items=[AddressAg(line=SUBNET30, platform="ios")],
                      note="a")
        self._test_attrs(obj1, req1_d, msg="obj1 does not depend on obj2")
        self._test_attrs(obj2, req2_d, msg="obj2 copied from obj1")

        # nxos
        obj1 = AddressAg(line=f"1 {PREFIX30}", platform="nxos", note="a")
        obj2 = obj1.copy()

        # change obj1 to check obj1 does not depend on obj2
        new_obj1_kwargs = dict(line=HOST, note="b", platform="ios")
        for arg, value in new_obj1_kwargs.items():
            setattr(obj1, arg, value)

        req1_d = dict(line="host 10.0.0.1",
                      platform="ios",
                      sequence=0,
                      addrgroup="",
                      items=[],
                      note="b")
        req2_d = dict(line="1 10.0.0.0/30",
                      platform="nxos",
                      sequence=1,
                      addrgroup="",
                      items=[],
                      note="a")
        self._test_attrs(obj1, req1_d, msg="obj1 does not depend on obj2")
        self._test_attrs(obj2, req2_d, msg="obj2 copied from obj1")

    def test_valid__data(self):
        """AddressAg.data()"""
        kwargs1 = dict(line=GROUPOBJ, platform="ios", items=[SUBNET30])
        req1 = dict(line="group-object NAME",
                    platform="ios",
                    version="0",
                    sequence=0,
                    items=[
                        dict(line="10.0.0.0 255.255.255.252",
                             platform="ios",
                             version="0",
                             sequence=0,
                             items=[],
                             note="",
                             max_ncwb=16,
                             type="subnet",
                             addrgroup="",
                             ipnet=IPv4Network("10.0.0.0/30"),
                             prefix="10.0.0.0/30",
                             subnet="10.0.0.0 255.255.255.252",
                             wildcard="10.0.0.0 0.0.0.3")],
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
                    version="0",
                    sequence=0,
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
            obj = AddressAg(**kwargs)
            obj.uuid = UUID
            for item in obj.items:
                item.uuid = UUID

            result = obj.data()
            diff = list(dictdiffer.diff(first=result, second=req_d))
            self.assertEqual(diff, [], msg=f"{kwargs=}")

            result = obj.data(uuid=True)
            diff = list(dictdiffer.diff(first=result, second=req_d))
            self.assertEqual(diff, req_uuid, msg=f"{kwargs=}")

    def test_valid__collapse(self):
        """address_ag.collapse()"""
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
            addresses = [AddressAg(s, platform="nxos") for s in lines]
            result_ = address_ag.collapse(addresses)
            result = [o.line for o in list(result_)]
            self.assertEqual(result, req, msg=f"{lines=}")

    def test_invalid__collapse(self):
        """address.collapse()"""
        addr = AddressAg("10.0.0.0/30", platform="nxos")
        nc_wild = AddressAg("10.0.0.0 0.0.3.3", platform="nxos")
        for addrs, error in [
            ([addr, nc_wild], TypeError),  # non-contiguous wildcard
        ]:
            with self.assertRaises(error, msg=f"{addrs=}"):
                address_ag.collapse(addrs)


if __name__ == "__main__":
    unittest.main()
