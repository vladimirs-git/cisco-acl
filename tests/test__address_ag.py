"""Unittest address_ag.py"""

import unittest
from ipaddress import IPv4Network

import dictdiffer  # type: ignore

from cisco_acl import AddressAg
from tests.helpers_test import (
    ANY,
    CNX_ADDGR,
    GROUPOBJ,
    GROUPOBJ_D,
    HOST,
    HOST_0_D,
    HOST_D,
    Helpers,
    IOS_ADDGR,
    PREFIX00,
    PREFIX00_32_D,
    PREFIX00_D,
    PREFIX30,
    PREFIX30_D,
    PREFIX32,
    PREFIX32_D,
    SUBNET00,
    SUBNET00_32_D,
    SUBNET30,
    SUBNET30_D,
    SUBNET32,
    SUBNET32_D,
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
        for platform, line, req_d in [
            # ios
            ("ios", PREFIX00, {}),
            ("ios", PREFIX30, SUBNET30_D),
            ("ios", PREFIX32, SUBNET32_D),
            ("ios", SUBNET00, {}),
            ("ios", SUBNET30, SUBNET30_D),
            ("ios", SUBNET32, SUBNET32_D),
            ("ios", WILD00, SUBNET00_32_D),
            ("ios", WILD30, {}),
            ("ios", WILD32, {}),
            ("ios", WILD_3_3, {}),
            ("ios", WILD_252, SUBNET30_D),
            ("ios", ANY, {}),
            ("ios", HOST, HOST_D),
            ("ios", GROUPOBJ, GROUPOBJ_D),
            ("ios", IOS_ADDGR, {}),
            ("ios", CNX_ADDGR, {}),
            # nxos
            ("nxos", PREFIX00, PREFIX00_D),
            ("nxos", PREFIX30, PREFIX30_D),
            ("nxos", PREFIX32, PREFIX32_D),
            ("nxos", SUBNET00, WILD00_32_D),
            ("nxos", SUBNET30, WILD_252_D),
            ("nxos", SUBNET32, {}),
            ("nxos", WILD00, WILD_ANY_D),
            ("nxos", WILD30, WILD30_D),
            ("nxos", WILD32, WILD32_D),
            ("nxos", WILD_3_3, WILD_33_D),
            ("nxos", WILD_252, WILD_252_D),
            ("nxos", ANY, {}),
            ("nxos", HOST, HOST_D),
            ("nxos", GROUPOBJ, {}),
            ("nxos", IOS_ADDGR, {}),
            ("nxos", CNX_ADDGR, {}),
        ]:
            # error
            if not req_d:
                with self.assertRaises(ValueError, msg=f"{line=} {platform=}"):
                    AddressAg(line=line, platform=platform)
                continue
            # init
            obj = AddressAg(line=line, platform=platform)
            self._test_attrs(obj=obj, req_d=req_d, msg=f"{line=} {platform=}")
            # setter
            obj = AddressAg(line=HOST, platform=platform)
            obj.line = line
            self._test_attrs(obj=obj, req_d=req_d, msg=f"{line=} {platform=}")

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
        for platform, line, req_d, platform_new, req_new_d in [
            # ios to ios
            ("ios", PREFIX30, SUBNET30_D, "ios", SUBNET30_D),
            ("ios", PREFIX32, SUBNET32_D, "ios", HOST_D),
            ("ios", SUBNET30, SUBNET30_D, "ios", SUBNET30_D),
            ("ios", SUBNET32, SUBNET32_D, "ios", HOST_D),
            ("ios", WILD00, SUBNET00_32_D, "ios", HOST_0_D),
            ("ios", WILD_252, SUBNET30_D, "ios", SUBNET30_D),
            ("ios", HOST, HOST_D, "ios", HOST_D),
            ("ios", GROUPOBJ, GROUPOBJ_D, "ios", GROUPOBJ_D),
            # ios to nxos
            ("ios", PREFIX30, SUBNET30_D, "nxos", PREFIX30_D),
            ("ios", PREFIX32, SUBNET32_D, "nxos", PREFIX32_D),
            ("ios", SUBNET30, SUBNET30_D, "nxos", PREFIX30_D),
            ("ios", SUBNET32, SUBNET32_D, "nxos", PREFIX32_D),
            ("ios", WILD00, SUBNET00_32_D, "nxos", PREFIX00_32_D),
            ("ios", WILD_252, SUBNET30_D, "nxos", PREFIX30_D),
            ("ios", HOST, HOST_D, "nxos", PREFIX32_D),
            ("ios", GROUPOBJ, GROUPOBJ_D, "nxos", {}),
            # nxos to nxos
            ("nxos", PREFIX00, PREFIX00_D, "nxos", PREFIX00_D),
            ("nxos", PREFIX30, PREFIX30_D, "nxos", PREFIX30_D),
            ("nxos", PREFIX32, PREFIX32_D, "nxos", PREFIX32_D),
            ("nxos", SUBNET00, WILD00_32_D, "nxos", PREFIX00_32_D),
            ("nxos", SUBNET30, WILD_252_D, "nxos", WILD_252_D),
            ("nxos", WILD00, WILD_ANY_D, "nxos", PREFIX00_D),
            ("nxos", WILD30, WILD30_D, "nxos", PREFIX30_D),
            ("nxos", WILD32, WILD32_D, "nxos", PREFIX32_D),
            ("nxos", WILD_3_3, WILD_33_D, "nxos", WILD_33_D),
            ("nxos", WILD_252, WILD_252_D, "nxos", WILD_252_D),
            ("nxos", HOST, HOST_D, "nxos", PREFIX32_D),
            # nxos to ios
            ("nxos", PREFIX00, PREFIX00_D, "ios", {}),
            ("nxos", PREFIX30, PREFIX30_D, "ios", SUBNET30_D),
            ("nxos", PREFIX32, PREFIX32_D, "ios", HOST_D),
            ("nxos", SUBNET00, WILD00_32_D, "ios", HOST_0_D),
            ("nxos", SUBNET30, WILD_252_D, "ios", {}),
            ("nxos", WILD00, WILD_ANY_D, "ios", {}),
            ("nxos", WILD30, WILD30_D, "ios", SUBNET30_D),
            ("nxos", WILD32, WILD32_D, "ios", HOST_D),
            ("nxos", WILD_3_3, WILD_33_D, "ios", {}),
            ("nxos", WILD_252, WILD_252_D, "ios", {}),
            ("nxos", HOST, HOST_D, "ios", HOST_D),
        ]:
            obj = AddressAg(line=line, platform=platform)
            self._test_attrs(obj=obj, req_d=req_d, msg=f"{line=} {platform=}")
            # platform error
            if not req_new_d:
                with self.assertRaises(ValueError, msg=f"{line=} {platform=}"):
                    obj.platform = platform_new
                continue
            # platform
            obj.platform = platform_new
            self._test_attrs(obj=obj, req_d=req_new_d, msg=f"{line=} {platform=}")

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

    # =========================== methods ============================

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
                    sequence=0,
                    items=[
                        dict(line="10.0.0.0 255.255.255.252",
                             platform="ios",
                             sequence=0,
                             items=[],
                             note="",
                             type="subnet",
                             addrgroup="",
                             ipnet=IPv4Network("10.0.0.0/30"),
                             prefix="10.0.0.0/30",
                             subnet="10.0.0.0 255.255.255.252",
                             wildcard="10.0.0.0 0.0.0.3")],
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
                    sequence=0,
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
            obj = AddressAg(**kwargs)
            result = obj.data()
            diff = list(dictdiffer.diff(first=result, second=req_d))
            self.assertEqual(diff, [], msg=f"{kwargs=}")


if __name__ == "__main__":
    unittest.main()
