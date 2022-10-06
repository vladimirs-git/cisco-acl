"""unittest addr_group.py"""

import unittest
from ipaddress import IPv4Network

import dictdiffer  # type: ignore

from cisco_acl import AddrGroup, AddressAg
from tests.helpers_test import (
    GROUPOBJ,
    HOST,
    Helpers,
    NAME_IOS,
    NAME_CNX,
    PREFIX00,
    PREFIX24,
    PREFIX30,
    PREFIX32,
    SUBNET30,
    SUBNET32,
    WILD00,
    WILD30,
    WILD32,
    WILD_252,
    WILD_3_3,
)

A_PREF00 = AddressAg(PREFIX00, platform="nxos")
A_PREF24 = AddressAg(PREFIX24, platform="nxos")
A_PREF30 = AddressAg(PREFIX30, platform="nxos")
A_PREF32 = AddressAg(PREFIX32, platform="nxos")
A_SUB30 = AddressAg(SUBNET30, platform="ios")
A_SUB32 = AddressAg(SUBNET32, platform="ios")
A_WILD00 = AddressAg(WILD00, platform="nxos")
A_WILD30 = AddressAg(WILD30, platform="nxos")
A_WILD32 = AddressAg(WILD32, platform="nxos")
A_WILD_3_3 = AddressAg(WILD_3_3, platform="nxos")
A_WILD_252 = AddressAg(WILD_252, platform="nxos")
# A_ADDGR = AddressAg(GROUPOBJ, platform="ios")  # todo AddressAg.addrgroup in AddrGroup.items
AG_PREF24 = AddrGroup(f"{NAME_CNX}\n{PREFIX24}", platform="nxos")
AG_SUB30 = AddrGroup(f"{NAME_CNX}\n{PREFIX30}", platform="nxos")
AG_WILD_3_3 = AddrGroup(f"{NAME_CNX}\n{WILD_3_3}", platform="nxos")
AG_TEXT = AddrGroup(f"{NAME_CNX}\n{PREFIX24}", platform="nxos")
# noinspection PyProtectedMember
AG_TEXT._items.insert(0, PREFIX30)  # type: ignore

CONFIG_IOS = """
object-group network NAME 
 description text 
 range 10.0.0.1 10.0.0.2
 10.0.0.0 255.255.255.252
 host 10.0.0.1
 group-object NAME2
 
object-group network NAME2
 host 10.0.0.2
"""
CONFIG_CNX = """
object-group ip address NAME
  10 10.0.0.0 0.0.0.3
  20 10.0.0.0/24
  30 host 10.0.0.1
"""
NORMALIZE_CNX = """
10.0.0.0 0.0.0.0 to host 10.0.0.0
10.0.0.0/32 to host 10.0.0.0
"""


# noinspection DuplicatedCode
class Test(Helpers):
    """AddrGroup"""

    # ========================== redefined ===========================

    def test_valid__hash__(self):
        """AddrGroup.__hash__()"""
        for platform, name, items, req_hash in [
            ("ios", "NAME", [SUBNET30], "NAME"),
            ("ios", "NAME", [HOST], "NAME"),
            ("nxos", "NAME", [WILD30], "NAME"),
            ("nxos", "NAME", [HOST], "NAME"),
        ]:
            obj = AddrGroup(platform=platform, name=name, items=items)
            result = obj.__hash__()
            req = req_hash.__hash__()
            self.assertEqual(result, req, msg=f"{name=} {items=}")

    def test_valid__eq__(self):
        """AddrGroup.__eq__() __ne__()"""
        obj1 = AddrGroup(platform="nxos", name="NAME", items=[PREFIX30])
        for obj2, req, in [
            (AddrGroup(platform="ios", name="NAME", items=[PREFIX30]), True),
            (AddrGroup(platform="nxos", name="NAME", items=[PREFIX30]), True),
            (AddrGroup(platform="ios", name="NAME", items=[HOST]), True),
            (AddrGroup(platform="ios", name="NAME", items=[GROUPOBJ]), True),
            (PREFIX30, False),
        ]:
            result = obj1.__eq__(obj2)
            self.assertEqual(result, req, msg=f"{obj1=} {obj2=}")
            result = obj1.__ne__(obj2)
            self.assertEqual(result, not req, msg=f"{obj1=} {obj2=}")

    def test_valid__lt__(self):
        """AddrGroup.__lt__() __le__() __gt__() __ge__()"""
        ag_pref = AddrGroup(platform="nxos", name="NAME", items=[SUBNET30])
        ag_host = AddrGroup(platform="ios", name="NAME", items=[HOST])
        ag_subnet = AddrGroup(platform="ios", name="NAME", items=[SUBNET30])
        ag_addgr = AddrGroup(platform="ios", name="NAME2", items=[GROUPOBJ])
        for obj1, obj2, req_lt, req_le, req_gt, req_ge in [
            (ag_pref, ag_pref, False, True, False, True),
            (ag_pref, ag_host, False, True, False, True),
            (ag_pref, ag_subnet, False, True, False, True),
            (ag_pref, ag_addgr, True, True, False, False),
        ]:
            result = obj1.__lt__(obj2)
            self.assertEqual(result, req_lt, msg=f"{obj1=} {obj2=}")
            result = obj1.__le__(obj2)
            self.assertEqual(result, req_le, msg=f"{obj1=} {obj2=}")
            result = obj1.__gt__(obj2)
            self.assertEqual(result, req_gt, msg=f"{obj1=} {obj2=}")
            result = obj1.__ge__(obj2)
            self.assertEqual(result, req_ge, msg=f"{obj1=} {obj2=}")

    def test_valid__contains__(self):
        """AddrGroup.__contains__()"""
        for obj1, obj2, req in [
            # in prefix "10.0.0.0/24"
            (AG_PREF24, A_PREF00, False),
            (AG_PREF24, A_PREF24, True),
            (AG_PREF24, A_PREF30, True),
            (AG_PREF24, A_PREF32, True),
            (AG_PREF24, A_SUB30, True),
            (AG_PREF24, A_SUB32, True),
            (AG_PREF24, A_WILD00, False),
            (AG_PREF24, A_WILD30, True),
            (AG_PREF24, A_WILD32, True),
            # (ag_pref24, addgr, True),  # todo AddressAg.addrgroup in AddrGroup.items
            (AG_PREF24, AG_PREF24, True),
            (AG_PREF24, AG_SUB30, True),
            (AG_WILD_3_3, A_WILD_3_3, True),
            (AG_WILD_3_3, AG_WILD_3_3, True),
        ]:
            msg = f"{obj1=} {obj2=}"
            result = obj1.__contains__(obj2)
            self.assertEqual(result, req, msg=msg)
            result = obj2 in obj1
            self.assertEqual(result, req, msg=msg)

    def test_invalid__contains__(self):
        """AddrGroup.__contains__()"""
        for obj1, obj2, error in [
            # in prefix "10.0.0.0/24"
            (AG_PREF24, A_WILD_3_3, TypeError),  # wildcard
            (AG_PREF24, A_WILD_252, TypeError),  # wildcard
            (AG_PREF24, PREFIX30, TypeError),  # text
            (AG_PREF24, AG_WILD_3_3, TypeError),  # wildcard in AddrGroup
            (AG_PREF24, AG_TEXT, TypeError),  # text in AddrGroup
            # in wildcard "10.0.0.0 0.0.3.3"
            (A_WILD_3_3, AG_PREF24, TypeError),
            (A_WILD_3_3, A_WILD_3_3, TypeError),
            (A_WILD_3_3, A_WILD_252, TypeError),
            (A_WILD_3_3, PREFIX30, TypeError),
            (A_WILD_3_3, AG_WILD_3_3, TypeError),
            (A_WILD_3_3, AG_TEXT, TypeError),
            # in wildcard "10.0.0.0 255.255.255.252"
            (A_WILD_252, AG_PREF24, TypeError),
            (A_WILD_252, A_WILD_3_3, TypeError),
            (A_WILD_252, A_WILD_252, TypeError),
            (A_WILD_252, PREFIX30, TypeError),
            (A_WILD_252, AG_WILD_3_3, TypeError),
            (A_WILD_252, AG_TEXT, TypeError),
            # in AddrGroup with wildcard "10.0.0.0 0.0.3.3"
            (AG_WILD_3_3, AG_PREF24, TypeError),
            (AG_WILD_3_3, A_WILD_252, TypeError),
            (AG_WILD_3_3, PREFIX30, TypeError),
            (AG_WILD_3_3, AG_TEXT, TypeError),
            # in AddrGroup with text
            (AG_TEXT, A_PREF30, TypeError),  # text in AddrGroup
        ]:
            with self.assertRaises(error):
                obj1.__contains__(obj2)

    # =========================== property ===========================

    def test_valid__indent(self):
        """AddrGroup.indent"""
        line1 = f"{NAME_IOS}\n  {HOST}"
        for kwargs, req in [
            (dict(line=line1), "  "),
            (dict(line=line1, indent=" "), " "),
            (dict(name="NAME", items=[HOST]), "  "),
            (dict(name="NAME", items=[HOST], indent=" "), " "),
        ]:
            obj = AddrGroup(**kwargs)
            result = obj.indent
            self.assertEqual(result, req, msg=f"{kwargs=}")
            # setter
            obj = AddrGroup(line1)
            obj.indent = req
            result = obj.indent
            self.assertEqual(result, req, msg=f"{kwargs=}")

    def test_valid__items(self):
        """AddrGroup.items"""
        for items, req, in [
            (HOST, [HOST]),
            ([HOST, SUBNET30], [HOST, SUBNET30]),
            ([AddressAg(HOST), AddressAg(SUBNET30)], [HOST, SUBNET30]),
        ]:
            obj = AddrGroup(items=items, name="NAME", platform="nxos")
            result = [o.line for o in obj.items]
            self.assertEqual(result, req, msg=f"{items=}")
            # setter
            obj = AddrGroup(f"{NAME_CNX}\n  {PREFIX30}", platform="nxos")
            obj.items = items
            result = [o.line for o in obj.items]
            self.assertEqual(result, req, msg=f"{items=}")

    def test_invalid__items(self):
        """AddrGroup.items"""
        for items, error, in [
            ([], ValueError),
            (["description text"], ValueError),  # todo description in AddGroup
        ]:
            with self.assertRaises(error, msg=f"{items=}"):
                AddrGroup(items=items, name="NAME", platform="nxos")

        obj = AddrGroup(f"{NAME_IOS}\n  {HOST}")
        for items, error, in [
            (1, TypeError),
            ([1], TypeError),
        ]:
            with self.assertRaises(error, msg=f"{items=}"):
                obj.items = items

    def test_valid__line(self):
        """AddrGroup.line"""
        # ios
        ios_subnet = f"{NAME_IOS}\n  {SUBNET30}"
        ios_host = f"{NAME_IOS}\n  {HOST}"
        ios_host_ = f"{NAME_IOS}\n{HOST}"
        ios_addgr = f"{NAME_IOS}\n  {GROUPOBJ}"
        # ios_range = f"{NAME_IOS}\n  range 10.0.0.1 10.0.0.3"  # todo range in AddGroup
        # ios_descr = f"{NAME_IOS}\n  description text"  # todo description in AddGroup
        # nxos
        nxos_prefix00 = f"{NAME_CNX}\n  {PREFIX00}"
        nxos_prefix30 = f"{NAME_CNX}\n  {PREFIX30}"
        nxos_prefix30_32 = f"{NAME_CNX}\n  {PREFIX30}\n  {PREFIX32}"
        nxos_prefix32 = f"{NAME_CNX}\n  {PREFIX32}"
        nxos_wild30 = f"{NAME_CNX}\n  {WILD30}"
        nxos_wild32 = f"{NAME_CNX}\n  {WILD30}"
        nxos_wild2 = f"{NAME_CNX}\n  {WILD30}"
        nxos_wild3 = f"{NAME_CNX}\n  {WILD30}"

        for kwargs, req_d, in [
            # ios
            (dict(line=ios_subnet, platform="ios"), dict(line=ios_subnet, name="NAME")),
            (dict(line=ios_host, platform="ios"), dict(line=ios_host, name="NAME")),
            (dict(line=ios_host_, platform="ios"), dict(line=ios_host, name="NAME")),  # no indent
            (dict(line=ios_addgr, platform="ios"), dict(line=ios_addgr, name="NAME")),
            # todo range in AddGroup
            # (dict(line=ios_range, platform="ios"), dict(line=ios_range, name="NAME")),
            # todo description in AddGroup
            # (dict(line=ios_descr, platform="ios"), dict(line=ios_descr, name="NAME")),
            # nxos
            (dict(line=nxos_prefix00, platform="nxos"), dict(line=nxos_prefix00, name="NAME")),
            (dict(line=nxos_prefix30, platform="nxos"), dict(line=nxos_prefix30, name="NAME")),
            (dict(line=nxos_prefix32, platform="nxos"), dict(line=nxos_prefix32, name="NAME")),
            (dict(line=nxos_prefix30_32, platform="nxos"), dict(line=nxos_prefix30_32)),
            (dict(line=nxos_wild30, platform="nxos"), dict(line=nxos_wild30, name="NAME")),
            (dict(line=nxos_wild32, platform="nxos"), dict(line=nxos_wild32, name="NAME")),
            (dict(line=nxos_wild2, platform="nxos"), dict(line=nxos_wild2, name="NAME")),
            (dict(line=nxos_wild3, platform="nxos"), dict(line=nxos_wild3, name="NAME")),
            # items
            (dict(platform="nxos", name="NAME", items=[PREFIX30, PREFIX32]),
             dict(line=nxos_prefix30_32, name="NAME")),
        ]:
            obj = AddrGroup(**kwargs)
            self._test_attrs(obj=obj, req_d=req_d, msg=f"{kwargs=}")
            # setter
            if kwargs.get("line"):
                obj.line = kwargs["line"]
                self._test_attrs(obj=obj, req_d=req_d, msg=f"{kwargs=}")

    def test_invalid__line(self):
        """AddrGroup.line"""
        for line, error, in [
            ("", ValueError),  # empty
            ("typo", ValueError),  # typo
            (f"{NAME_IOS} NAME\n  {SUBNET30}", ValueError),  # 2 names
            (NAME_IOS, ValueError),  # no items
        ]:
            with self.assertRaises(error, msg=f"{line=}"):
                AddrGroup(line)

    def test_valid__platform(self):
        """AddrGroup.platform"""
        kwargs_ios = dict(platform="ios", name="NAME", items=[SUBNET30])
        kwargs_nxos = dict(platform="nxos", name="NAME", items=[PREFIX30])
        for kwargs, platform_new, req in [
            (kwargs_ios, "nxos", f"{NAME_CNX}\n  {PREFIX30}"),
            (kwargs_nxos, "ios", f"{NAME_IOS}\n  {SUBNET30}"),
        ]:
            obj = AddrGroup(**kwargs)
            obj.platform = platform_new
            result = obj.line
            self.assertEqual(result, req, msg=f"{kwargs=} {platform_new=}")

    # =========================== methods ============================

    def test_valid__copy(self):
        """AddrGroup.copy()"""
        obj1 = AddrGroup(platform="ios", name="NAME", items=[SUBNET30], ident="  ")
        obj2 = obj1.copy()

        # change obj1 to check obj1 does not depend on obj2
        new_obj1_kwargs = dict(name="NAME2", items=[PREFIX32], ident=" ", platform="nxos")
        for arg, value in new_obj1_kwargs.items():
            setattr(obj1, arg, value)

        req1_d = dict(line="object-group ip address NAME2\n  10.0.0.1/32",
                      platform="nxos",
                      name="NAME2",
                      items=[AddressAg(line=HOST, platform="nxos")])
        req2_d = dict(line="object-group network NAME\n  10.0.0.0 255.255.255.252",
                      platform="ios",
                      name="NAME",
                      items=[AddressAg(line=PREFIX30, platform="ios")])
        self._test_attrs(obj1, req1_d, msg="obj1 does not depend on obj2")
        self._test_attrs(obj2, req2_d, msg="obj2 copied from obj1")

    def test_valid__data(self):
        """AddrGroup.data()"""
        kwargs1 = dict(platform="ios", name="NAME", items=[f"10 {SUBNET30}"], ident="  ")
        req1 = dict(line="object-group network NAME\n  10 10.0.0.0 255.255.255.252",
                    platform="ios",
                    note="",
                    indent="  ",
                    name="NAME",
                    items=[
                        dict(line="10 10.0.0.0 255.255.255.252",
                             platform="ios",
                             note="",
                             items=[],
                             sequence=10,
                             type="subnet",
                             addrgroup="",
                             ipnet=IPv4Network("10.0.0.0/30"),
                             prefix="10.0.0.0/30",
                             subnet="10.0.0.0 255.255.255.252",
                             wildcard="10.0.0.0 0.0.0.3"),
                    ])
        for kwargs, req_d in [
            (kwargs1, req1),
        ]:
            obj = AddrGroup(**kwargs)
            result = obj.data()
            diff = list(dictdiffer.diff(first=result, second=req_d))
            self.assertEqual(diff, [], msg=f"{kwargs=}")

    def test_valid__cmd_addgr_name(self):
        """AddrGroup.cmd_addgr_name()"""
        for platform, req in [
            ("ios", "object-group network NAME"),
            ("nxos", "object-group ip address NAME"),
        ]:
            obj = AddrGroup(platform=platform, name="NAME", items=[HOST])
            result = obj.cmd_addgr_name()
            self.assertEqual(result, req, msg=f"{platform=}")

    def test_valid__ipnets(self):
        """Address.ipnets()"""
        pref30 = AddressAg(PREFIX30, platform="nxos")
        pref32 = AddressAg(PREFIX32, platform="nxos")
        for items, req in [
            ([pref30, pref32], [PREFIX30, PREFIX32]),
        ]:
            obj = AddrGroup(platform="nxos", name="NAME", items=items)
            ipnets = obj.ipnets()
            result = [str(o) for o in ipnets]
            self.assertEqual(result, req, msg=f"{items=}")

    def test_invalid__ipnets(self):
        """Address.ipnets()"""
        addgr1 = AddressAg(line=GROUPOBJ, platform="ios", items=SUBNET32)
        for items, error in [
            ([addgr1], TypeError),
        ]:
            obj = AddrGroup(platform="nxos", name="NAME", items=items)
            with self.assertRaises(error, msg=f"{items=}"):
                obj.ipnets()

    def test_valid__prefixes(self):
        """AddrGroup.prefixes()"""
        pref30 = AddressAg(PREFIX30, platform="nxos")
        pref32 = AddressAg(PREFIX32, platform="nxos")
        for items, req in [
            ([pref30, pref32], [PREFIX30, PREFIX32]),
        ]:
            obj = AddrGroup(platform="nxos", name="NAME", items=items)
            prefixes = obj.prefixes()
            result = [str(o) for o in prefixes]
            self.assertEqual(result, req, msg=f"{items=}")

    def test_invalid__prefixes(self):
        """AddrGroup.prefixes()"""
        addgr1 = AddressAg(line=GROUPOBJ, platform="ios", items=SUBNET32)
        for items, error in [
            ([addgr1], TypeError),
        ]:
            obj = AddrGroup(platform="nxos", name="NAME", items=items)
            with self.assertRaises(error, msg=f"{items=}"):
                obj.prefixes()

    def test_invalid__resequence(self):
        """AddrGroup.resequence()"""
        for items, kwargs, req in [
            ([PREFIX30, PREFIX32], {}, [f"10 {PREFIX30}", f"20 {PREFIX32}"]),
            ([PREFIX30, PREFIX32], dict(start=2, step=3), [f"2 {PREFIX30}", f"5 {PREFIX32}"]),
            ([PREFIX30, PREFIX32], dict(start=0), [PREFIX30, PREFIX32]),
            ([PREFIX30, PREFIX32], dict(start=0, step=3), [PREFIX30, PREFIX32]),
            ([f"10 {PREFIX30}", f"20 {PREFIX32}"], dict(start=0), [PREFIX30, PREFIX32]),
        ]:
            obj = AddrGroup(name="NAME", platform="nxos", items=items)
            obj.resequence(**kwargs)
            result = [o.line for o in obj.items]
            self.assertEqual(result, req, msg=f"{items=} {kwargs=}")

    def test_valid__subnets(self):
        """AddrGroup.subnets()"""
        pref30 = AddressAg(PREFIX30, platform="nxos")
        pref32 = AddressAg(PREFIX32, platform="nxos")
        for items, req in [
            ([pref30, pref32], [SUBNET30, SUBNET32]),
        ]:
            obj = AddrGroup(platform="nxos", name="NAME", items=items)
            subnets = obj.subnets()
            result = [str(o) for o in subnets]
            self.assertEqual(result, req, msg=f"{items=}")

    def test_invalid__subnets(self):
        """AddrGroup.subnets()"""
        addgr1 = AddressAg(line=GROUPOBJ, platform="ios", items=SUBNET32)
        for items, error in [
            ([addgr1], TypeError),
        ]:
            obj = AddrGroup(platform="nxos", name="NAME", items=items)
            with self.assertRaises(error, msg=f"{items=}"):
                obj.subnets()

    def test_valid__wildcards(self):
        """AddrGroup.wildcards()"""
        pref30 = AddressAg(PREFIX30, platform="nxos")
        pref32 = AddressAg(PREFIX32, platform="nxos")
        for items, req in [
            ([pref30, pref32], [WILD30, WILD32]),
        ]:
            obj = AddrGroup(platform="nxos", name="NAME", items=items)
            wildcards = obj.wildcards()
            result = [str(o) for o in wildcards]
            self.assertEqual(result, req, msg=f"{items=}")

    def test_invalid__wildcards(self):
        """AddrGroup.wildcards()"""
        addgr1 = AddressAg(line=GROUPOBJ, platform="ios", items=SUBNET32)
        for items, error in [
            ([addgr1], ValueError),
        ]:
            obj = AddrGroup(platform="nxos", name="NAME", items=items)
            with self.assertRaises(error, msg=f"{items=}"):
                obj.wildcards()


if __name__ == "__main__":
    unittest.main()
