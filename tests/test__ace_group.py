"""Unittest ace_group.py"""

import unittest

import dictdiffer  # type: ignore

from cisco_acl import Ace, AceGroup, Remark, Address
from tests.helpers_test import (
    DENY_ICMP,
    DENY_IP,
    DENY_IP2,
    HOST,
    Helpers,
    PERMIT_135,
    PERMIT_IP,
    PERMIT_IP1,
    PERMIT_MSRPC,
    PERMIT_NAM,
    PERMIT_NUM,
    PERMIT_TCP1,
    PREFIX30,
    REMARK,
    UUID,
    UUID_R,
    WILD30,
    WILD_NC3,
)
from tests.test__ace_group__helpers import REQ_NO_LINE, REQ_LINE


# noinspection DuplicatedCode
class Test(Helpers):
    """AceGroup"""

    # ========================== redefined ===========================

    def test_valid__hash__(self):
        """AceGroup.__hash__()"""
        line = f"{PERMIT_IP}\n{DENY_IP}"
        obj = AceGroup(line)
        result = obj.__hash__()
        req = line.__hash__()
        self.assertEqual(result, req, msg=f"{line=}")

    def test_valid__eq__(self):
        """AceGroup.__eq__() __ne__()"""
        line = f"{PERMIT_IP}\n{DENY_IP}"
        obj1 = AceGroup(line)
        for obj2, req, in [
            (AceGroup(line), True),
            (AceGroup(f"{PERMIT_IP1}\n{DENY_IP}"), False),
            (AceGroup(PERMIT_IP), False),
            (Remark(REMARK), False),
            (line, False),
        ]:
            result = obj1.__eq__(obj2)
            self.assertEqual(result, req, msg=f"{obj1=} {obj2=}")
            result = obj1.__ne__(obj2)
            self.assertEqual(result, not req, msg=f"{obj1=} {obj2=}")

    def test_valid__lt__sort(self):
        """AceGroup.__lt__(), AceGroup.__le__()"""
        line = f"{PERMIT_IP}\n{DENY_IP}"
        obj = AceGroup(line)
        for items in [
            [AceGroup(line), obj],
            [AceGroup(f"{DENY_IP}\n{PERMIT_IP}"), obj],
            [obj, AceGroup(f"{PERMIT_IP1}\n{PERMIT_IP}")],
            [Remark("remark text"), obj],
            [Ace("permit ip any any"), obj],
            [line, obj],
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
        for items, req, in [
            ([], []),
            (PERMIT_IP, [PERMIT_IP]),
            (REMARK, [REMARK]),
            (Ace(PERMIT_IP), [PERMIT_IP]),
            (Remark(REMARK), [REMARK]),
            ([REMARK, DENY_IP], [REMARK, DENY_IP]),
            ([Remark(REMARK), Ace(DENY_IP)], [REMARK, DENY_IP]),
        ]:
            obj = AceGroup(items=items)
            result = [str(o) for o in obj.items]
            self.assertEqual(result, req, msg=f"{items=}")
            # setter
            obj = AceGroup()
            obj.items = items
            result = [str(o) for o in obj.items]
            self.assertEqual(result, req, msg=f"{items=}")

    def test_invalid__items(self):
        """AceGroup.items"""
        obj = AceGroup()
        for items, error, in [
            (1, TypeError),
            ([1], TypeError),
        ]:
            with self.assertRaises(error, msg=f"{items=}"):
                obj.items = items

    def test_valid__line(self):
        """AceGroup.line"""
        acl1 = f"{PERMIT_IP}\n \n{DENY_IP}\n \n{REMARK}"
        acl1_name = f"ip access-list NAME\n{acl1}"
        acl2 = f"2 {acl1}"
        group1 = f"{PERMIT_IP}\n{DENY_IP}\n{REMARK}"
        group2 = f"2 {group1}"

        for kwargs, req_d, in [
            (dict(line=""), dict(line="", sequence=0)),
            (dict(line="typo"), dict(line="", sequence=0)),
            (dict(line=PERMIT_IP), dict(line=PERMIT_IP, sequence=0)),
            (dict(line=PERMIT_IP1), dict(line=PERMIT_IP1, sequence=1)),
            (dict(line=acl1), dict(line=group1, sequence=0)),
            (dict(line=acl1_name), dict(line=group1, sequence=0)),
            (dict(line=acl2), dict(line=group2, sequence=2)),
            # port_nr
            (dict(line=PERMIT_NUM, port_nr=False), dict(line=PERMIT_NAM)),
            (dict(line=PERMIT_NAM, port_nr=True), dict(line=PERMIT_NUM)),
            # name
            (dict(line=PERMIT_IP, name="NAME1", note="NOTE1"),
             dict(line=PERMIT_IP, name="NAME1", note="NOTE1")),
        ]:
            obj = AceGroup(**kwargs)
            self._test_attrs(obj=obj, req_d=req_d, msg=f"{kwargs=}")
            # setter
            obj.line = kwargs["line"]
            self._test_attrs(obj=obj, req_d=req_d, msg=f"{kwargs=}")

    def test_valid__platform(self):
        """AceGroup.platform()"""
        any_port = "permit tcp any eq 1 any neq 2 log"
        host = "permit ip host 10.0.0.1 any"
        wild30 = "permit ip 10.0.0.0 0.0.0.3 any"
        wild32 = "permit ip 10.0.0.1 0.0.0.0 any"
        prefix30 = "permit ip 10.0.0.0/30 any"
        prefix32 = "permit ip 10.0.0.1/32 any"
        addgr_ios = "permit ip object-group NAME any"
        addgr_cnx = "permit ip addrgroup NAME any"

        for platform, platform_new, line, req, req_new in [
            # ios to ios
            ("ios", "ios", any_port, any_port, any_port),
            ("ios", "ios", host, host, host),
            ("ios", "ios", wild30, wild30, wild30),
            ("ios", "ios", wild32, host, host),
            ("ios", "ios", addgr_ios, addgr_ios, addgr_ios),
            # ios to nxos
            ("ios", "nxos", any_port, any_port, any_port),
            ("ios", "nxos", host, host, host),
            ("ios", "nxos", wild30, wild30, prefix30),
            ("ios", "nxos", wild32, host, host),
            ("ios", "nxos", addgr_ios, addgr_ios, addgr_cnx),
            # nxos to nxos
            ("nxos", "nxos", any_port, any_port, any_port),
            ("nxos", "nxos", host, host, host),
            ("nxos", "nxos", wild30, prefix30, prefix30),
            ("nxos", "nxos", wild32, host, host),
            ("nxos", "nxos", prefix30, prefix30, prefix30),
            ("nxos", "nxos", prefix32, host, host),
            ("nxos", "nxos", addgr_cnx, addgr_cnx, addgr_cnx),
            # nxos to ios
            ("nxos", "ios", any_port, any_port, any_port),
            ("nxos", "ios", host, host, host),
            ("nxos", "ios", wild30, prefix30, wild30),
            ("nxos", "ios", wild32, host, host),
            ("nxos", "ios", prefix30, prefix30, wild30),
            ("nxos", "ios", prefix32, host, host),
            ("nxos", "ios", addgr_cnx, addgr_cnx, addgr_ios),
        ]:
            obj = AceGroup(line, platform=platform)
            result = obj.line
            self.assertEqual(result, req, msg=f"{platform=} {platform_new=} {line=}")
            # platform
            obj.platform = platform_new
            result = obj.line
            self.assertEqual(result, req_new, msg=f"{platform=} {platform_new=} {line=}")

    def test_valid__platform__addrgroup_items(self):
        """AceGroup.platform()"""
        ios_addgr = "permit ip object-group A object-group A"
        cnx_addgr = "permit ip addrgroup A addrgroup A"
        for platform, line, items, platform_new, req in [
            ("ios", ios_addgr, [WILD30], "ios", [WILD30]),
            ("ios", ios_addgr, [WILD30], "nxos", [PREFIX30]),
            ("nxos", cnx_addgr, [PREFIX30], "nxos", [PREFIX30]),
            ("nxos", cnx_addgr, [PREFIX30], "ios", [WILD30]),
        ]:
            msg = f"{platform=} {line=} {items=} {platform_new=}"
            obj = AceGroup(line, platform=platform)
            obj.items[0].srcaddr.items = [Address(s, platform=platform) for s in items]
            obj.items[0].dstaddr.items = [Address(s, platform=platform) for s in items]
            for item in obj.items:
                item.uuid = UUID
                for item_ in [*item.srcaddr.items, *item.dstaddr.items]:
                    item_.uuid = UUID
            # setter
            obj.platform = platform_new
            result = [a.line for o in obj.items for a in o.srcaddr.items]
            self.assertEqual(result, req, msg=msg)
            result = [a.line for o in obj.items for a in o.dstaddr.items]
            self.assertEqual(result, req, msg=msg)
            # uuid
            for item in obj.items:
                result_ = item.uuid
                self.assertEqual(result_, UUID, msg=msg)
                for item_ in [*item.srcaddr.items, *item.dstaddr.items]:
                    result_ = item_.uuid
                    self.assertEqual(result_, UUID, msg=msg)

    def test_invalid__platform(self):
        """AceGroup.platform()"""
        ports_group = "permit tcp any eq 1 2 any neq 3 4"
        for platform, platform_new, line, error in [
            ("ios", "nxos", ports_group, ValueError),
        ]:
            obj = AceGroup(line, platform=platform)
            with self.assertRaises(error, msg=f"{platform=} {platform_new=} {line=}"):
                obj.platform = platform_new

    def test_valid__port_nr(self):
        """AceGroup.port_nr"""
        for kwargs, port_nr, req_d, in [
            (dict(line=PERMIT_NUM, port_nr=True), False, dict(line=PERMIT_NAM)),
            (dict(line=PERMIT_NAM, port_nr=False), True, dict(line=PERMIT_NUM)),
        ]:
            obj = AceGroup(**kwargs)
            obj.port_nr = port_nr
            self._test_attrs(obj=obj, req_d=req_d, msg=f"{kwargs=}")

    def test_valid__type(self):
        """AceGroup.type"""
        host_ext = f"{REMARK}\npermit tcp host 10.0.0.1 eq 1 host 10.0.0.2 eq 2 ack log"
        host_std = f"{REMARK}\npermit host 10.0.0.1"
        host_ext_ = f"{REMARK}\npermit ip host 10.0.0.1 any"
        wild_ext = f"{REMARK}\npermit tcp 10.0.0.0 0.0.0.3 eq 1 10.0.0.4 0.0.0.3 eq 2 ack log"
        wild_std = f"{REMARK}\npermit 10.0.0.0 0.0.0.3"
        wild_ext_ = f"{REMARK}\npermit ip 10.0.0.0 0.0.0.3 any"

        for type_, type_new, line, req in [
            # extended
            ("extended", "extended", host_ext, host_ext),
            ("extended", "extended", wild_ext, wild_ext),
            ("extended", "standard", host_ext, host_std),
            ("extended", "standard", wild_ext, wild_std),
            # standard
            ("standard", "standard", host_std, host_std),
            ("standard", "standard", wild_std, wild_std),
            ("standard", "extended", host_std, host_ext_),
            ("standard", "extended", wild_std, wild_ext_),
        ]:
            obj = AceGroup(line, platform="ios", type=type_)
            obj.type = type_new
            result = obj.line
            self.assertEqual(result, req, msg=f"{type_=} {line=}")

    def test_invalid__type(self):
        """AceGroup.type"""
        addrgroup = f"{REMARK}\npermit ip object-group NAME any"

        for platform, type_, type_new, line, error in [
            ("nxos", "extended", "standard", PERMIT_IP, ValueError),  # nxos
            ("ios", "extended", "standard", addrgroup, ValueError),  # addrgroup
        ]:
            obj = AceGroup(line, platform=platform, type=type_)
            with self.assertRaises(error, msg=f"{platform=} {type_=} {type_new=} {line=}"):
                obj.type = type_new

    # =========================== method =============================

    def test_valid__copy(self):
        """AceGroup.copy()"""
        obj1 = AceGroup(line=f"1 {PERMIT_IP}", platform="ios", name="NAME",
                        note="a", protocol_nr=True, port_nr=True)
        obj2 = obj1.copy()

        # change obj1 to check obj1 does not depend on obj2
        new_obj1_kwargs = dict(line=f"2 {DENY_IP}", name="NAME2", note="b",
                               protocol_nr=False, port_nr=False, platform="nxos")
        for arg, value in new_obj1_kwargs.items():
            setattr(obj1, arg, value)

        req1_d = dict(line="2 deny ip any any",
                      platform="nxos",
                      name="NAME2",
                      sequence=2,
                      items=[Ace("2 deny ip any any", platform="nxos")],
                      note="b",
                      protocol_nr=False,
                      port_nr=False)
        req2_d = dict(line="1 permit 0 any any",
                      platform="ios",
                      name="NAME",
                      sequence=1,
                      items=[Ace("1 permit 0 any any", protocol_nr=True, port_nr=True)],
                      note="a",
                      protocol_nr=True,
                      port_nr=True)
        self._test_attrs(obj1, req1_d, msg="obj1 does not depend on obj2")
        self._test_attrs(obj2, req2_d, msg="obj2 copied from obj1")

    def test_valid__data(self):
        """AceGroup.data()"""
        kw_no_line = dict(line="")
        kw_line = dict(
            line=f"1 {PERMIT_IP}\n2 {DENY_ICMP}",
            platform="nxos",
            note="a",
            protocol_nr=True,
            port_nr=True,
        )
        req_uuid1 = [("remove", ["items", 0, "protocol"], [("uuid", "ID1")]),
                     ("remove", ["items", 0, "srcaddr"], [("uuid", "ID1")]),
                     ("remove", ["items", 0, "srcport"], [("uuid", "ID1")]),
                     ("remove", ["items", 0, "dstaddr"], [("uuid", "ID1")]),
                     ("remove", ["items", 0, "dstport"], [("uuid", "ID1")]),
                     ("remove", ["items", 0, "option"], [("uuid", "ID1")]),
                     ("remove", ["items", 0], [("uuid", "ID1")]),
                     ("remove", ["items", 1, "protocol"], [("uuid", "ID1")]),
                     ("remove", ["items", 1, "srcaddr"], [("uuid", "ID1")]),
                     ("remove", ["items", 1, "srcport"], [("uuid", "ID1")]),
                     ("remove", ["items", 1, "dstaddr"], [("uuid", "ID1")]),
                     ("remove", ["items", 1, "dstport"], [("uuid", "ID1")]),
                     ("remove", ["items", 1, "option"], [("uuid", "ID1")]),
                     ("remove", ["items", 1], [("uuid", "ID1")]),
                     ("remove", "", [("uuid", "ID1")])]
        for kwargs, req_d, req_uuid in [
            (kw_no_line, REQ_NO_LINE, UUID_R),
            (kw_line, REQ_LINE, req_uuid1),
        ]:
            obj = AceGroup(**kwargs)
            obj.uuid = UUID
            for item in obj.items:
                item.uuid = UUID
                item.protocol.uuid = UUID
                item.srcaddr.uuid = UUID
                item.srcport.uuid = UUID
                item.dstaddr.uuid = UUID
                item.dstport.uuid = UUID
                item.option.uuid = UUID
                for item_ in [*item.srcaddr.items, *item.dstaddr.items]:
                    item_.uuid = UUID

            result = obj.data()
            diff = list(dictdiffer.diff(first=result, second=req_d))
            self.assertEqual(diff, [], msg=f"{kwargs=}")

            result = obj.data(uuid=True)
            diff = list(dictdiffer.diff(first=result, second=req_d))
            self.assertEqual(diff, req_uuid, msg=f"{kwargs=}")

    def test_valid__tcam_count(self):
        """AceGroup.tcam_count()"""
        addrs = [Address(WILD30), Address(WILD_NC3), Address(HOST)]
        for line, req in [
            (REMARK, 0),
            (PERMIT_IP, 1),
            (f"{REMARK}\n{PERMIT_TCP1}\n{REMARK}\n{DENY_ICMP}\n{PERMIT_IP}\n", 3),
            ("permit ip object-group NAME any", 3),
            ("permit ip any object-group NAME", 3),
            ("permit ip object-group NAME object-group NAME", 9),
        ]:
            obj = AceGroup(line)
            for item in obj.items:
                if isinstance(item, Ace) and req:
                    if item.srcaddr.type == "addrgroup":
                        item.srcaddr.items = addrs
                    if item.dstaddr.type == "addrgroup":
                        item.dstaddr.items = addrs

            result = obj.tcam_count()
            self.assertEqual(result, req, msg=f"{line=}")

    def test_valid__ungroup_ports(self):
        """AceGroup.ungroup_ports()"""
        for line, req in [
            ("permit tcp any any", "permit tcp any any"),
            ("permit tcp any eq 1 any eq 2", "permit tcp any eq 1 any eq 2"),
            ("permit tcp any eq 1 2 any", "permit tcp any eq 1 any\npermit tcp any eq 2 any"),
            ("permit tcp any eq 1 2 any eq 3 4", "permit tcp any eq 1 any eq 3\n"
                                                 "permit tcp any eq 1 any eq 4\n"
                                                 "permit tcp any eq 2 any eq 3\n"
                                                 "permit tcp any eq 2 any eq 4"),
            ("permit tcp any eq 1 any eq 2\npermit tcp any eq 3 any eq 4",
             "permit tcp any eq 1 any eq 2\npermit tcp any eq 3 any eq 4"),
            ("permit tcp any eq 1 2 any eq 3 4\npermit tcp any eq 1 2 any eq 1 2",
             "permit tcp any eq 1 any eq 3\npermit tcp any eq 1 any eq 4\n"
             "permit tcp any eq 2 any eq 3\npermit tcp any eq 2 any eq 4\n"
             "permit tcp any eq 1 any eq 1\npermit tcp any eq 1 any eq 2\n"
             "permit tcp any eq 2 any eq 1\npermit tcp any eq 2 any eq 2"),
        ]:
            obj = AceGroup(line, platform="ios")
            obj.ungroup_ports()
            result = obj.line
            self.assertEqual(result, req, msg=f"{line=}")

    # =========================== helper =============================

    def test_valid__convert_any_to_aces(self):
        """AceGroup._convert_any_to_aces()"""
        items0 = [Remark(REMARK), Ace(PERMIT_IP1)]
        items1 = [Ace(PERMIT_IP1), Ace(DENY_IP2)]
        items2 = [Ace(DENY_IP2), Ace(PERMIT_IP1)]
        for items, req_d in [
            (items0, dict(line=f"{REMARK}\n{PERMIT_IP1}", sequence=0)),
            (items1, dict(line=f"{PERMIT_IP1}\n{DENY_IP2}", sequence=0)),
            (items2, dict(line=f"{DENY_IP2}\n{PERMIT_IP1}", sequence=0)),
        ]:
            obj = AceGroup(items=items)
            self._test_attrs(obj=obj, req_d=req_d, msg=f"{items=}")
            # setter
            obj.items = items
            self._test_attrs(obj=obj, req_d=req_d, msg=f"{items=}")

    def test_valid__dict_to_ace(self):
        """AceGroup._dict_to_ace()"""
        obj = AceGroup()
        for params, req in [
            ({"line": REMARK, "action": "remark"}, REMARK),
            ({"line": PERMIT_IP, "action": "permit"}, PERMIT_IP),
            ({"line": DENY_IP, "action": "deny"}, DENY_IP),
            ({"line": ""}, None),
            ({"line": "typo"}, None),
        ]:
            if req:
                obj_ = obj._dict_to_ace(**params)
                result = str(obj_)
                self.assertEqual(result, req, msg=f"{params=}")
            else:
                with self.assertRaises(ValueError, msg=f"{params=}"):
                    obj._dict_to_ace(**params)

    def test_valid__dict_to_ace__version(self):
        """AceGroup._dict_to_ace() version"""
        for version, params, req in [
            ("", {"line": PERMIT_135, "action": "permit"}, PERMIT_MSRPC),
            ("15", {"line": PERMIT_135, "action": "permit"}, PERMIT_135),
        ]:
            obj = AceGroup(version=version)
            result = str(obj._dict_to_ace(**params))
            self.assertEqual(result, req, msg=f"{version=}")

    def test_valid__line_to_ace(self):
        """AceGroup._line_to_ace() AceGroup._line_to_oace()"""
        obj = AceGroup()
        for line, req in [
            (REMARK, Remark(REMARK)),
            (PERMIT_IP, Ace(PERMIT_IP)),
            (DENY_IP, Ace(DENY_IP)),
            ("", None),
            ("typo", None),
        ]:
            if req:
                result = obj._line_to_ace(line)
                self.assertEqual(result, req, msg=f"{line=}")
            else:
                with self.assertRaises(ValueError, msg=f"{line=}"):
                    obj._line_to_ace(line)

            result = obj._line_to_oace(line)
            self.assertEqual(result, req, msg=f"{line=}")

    def test_valid__line_to_ace__version(self):
        """AceGroup._line_to_ace() version"""
        for version, req in [
            ("", PERMIT_MSRPC),
            ("15", PERMIT_135),
        ]:
            obj = AceGroup(version=version)
            result = str(obj._line_to_ace(PERMIT_135))
            self.assertEqual(result, req, msg=f"{version=}")


if __name__ == "__main__":
    unittest.main()
