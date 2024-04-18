"""Unittest acl.py"""

import unittest
from ipaddress import IPv4Network

import dictdiffer  # type: ignore

from cisco_acl import Ace, AceGroup, Acl, Remark, Address
from tests import test__acl__helpers as h2
from tests.helpers_test import (
    ACL_NAME_CNX,
    ACL_NAME_IOS,
    ACL_NAME_IOS_STD,
    ACL_NAME_RP_CNX,
    ACL_NAME_RP_IOS,
    DENY_IP,
    DENY_IP1,
    ETH1,
    ETH2,
    HOST,
    Helpers,
    PERMIT_0,
    PERMIT_135,
    PERMIT_ICMP,
    PERMIT_IP,
    PERMIT_IP2,
    PERMIT_MSRPC,
    PERMIT_NAM,
    PERMIT_NUM,
    PERMIT_OBJ_GR,
    PERMIT_TCP,
    PERMIT_TCP1,
    PERMIT_TCP2,
    PERMIT_UDP,
    PERMIT_UDP1,
    PREFIX24,
    PREFIX30,
    PREFIX31,
    PREFIX32,
    REMARK,
    UUID,
    WILD30,
    WILD_NC3,
    make_acl,
    remove_acl_name,
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

    # ========================== redefined ===========================

    def test_valid__repr__(self):
        """Acl.__repr__()"""
        for kwargs, req in [
            (dict(line=f"{ACL_NAME_IOS}\n{PERMIT_IP2}\""),
             f"Acl(\"{ACL_NAME_IOS}\\n  {PERMIT_IP2}\")"),
            (dict(line=f"{ACL_NAME_CNX}\n{PERMIT_NAM}",
                  platform="nxos", version="15.2(02)SY", note="a",
                  input="intf1", output="intf2", indent=" ", protocol_nr=True, port_nr=True),
             "Acl(\"ip access-list NAME\\n permit tcp any eq 21 any eq 80\", "
             "platform=\"nxos\", version=\"15.2(02)sy\", note=\"a\", "
             "input=[\"intf1\"], output=[\"intf2\"], "
             "indent=\" \", protocol_nr=True, port_nr=True)"),
        ]:
            obj = Acl(**kwargs)
            result = obj.__repr__()
            result = self._quotation(result)
            self.assertEqual(result, req, msg=f"{result=}")

    # =========================== property ===========================

    def test_valid__indent(self):
        """Acl.indent"""
        for indent, req in [
            (None, "  "),
            ("", ""),
            (" ", " "),
        ]:
            obj = Acl(indent=indent)
            result = obj.indent
            self.assertEqual(result, req, msg=f"{indent=}")
            # setter
            obj = Acl()
            obj.indent = indent
            result = obj.indent
            self.assertEqual(result, req, msg=f"{indent=}")

    def test_valid__items(self):
        """Acl.items"""
        for items, req, in [
            ([], []),
            # str
            (REMARK, [REMARK]),
            (PERMIT_IP, [PERMIT_IP]),
            ([REMARK, PERMIT_IP, DENY_IP], [REMARK, PERMIT_IP, DENY_IP]),
            # dict
            (dict(line=REMARK, action="remark"), [REMARK]),
            (dict(line=PERMIT_IP, action="permit"), [PERMIT_IP]),
            ([dict(line=REMARK, action="remark"),
              dict(line=PERMIT_IP, action="permit"),
              dict(line=DENY_IP, action="deny")],
             [REMARK, PERMIT_IP, DENY_IP]),
            # objects
            ([Remark(REMARK)], [REMARK]),
            ([Ace(PERMIT_IP)], [PERMIT_IP]),
            ([AceGroup(PERMIT_IP)], [PERMIT_IP]),
            ([Remark(REMARK), AceGroup(PERMIT_IP), Ace(DENY_IP)], [REMARK, PERMIT_IP, DENY_IP]),
            ([Remark(REMARK), AceGroup(f"{PERMIT_IP}\n{DENY_IP}")],
             [REMARK, f"{PERMIT_IP}\n{DENY_IP}"]),
        ]:
            obj = Acl(name="NAME", items=items)
            result = [str(o) for o in obj.items]
            self.assertEqual(result, req, msg=f"{items=}")
            # setter
            obj = Acl()
            obj.items = items
            result = [str(o) for o in obj.items]
            self.assertEqual(result, req, msg=f"{items=}")

        # group_by
        req1 = [f"remark =G1\n{PERMIT_OBJ_GR}", f"remark =G2\n{PERMIT_IP}"]
        for items, req, req_addr, in [
            # list
            (["remark =G1", PERMIT_OBJ_GR, "remark =G2", PERMIT_IP], req1, []),
            # dict
            ([dict(line="remark =G1", action="remark"),
              dict(line=PERMIT_OBJ_GR,
                   action="permit",
                   srcaddr=dict(line="object-group NAME", items=[dict(line=WILD30)])),
              dict(line="remark =G2", action="remark"),
              dict(line=PERMIT_IP, action="permit")],
             req1, [WILD30]),
            # objects
            ([Remark("remark =G1"),
              Ace(PERMIT_OBJ_GR),
              Remark("remark =G2"),
              Ace(PERMIT_IP)],
             req1, []),
        ]:
            obj = Acl(name="NAME", items=items, group_by="=")
            result = [o.line for o in obj.items]
            self.assertEqual(result, req, msg=f"{items=}")

            # AddrGroup items
            obj.ungroup()
            aces = [o for o in obj.items if isinstance(o, Ace)]
            addr_items = aces[0].srcaddr.items
            result = [o.line for o in addr_items]
            self.assertEqual(result, req_addr, msg=f"{items=}")

    def test_invalid__items(self):
        """Acl.items"""
        for items, error, in [
            (1, TypeError),
        ]:
            obj = Acl()
            with self.assertRaises(error, msg=f"{items=}"):
                obj.items = items

    def test_valid__line(self):
        """Acl.line"""
        for kwargs, req_d, in [
            # ios
            (dict(line="\n", platform="ios"), dict(line="ip access-list extended \n", name="")),
            (dict(line=ACL_NAME_IOS, platform="ios"), dict(line=f"{ACL_NAME_IOS}\n", name="NAME")),
            (dict(line=ACL_NAME_RP_IOS, platform="ios"), dict(line=ACL_NAME_RP_IOS, name="NAME")),
            # nxos
            (dict(line="\n", platform="nxos"), dict(line="ip access-list \n", name="")),
            (dict(line=ACL_NAME_CNX, platform="nxos"), dict(line=f"{ACL_NAME_CNX}\n", name="NAME")),
            (dict(line=ACL_NAME_RP_CNX, platform="nxos"), dict(line=ACL_NAME_RP_CNX, name="NAME")),
            # input output
            (dict(line=ACL_NAME_IOS, input="eth1"), dict(line=f"{ACL_NAME_IOS}\n", input=["eth1"])),
            (dict(line=ACL_NAME_IOS, input=["eth1"]),
             dict(line=f"{ACL_NAME_IOS}\n", input=["eth1"])),
            (dict(line=ACL_NAME_IOS, output="eth1"),
             dict(line=f"{ACL_NAME_IOS}\n", output=["eth1"])),
            (dict(line=ACL_NAME_IOS, output=["eth1"]),
             dict(line=f"{ACL_NAME_IOS}\n", output=["eth1"])),
            # protocol_nr
            (dict(line=f"{ACL_NAME_IOS}\n{PERMIT_IP}", protocol_nr=False),
             dict(line=f"{ACL_NAME_IOS}\n  {PERMIT_IP}")),
            (dict(line=f"{ACL_NAME_IOS}\n{PERMIT_0}", protocol_nr=False),
             dict(line=f"{ACL_NAME_IOS}\n  {PERMIT_IP}")),
            (dict(line=f"{ACL_NAME_IOS}\n{PERMIT_IP}", protocol_nr=True),
             dict(line=f"{ACL_NAME_IOS}\n  {PERMIT_0}")),
            (dict(line=f"{ACL_NAME_IOS}\n{PERMIT_0}", protocol_nr=True),
             dict(line=f"{ACL_NAME_IOS}\n  {PERMIT_0}")),
            # port_nr
            (dict(line=f"{ACL_NAME_IOS}\n{PERMIT_NUM}", port_nr=False),
             dict(line=f"{ACL_NAME_IOS}\n  {PERMIT_NAM}")),
            (dict(line=f"{ACL_NAME_IOS}\n{PERMIT_NUM}", port_nr=True),
             dict(line=f"{ACL_NAME_IOS}\n  {PERMIT_NUM}")),
            (dict(line=f"{ACL_NAME_IOS}\n{PERMIT_NAM}", port_nr=False),
             dict(line=f"{ACL_NAME_IOS}\n  {PERMIT_NAM}")),
            (dict(line=f"{ACL_NAME_IOS}\n{PERMIT_NAM}", port_nr=True),
             dict(line=f"{ACL_NAME_IOS}\n  {PERMIT_NUM}")),
            # not supported lines
            (dict(line=f"{ACL_NAME_IOS}\nstatistics per-entry", platform="ios"),
             dict(line=f"{ACL_NAME_IOS}\n", name="NAME")),
            (dict(line=f"{ACL_NAME_IOS}\nignore routable", platform="ios"),
             dict(line=f"{ACL_NAME_IOS}\n", name="NAME")),
            # version
            (dict(line=f"{ACL_NAME_IOS}\n{PERMIT_135}", platform="ios", version=""),
             dict(line=f"{ACL_NAME_IOS}\n  {PERMIT_MSRPC}")),
            (dict(line=f"{ACL_NAME_IOS}\n{PERMIT_135}", platform="ios", version="15"),
             dict(line=f"{ACL_NAME_IOS}\n  {PERMIT_135}")),
        ]:
            obj = Acl(**kwargs)
            self._test_attrs(obj=obj, req_d=req_d, msg=f"{kwargs=}")
            # setter
            obj.line = kwargs["line"]
            self._test_attrs(obj=obj, req_d=req_d, msg=f"{kwargs=}")

    def test_invalid__line__skip(self):
        """Acl.line skip invalid line"""
        expected = ACL_NAME_IOS
        for line in [
            f"{ACL_NAME_IOS}\npermit ip any any 0.0.0.0"  # option
            f"{ACL_NAME_IOS_STD}\npermit host 10.0.0.1 0.0.0.0"  # option
        ]:
            obj = Acl(line, platform="ios")
            result = str(obj).strip()
            self.assertEqual(result, expected, msg=f"{line=}")

    def test_invalid__line__error(self):
        """Acl.line raise error"""
        for line, error, in [
            ("ip access-list extended\n permit ip any any", ValueError),  # no name
            ("ip access-listy\n permit ip any any", ValueError),  # no name
            (f"{ACL_NAME_IOS} NAME\n permit ip any any", ValueError),  # 2 names
            (PERMIT_IP, ValueError),
        ]:
            with self.assertRaises(error, msg=f"{line=}"):
                Acl(line, platform="ios")

            obj = Acl(f"{ACL_NAME_IOS}\n{PERMIT_IP}", platform="ios")
            with self.assertRaises(error, msg=f"{line=}"):
                obj.line = line

    def test_valid__name(self):
        """Acl.name"""
        for name, req in [
            (None, ""),
            ("", ""),
            ("A1", "A1"),
            ("a_", "a_"),
            ("\tab\n", "ab"),
        ]:
            obj = Acl(name=name, line_length=2)
            result = obj.name
            self.assertEqual(result, req, msg=f"{name=}")
            # setter
            obj.name = name
            result = obj.name
            self.assertEqual(result, req, msg=f"{name=}")

    def test_valid__platform(self):
        """Ace.platform()"""
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
                    "  permit ip host 1.1.1.1 host 2.2.2.2\n" \
                    "  permit ip 1.1.1.0/24 2.2.2.0/24\n" \
                    "  permit udp 1.1.0.0 0.0.3.3 2.2.0.0 0.0.3.3 range 1 3\n" \
                    "  permit tcp any eq 1 any neq 3\n" \
                    "  permit tcp any eq 1 any neq 4\n" \
                    "  permit tcp any eq 2 any neq 3\n" \
                    "  permit tcp any eq 2 any neq 4\n" \
                    "  permit tcp any gt 65533 any lt 3"
        for platform, platform_new, line, req, req_new in [
            # ios to ios
            ("ios", "ios", acl1_ios, acl1_ios, acl1_ios),
            # ios to nxos
            ("ios", "nxos", acl1_ios, acl1_ios, acl1_nxos),
            ("ios", "nxos", acl3_ios, acl3_ios, acl3_nxos),
            # nxos to nxos
            ("nxos", "nxos", acl1_nxos, acl1_nxos, acl1_nxos),
            # nxos to ios
            ("nxos", "ios", acl1_nxos, acl1_nxos, acl2_ios),
        ]:
            msg = f"{platform=} {platform_new=} {line=}"
            obj = Acl(line, platform=platform)
            result = obj.line
            self.assertEqual(result, req, msg=msg)

            obj.platform = platform_new
            result = str(obj)
            self.assertEqual(result, req_new, msg=msg)

    def test_valid__platform__addrgroup_items(self):
        """Acl.platform()"""
        ios_addgr = "ip access-list extended NAME\n permit ip object-group A object-group A"
        cnx_addgr = "ip access-list NAME\n permit ip addrgroup A addrgroup A"
        for platform, line, items, platform_new, req in [
            ("ios", ios_addgr, [WILD30], "ios", [WILD30]),
            ("ios", ios_addgr, [WILD30], "nxos", [PREFIX30]),
            ("nxos", cnx_addgr, [PREFIX30], "nxos", [PREFIX30]),
            ("nxos", cnx_addgr, [PREFIX30], "ios", [WILD30]),
        ]:
            msg = f"{platform=} {line=} {items=} {platform_new=}"
            obj = Acl(line, platform=platform)
            obj.items[0].srcaddr.items = [Address(s, platform=platform) for s in items]
            obj.items[0].dstaddr.items = [Address(s, platform=platform) for s in items]
            obj.uuid = UUID
            for item in obj.items:
                item.uuid = UUID
                item.srcaddr.uuid = UUID
                item.dstaddr.uuid = UUID
                for item_ in [*item.srcaddr.items, *item.dstaddr.items]:
                    item_.uuid = UUID
            # setter
            obj.platform = platform_new
            result = [o.line for o in obj.items[0].srcaddr.items]
            self.assertEqual(result, req, msg=msg)
            result = [o.line for o in obj.items[0].dstaddr.items]
            self.assertEqual(result, req, msg=msg)
            # uuid
            aces = [o for o in obj.items if isinstance(o, Ace)]
            for ace_o in aces:
                result_ = ace_o.uuid
                self.assertEqual(result_, UUID, msg=msg)
                for item_ in [*ace_o.srcaddr.items, *ace_o.dstaddr.items]:
                    result_ = item_.uuid
                    self.assertEqual(result_, UUID, msg=msg)

    def test_valid__type(self):
        """Acl.type"""
        host_ext = f"{ACL_NAME_IOS}\n" \
                   f"  {REMARK}\n" \
                   f"  permit tcp host 10.0.0.1 eq 1 host 10.0.0.2 eq 2 ack log"
        host1_std = f"{ACL_NAME_IOS_STD}\n" \
                    f"  {REMARK}\n" \
                    f"  permit host 10.0.0.1"
        host2_std = f"{ACL_NAME_IOS_STD}\n" \
                    f"  {REMARK}\n" \
                    f"  permit 10.0.0.1"
        host3_std = f"{ACL_NAME_IOS_STD}\n" \
                    f"  {REMARK}\n" \
                    f"  permit 10.0.0.1 0.0.0.0"
        host_ext_ = f"{ACL_NAME_IOS}\n" \
                    f"  {REMARK}\n  permit ip host 10.0.0.1 any"
        wild_ext = f"{ACL_NAME_IOS}\n" \
                   f"  {REMARK}\n" \
                   f"  permit tcp 10.0.0.0 0.0.0.3 eq 1 10.0.0.4 0.0.0.3 eq 2 ack log"
        wild_std = f"{ACL_NAME_IOS_STD}\n" \
                   f"  {REMARK}\n" \
                   f"  permit 10.0.0.0 0.0.0.3"
        wild_ext_ = f"{ACL_NAME_IOS}\n" \
                    f"  {REMARK}\n" \
                    f"  permit ip 10.0.0.0 0.0.0.3 any"
        aceg_ext = f"{ACL_NAME_IOS}\n" \
                   f"  remark = C-1\n" \
                   f"  permit tcp host 10.0.0.1 eq 1 host 10.0.0.2 eq 2 ack log\n" \
                   f"  remark = C-2\n" \
                   f"  {PERMIT_IP}"
        aceg_std = f"{ACL_NAME_IOS_STD}\n" \
                   f"  remark = C-1\n" \
                   f"  permit host 10.0.0.1\n" \
                   f"  remark = C-2\n" \
                   f"  permit any"
        aceg_ext_ = f"{ACL_NAME_IOS}\n" \
                    f"  remark = C-1\n" \
                    f"  permit ip host 10.0.0.1 any\n" \
                    f"  remark = C-2\n" \
                    f"  {PERMIT_IP}"
        for type_, type_new, line, req in [
            # extended to extended
            ("extended", "extended", host_ext, host_ext),
            ("extended", "extended", wild_ext, wild_ext),
            ("extended", "extended", aceg_ext, aceg_ext),
            # extended to standard
            ("extended", "standard", host_ext, host1_std),
            ("extended", "standard", wild_ext, wild_std),
            ("extended", "standard", aceg_ext, aceg_std),
            # standard to standard
            ("standard", "standard", host1_std, host1_std),
            ("standard", "standard", host2_std, host1_std),
            ("standard", "standard", host3_std, host1_std),
            ("standard", "standard", wild_std, wild_std),
            ("standard", "standard", aceg_std, aceg_std),
            # standard to extended
            ("standard", "extended", host1_std, host_ext_),
            ("standard", "extended", host2_std, host_ext_),
            ("standard", "extended", host3_std, host_ext_),
            ("standard", "extended", wild_std, wild_ext_),
            ("standard", "extended", aceg_std, aceg_ext_),
        ]:
            obj = Acl(line, platform="ios", type=type_, group_by="= ")
            obj.type = type_new
            result = obj.line
            self.assertEqual(result, req, msg=f"{type_=} {line=}")

    def test_invalid__type(self):
        """Acl.type"""
        acl_cnx = f"{ACL_NAME_CNX}\n{PERMIT_IP}\n"
        acl_ios_addgr = f"{ACL_NAME_IOS}\npermit ip object-group NAME any"

        for line, platform, type_, type_new, error in [
            (acl_cnx, "nxos", "extended", "standard", ValueError),  # nxos
            (acl_ios_addgr, "ios", "extended", "standard", ValueError),  # addrgroup
        ]:
            obj = Acl(line, platform=platform, type=type_)
            with self.assertRaises(error, msg=f"{platform=} {type_=} {type_new=} {line=}"):
                obj.type = type_new

    # =========================== method =============================

    def test_valid__copy(self):
        """Acl.copy()"""
        kwargs1 = dict(line=f"{ACL_NAME_IOS}\n10 permit tcp {HOST} {WILD30} eq www 443 log",
                       platform="ios",
                       input=[ETH1],
                       output=[ETH2],
                       note="a",
                       indent=" ",
                       rotocol_nr=False,
                       port_nr=False)
        obj1 = Acl(**kwargs1)
        obj2 = obj1.copy()

        # change obj1 to check obj1 does not depend on obj2
        new_obj1_kwargs = dict(line=f"{ACL_NAME_IOS}2\n{DENY_IP}",
                               input=[ETH2],
                               output=[ETH1],
                               note="b",
                               indent="",
                               rotocol_nr=False,
                               port_nr=False,
                               platform="nxos")
        for arg, value in new_obj1_kwargs.items():
            setattr(obj1, arg, value)

        req1_d = dict(line="ip access-list NAME2\ndeny ip any any",
                      platform="nxos",
                      name="NAME2",
                      items=[Ace("deny ip any any", platform="nxos")],
                      input=["interface Ethernet2"],
                      output=["interface Ethernet1"],
                      note="b",
                      indent="",
                      protocol_nr=False,
                      port_nr=False)
        req2_d = dict(line=f"{ACL_NAME_IOS}\n 10 permit tcp {HOST} {WILD30} eq www 443 log",
                      platform="ios",
                      name="NAME",
                      items=[Ace(f"10 permit tcp {HOST} {WILD30} eq www 443 log")],
                      input=["interface Ethernet1"],
                      output=["interface Ethernet2"],
                      note="a",
                      indent=" ",
                      protocol_nr=False,
                      port_nr=False)
        self._test_attrs(obj1, req1_d, msg="obj1 does not depend on obj2")
        self._test_attrs(obj2, req2_d, msg="obj1 copy of obj2")

    def test_valid__data(self):
        """Acl.data()"""
        kwargs1 = dict(line=f"{ACL_NAME_IOS}\n{PERMIT_IP}",
                       platform="ios",
                       input=[ETH1],
                       output=[ETH2],
                       note="a",
                       indent=" ",
                       protocol_nr=True,
                       port_nr=True)
        req1 = dict(
            line="ip access-list extended NAME\n permit 0 any any",
            platform="ios",
            version="0",
            type="extended",
            input=["interface Ethernet1"],
            output=["interface Ethernet2"],
            name="NAME",
            items=[
                dict(line="permit 0 any any",
                     platform="ios",
                     version="0",
                     type="extended",
                     note="",
                     max_ncwb=16,
                     protocol_nr=True,
                     port_nr=True,
                     sequence=0,
                     action="permit",
                     protocol=dict(line="0",
                                   platform="ios",
                                   version="0",
                                   note="",
                                   protocol_nr=True,
                                   has_port=False,
                                   name="ip",
                                   number=0),
                     srcaddr=dict(line="any",
                                  platform="ios",
                                  version="0",
                                  items=[],
                                  note="",
                                  max_ncwb=16,
                                  type="any",
                                  addrgroup="",
                                  ipnet=IPv4Network("0.0.0.0/0"),
                                  prefix="0.0.0.0/0",
                                  subnet="0.0.0.0 0.0.0.0",
                                  wildcard="0.0.0.0 255.255.255.255"),
                     srcport=dict(line="",
                                  platform="ios",
                                  version="0",
                                  note="",
                                  protocol="",
                                  port_nr=True,
                                  items=[],
                                  operator="",
                                  ports=[],
                                  sport=""),
                     dstaddr=dict(line="any",
                                  platform="ios",
                                  version="0",
                                  items=[],
                                  note="",
                                  max_ncwb=16,
                                  type="any",
                                  addrgroup="",
                                  ipnet=IPv4Network("0.0.0.0/0"),
                                  prefix="0.0.0.0/0",
                                  subnet="0.0.0.0 0.0.0.0",
                                  wildcard="0.0.0.0 255.255.255.255"),
                     dstport=dict(line="",
                                  platform="ios",
                                  version="0",
                                  note="",
                                  protocol="",
                                  port_nr=True,
                                  items=[],
                                  operator="",
                                  ports=[],
                                  sport=""),
                     option=dict(line="",
                                 platform="ios",
                                 version="0",
                                 note="",
                                 flags=[],
                                 logs=[])),
            ],
            group_by="",
            note="a",
            max_ncwb=16,
            indent=" ",
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
                     ("remove", "", [("uuid", "ID1")])]

        for kwargs, req_d, req_uuid in [
            (kwargs1, req1, req_uuid1),
        ]:
            obj = Acl(**kwargs)
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

    def test_valid__delete_note(self):
        """Acl.delete_note()"""
        remark1 = Remark("remark 1", note="1")
        ace2 = Ace("permit tcp any any eq 2", note="2")
        aceg3 = AceGroup(items=[Ace("permit tcp any any eq 3", note="3")], note="3")
        aceg4 = AceGroup(items=[Ace("permit tcp any any eq 4", note="4")], note="4")
        # noinspection PyTypeChecker
        aceg3.items.append(aceg4)
        obj = Acl(items=[remark1, ace2, aceg3], note="0")

        obj.delete_note()
        for item in obj.items:
            self.assertEqual(item.note, "", msg="delete_note")
            if hasattr(item, "items"):
                for item2 in item.items:
                    self.assertEqual(item2.note, "", msg="delete_note")
                    if hasattr(item2, "items"):
                        for item3 in item2.items:
                            self.assertEqual(item3.note, "", msg="delete_note")

    def test_valid__group(self):
        """Acl.group()"""
        for line, req_acegs_d in [
            (h2.LINE_GROUP_ACEGS, h2.REQ_GROUPS_ACEGS_D),
            (h2.LINE_GROUP_REMARKS, h2.REQ_GROUP_REMARKS_D),
            (h2.LINE_DUPLICATE_REMARKS_UNGROUPED, h2.REQ_DUPLICATE_REMARKS),
        ]:
            acl_o = Acl(line, platform="ios")
            acl_o.group(group_by="=== ")
            result = acl_o.data()
            diff = list(dictdiffer.diff(first=result, second=req_acegs_d))
            self.assertEqual(diff, [], msg=f"{line=}")

    def test_valid__resequence(self):
        """Acl.resequence()"""
        aces_0 = f"{ACL_NAME_IOS}\n  {PERMIT_IP}\n  {DENY_IP}\n  {REMARK}"
        aces_10 = f"{ACL_NAME_IOS}\n  10 {PERMIT_IP}\n  20 {DENY_IP}\n  30 {REMARK}"
        aces_2_3 = f"{ACL_NAME_IOS}\n  2 {PERMIT_IP}\n  5 {DENY_IP}\n  8 {REMARK}"
        group_0 = f"{ACL_NAME_IOS}\n  remark = C-1\n  {PERMIT_IP}\n  {REMARK}"
        group_10 = f"{ACL_NAME_IOS}\n  10 remark = C-1\n  20 {PERMIT_IP}\n  30 {REMARK}"

        for line, kwargs, req in [
            (aces_0, {}, aces_10),
            (aces_0, dict(start=2, step=3), aces_2_3),
            (aces_10, dict(start=0), aces_0),
            (aces_10, dict(start=0, step=3), aces_0),
            (group_0, {}, group_10),
            (group_10, dict(start=0), group_0),
        ]:
            obj = Acl(line, group_by="= ")
            obj.resequence(**kwargs)
            result = obj.line
            self.assertEqual(result, req, msg=f"{line=} {kwargs=}")
            # sequence after copy
            obj2 = obj.copy()
            result = obj2.line
            self.assertEqual(result, req, msg=f"{line=} {kwargs=}")

    def test_invalid__resequence(self):
        """Acl.resequence()"""
        for kwargs, error in [
            (dict(start=4294967296), ValueError),
            (dict(step=0), ValueError),
            (dict(step=4294967296), ValueError),
        ]:
            obj = Acl(f"{ACL_NAME_IOS}\n{PERMIT_IP2}\n{DENY_IP1}")
            with self.assertRaises(error, msg=f"{kwargs=}"):
                obj.resequence(**kwargs)

    def test_delete_shadow(self):
        """Acl.delete_shadow()"""
        line1 = """permit ip 10.0.0.0/30 any
                   permit ip 10.0.0.0/31 any
                   permit ip 10.0.0.0/32 any"""
        result1 = ["permit ip 10.0.0.0/30 any"]
        line2 = """permit ip 10.0.0.0/30 any
                   permit ip 10.0.0.4/30 any
                   remark === NAME1
                   permit ip 10.0.0.8/30 any
                   permit ip 10.0.0.0/31 any
                   remark === NAME2
                   permit ip 10.0.0.0/24 any
                   permit ip 10.0.0.1/32 any
                   permit ip 10.0.0.4/30 any
                   permit ip 10.0.0.8/30 any
                   remark TEXT1
                   permit ip 10.0.0.8/32 any"""
        result2 = ["permit ip 10.0.0.0/30 any\npermit ip 10.0.0.4/30 any",
                   "remark === NAME1\npermit ip 10.0.0.8/30 any",
                   "remark === NAME2\npermit ip 10.0.0.0/24 any\nremark TEXT1"]

        for line, req in [
            (line1, result1),
            (line2, result2),
        ]:
            acl_o = make_acl(line)
            acl_o.delete_shadow()
            result = [o.line for o in acl_o.items]
            self.assertEqual(result, req, msg=f"{line=}")

    def test_valid__delete_shadow_2(self):
        """RulesForAcl._delete_shadow() with multiple rules"""
        ip_ = [PERMIT_IP]
        tcp_ip = [PERMIT_TCP, PERMIT_IP]
        tcp1_ip = [PERMIT_TCP1, PERMIT_IP]
        tcp = [PERMIT_TCP]
        tcp_udp = [PERMIT_TCP, PERMIT_UDP]
        tcp_udp1 = [PERMIT_TCP, PERMIT_UDP1]
        for top, middle, bottom, req, req_aces in [
            # ip        ip          any
            (PERMIT_IP, PERMIT_IP, PERMIT_IP, {PERMIT_IP: [PERMIT_IP]}, ip_),
            (PERMIT_IP, PERMIT_IP, PERMIT_TCP, {PERMIT_IP: [PERMIT_IP, PERMIT_TCP]}, ip_),
            (PERMIT_IP, PERMIT_IP, PERMIT_UDP, {PERMIT_IP: [PERMIT_IP, PERMIT_UDP]}, ip_),
            (PERMIT_IP, PERMIT_IP, PERMIT_TCP1, {PERMIT_IP: [PERMIT_IP, PERMIT_TCP1]}, ip_),
            (PERMIT_IP, PERMIT_IP, PERMIT_UDP1, {PERMIT_IP: [PERMIT_IP, PERMIT_UDP1]}, ip_),
            # ip        tcp         any
            (PERMIT_IP, PERMIT_TCP, PERMIT_IP, {PERMIT_IP: [PERMIT_TCP, PERMIT_IP]}, ip_),
            (PERMIT_IP, PERMIT_TCP, PERMIT_TCP, {PERMIT_IP: [PERMIT_TCP]}, ip_),
            (PERMIT_IP, PERMIT_TCP, PERMIT_UDP, {PERMIT_IP: [PERMIT_TCP, PERMIT_UDP]}, ip_),
            (PERMIT_IP, PERMIT_TCP, PERMIT_TCP1, {PERMIT_IP: [PERMIT_TCP, PERMIT_TCP1]}, ip_),
            (PERMIT_IP, PERMIT_TCP, PERMIT_UDP1, {PERMIT_IP: [PERMIT_TCP, PERMIT_UDP1]}, ip_),
            # tcp       ip          any
            (PERMIT_TCP, PERMIT_IP, PERMIT_IP, {PERMIT_IP: [PERMIT_IP]}, tcp_ip),
            (PERMIT_TCP, PERMIT_IP, PERMIT_TCP, {PERMIT_TCP: [PERMIT_TCP]}, tcp_ip),
            (PERMIT_TCP, PERMIT_IP, PERMIT_UDP, {PERMIT_IP: [PERMIT_UDP]}, tcp_ip),
            (PERMIT_TCP, PERMIT_IP, PERMIT_TCP1, {PERMIT_TCP: [PERMIT_TCP1]}, tcp_ip),
            (PERMIT_TCP, PERMIT_IP, PERMIT_UDP1, {PERMIT_IP: [PERMIT_UDP1]}, tcp_ip),
            # tcp       tcp_         any
            (PERMIT_TCP, PERMIT_TCP, PERMIT_IP, {PERMIT_TCP: [PERMIT_TCP]}, tcp_ip),
            (PERMIT_TCP, PERMIT_TCP, PERMIT_TCP, {PERMIT_TCP: [PERMIT_TCP]}, tcp),
            (PERMIT_TCP, PERMIT_TCP, PERMIT_UDP, {PERMIT_TCP: [PERMIT_TCP]}, tcp_udp),
            (PERMIT_TCP, PERMIT_TCP, PERMIT_TCP1, {PERMIT_TCP: [PERMIT_TCP, PERMIT_TCP1]}, tcp),
            (PERMIT_TCP, PERMIT_TCP, PERMIT_UDP1, {PERMIT_TCP: [PERMIT_TCP]}, tcp_udp1),
            # tcp=1     ip          any
            (PERMIT_TCP1, PERMIT_IP, PERMIT_IP, {PERMIT_IP: [PERMIT_IP]}, tcp1_ip),
            (PERMIT_TCP1, PERMIT_IP, PERMIT_TCP, {PERMIT_IP: [PERMIT_TCP]}, tcp1_ip),
            (PERMIT_TCP1, PERMIT_IP, PERMIT_UDP, {PERMIT_IP: [PERMIT_UDP]}, tcp1_ip),
            (PERMIT_TCP1, PERMIT_IP, PERMIT_TCP1, {PERMIT_TCP1: [PERMIT_TCP1]}, tcp1_ip),
            (PERMIT_TCP1, PERMIT_IP, PERMIT_TCP2, {PERMIT_IP: [PERMIT_TCP2]}, tcp1_ip),
            (PERMIT_TCP1, PERMIT_IP, PERMIT_UDP1, {PERMIT_IP: [PERMIT_UDP1]}, tcp1_ip),
        ]:
            line = f"ip access-list NAME\n {top}\n {middle}\n {bottom}"
            acl_o = Acl(line, platform="nxos")

            result = acl_o.delete_shadow()
            self.assertEqual(result, req, msg=f"{top=} {middle=} {bottom=}")

            result_ = [o.line for o in acl_o.items]
            self.assertEqual(result_, req_aces, msg=f"{top=} {middle=} {bottom=}")

    def test_valid__shading(self):
        """Acl.shading() Acl.shadow_of()"""
        for line, req_d in [
            (PERMIT_IP, {}),
            # protocol
            (f"{PERMIT_IP}\n{PERMIT_IP}", {PERMIT_IP: [PERMIT_IP]}),
            (f"{PERMIT_IP}\n{PERMIT_ICMP}", {PERMIT_IP: [PERMIT_ICMP]}),
            (f"{PERMIT_IP}\n{PERMIT_NAM}", {PERMIT_IP: [PERMIT_NAM]}),
            (f"{PERMIT_ICMP}\n{PERMIT_IP}", {}),
            (f"{PERMIT_ICMP}\n{PERMIT_ICMP}", {PERMIT_ICMP: [PERMIT_ICMP]}),
            (f"{PERMIT_ICMP}\n{PERMIT_NAM}", {}),
            (f"{PERMIT_NAM}\n{PERMIT_IP}", {}),
            (f"{PERMIT_NAM}\n{PERMIT_ICMP}", {}),
            (f"{PERMIT_NAM}\n{PERMIT_NAM}", {PERMIT_NAM: [PERMIT_NAM]}),
            # srcaddr
            (f"permit ip {PREFIX30} {PREFIX30}\n{PERMIT_IP}", {}),
            (f"permit ip {PREFIX30} any\npermit ip {PREFIX24} any", {}),
            (f"permit ip {PREFIX30} any\npermit ip {PREFIX30} any",
             {f"permit ip {PREFIX30} any": [f"permit ip {PREFIX30} any"]}),
            (f"permit ip {PREFIX30} any\npermit ip {PREFIX32} any",
             {f"permit ip {PREFIX30} any": [f"permit ip {HOST} any"]}),
            (f"permit ip {PREFIX30} any\npermit ip 10.0.0.2/32 any",
             {f"permit ip {PREFIX30} any": ["permit ip host 10.0.0.2 any"]}),
            (f"permit ip {WILD_NC3} any\npermit ip 10.0.0.2/32 any\npermit ip 10.0.1.2/32 any",
             {f"permit ip {WILD_NC3} any": ["permit ip host 10.0.0.2 any",
                                            "permit ip host 10.0.1.2 any"]}),
            # tcp port
            ("permit tcp any eq 1 any\npermit tcp any eq 1 any",
             {"permit tcp any eq 1 any": ["permit tcp any eq 1 any"]}),
            ("permit tcp any eq 1 any\npermit tcp any eq 2 any", {}),
            ("permit tcp any eq 1 any\npermit tcp any any eq 1", {}),
            ("permit tcp any eq 1 any\npermit tcp any any eq 2", {}),
            ("permit tcp any any eq 1\npermit tcp any eq 1 any", {}),
            ("permit tcp any any eq 1\npermit tcp any eq 2 any", {}),
            ("permit tcp any any eq 1\npermit tcp any any eq 1",
             {"permit tcp any any eq 1": ["permit tcp any any eq 1"]}),
            ("permit tcp any any eq 1\npermit tcp any any eq 2", {}),
            # # combo
            (f"permit tcp {PREFIX30} any\n"
             f"permit tcp {PREFIX31} any\n"
             f"permit tcp {PREFIX24} any\n"
             f"permit tcp {PREFIX32} any\n",
             {f"permit tcp {PREFIX30} any": [f"permit tcp {PREFIX31} any",
                                             f"permit tcp {HOST} any"]}),
            (f"permit tcp {PREFIX30} any\npermit udp {PREFIX30} any\n"
             f"permit tcp {PREFIX31} any\npermit udp {PREFIX31} any\n"
             f"permit tcp {PREFIX24} any\npermit udp {PREFIX24} any\n"
             f"permit tcp {PREFIX32} any\npermit udp {PREFIX32} any",
             {f"permit tcp {PREFIX30} any": [f"permit tcp {PREFIX31} any",
                                             f"permit tcp {HOST} any"],
              f"permit udp {PREFIX30} any": [f"permit udp {PREFIX31} any",
                                             f"permit udp {HOST} any"]}),
        ]:
            line = f"{ACL_NAME_CNX}\n{line}"
            obj = Acl(line, platform="nxos")
            # shading
            result = obj.shading()
            diff = list(dictdiffer.diff(first=result, second=req_d))
            self.assertEqual(diff, [], msg=f"{line=}")
            # shadow
            result_ = obj.shadow_of()
            req = [s for ls in req_d.values() for s in ls]
            self.assertEqual(result_, req, msg=f"{line=}")

    def test_valid__sort(self):
        """Acl.sort()"""
        for line, req in [
            (f"{ACL_NAME_IOS}\n{DENY_IP}\n{PERMIT_IP}", [DENY_IP, PERMIT_IP]),
            (f"{ACL_NAME_IOS}\n{PERMIT_IP}\n{DENY_IP}", [DENY_IP, PERMIT_IP]),
        ]:
            obj = Acl(line)
            obj.items.sort()
            result = [str(o) for o in obj.items]
            self.assertEqual(result, req, msg=f"{obj=}")

    def test_valid__split_ports(self):
        """Acl.split_ports()"""
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
            obj = make_acl(line, platform="ios")
            obj.ungroup_ports()
            result = obj.line
            result = remove_acl_name(result)
            self.assertEqual(result, req, msg=f"{line=}")

        # AceGroup
        line = "permit tcp any eq 1 2 any eq 3 4"
        obj = Acl(items=[AceGroup(line, platform="ios", name="NAME")])
        obj.ungroup_ports()
        result = obj.items[0].line
        req = "permit tcp any eq 1 any eq 3\n" \
              "permit tcp any eq 1 any eq 4\n" \
              "permit tcp any eq 2 any eq 3\n" \
              "permit tcp any eq 2 any eq 4"
        self.assertEqual(result, req, msg=f"{line=}")

    def test_valid__tcam_count(self):
        """AceGroup.tcam_count()"""
        addrs = [Address(WILD30), Address(WILD_NC3), Address(HOST)]
        for line, req in [
            (REMARK, 1),
            (PERMIT_IP, 2),
            (f"{REMARK}\n{PERMIT_TCP1}\n{REMARK}\n{PERMIT_IP}\n", 3),
            ("permit ip object-group NAME any", 4),
            ("permit ip any object-group NAME", 4),
            ("permit ip object-group NAME object-group NAME", 10),
        ]:
            obj = Acl(f"{ACL_NAME_IOS}\n{line}")
            for item in obj.items:
                if isinstance(item, Ace) and req:
                    if item.srcaddr.type == "addrgroup":
                        item.srcaddr.items = addrs
                    if item.dstaddr.type == "addrgroup":
                        item.dstaddr.items = addrs

            result = obj.tcam_count()
            self.assertEqual(result, req, msg=f"{line=}")

    def test_valid__ungroup(self):
        """Acl.ungroup() Acl._ungroup()"""
        acl1 = Acl(f"{ACL_NAME_IOS}\n{REMARK}\n{DENY_IP}\n{PERMIT_IP}")
        acl2 = Acl(f"{ACL_NAME_IOS}\nremark =A\n{REMARK}\n{DENY_IP}\nremark =C\n{PERMIT_IP}",
                   group_by="=")

        for obj, req in [
            (acl1, [REMARK, DENY_IP, PERMIT_IP]),
            (acl2, ["remark =A", REMARK, DENY_IP, "remark =C", PERMIT_IP]),
        ]:
            obj.ungroup()
            result = [o.line for o in obj.items]
            self.assertEqual(result, req, msg=f"{obj=}")

    # =========================== helper =============================

    def test_valid__cfg_acl_name(self):
        """Acl._cfg_acl_name()"""
        for platform, req in [
            ("ios", ACL_NAME_IOS),
            ("nxos", "ip access-list NAME"),
        ]:
            obj = Acl(name="NAME", platform=platform)
            result = obj._cfg_acl_name()
            self.assertEqual(result, req, msg=f"{platform=}")


if __name__ == "__main__":
    unittest.main()
