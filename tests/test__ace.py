"""Unittest ace.py"""
# pylint: disable=too-many-lines
import re
import unittest

import dictdiffer  # type: ignore

from cisco_acl import Ace, Remark
from cisco_acl.address import Address
from tests.helpers_test import (
    DENY_IP,
    DENY_IP1,
    Helpers,
    PERMIT_IP,
    PERMIT_IP1,
    PERMIT_IP2,
    PREFIX30,
    REMARK,
    UUID,
    WILD30,
)
from tests.test__ace__helpers import REQ_DATA1, REQ_COPY1, REQ_COPY2


# noinspection DuplicatedCode
class Test(Helpers):
    """Ace"""

    # ========================== redefined ===========================

    def test_valid__hash__(self):
        """Ace.__hash__()"""
        line = PERMIT_IP
        obj = Ace(line)
        result = obj.__hash__()
        req = line.__hash__()
        self.assertEqual(result, req, msg=f"{line=}")

    def test_valid__eq__(self):
        """Ace.__eq__() __ne__()"""
        obj1 = Ace(PERMIT_IP1)
        for obj2, req, in [
            (Ace(PERMIT_IP1), True),
            (Ace(PERMIT_IP2), False),
            (Ace(DENY_IP1), False),
            (Remark(REMARK), False),
            (PERMIT_IP1, False),
        ]:
            result = obj1.__eq__(obj2)
            self.assertEqual(result, req, msg=f"{obj1=} {obj2=}")
            result = obj1.__ne__(obj2)
            self.assertEqual(result, not req, msg=f"{obj1=} {obj2=}")

    def test_valid__lt__(self):
        """Ace.__lt__() __le__() __gt__() __ge__()"""
        for obj1, obj2, req_lt, req_le, req_gt, req_ge in [
            (Ace(PERMIT_IP), Ace(PERMIT_IP), False, True, False, True),
            (Ace(PERMIT_IP), Ace(DENY_IP), False, False, True, True),
            (Ace(PERMIT_IP1), Ace(PERMIT_IP2), True, True, False, False),
            (Ace(PERMIT_IP2), Ace(DENY_IP1), False, False, True, True),
        ]:
            result = obj1.__lt__(obj2)
            self.assertEqual(result, req_lt, msg=f"{obj1=} {obj2=}")
            result = obj1.__le__(obj2)
            self.assertEqual(result, req_le, msg=f"{obj1=} {obj2=}")
            result = obj1.__gt__(obj2)
            self.assertEqual(result, req_gt, msg=f"{obj1=} {obj2=}")
            result = obj1.__ge__(obj2)
            self.assertEqual(result, req_ge, msg=f"{obj1=} {obj2=}")

    def test_valid__lt__sort(self):
        """Ace.__lt__(), Ace.__le__()"""
        for items in [
            # action
            [Remark("remark TEXT"), Remark("remark TEXT2")],
            [Remark("remark TEXT"), Ace("permit ip any any")],
            [Remark("remark TEXT"), Ace("deny ip any any")],
            [Ace("deny ip any any"), Ace("permit ip any any")],
            # protocol
            [Ace("permit ip any any"), Ace("permit ahp any any")],
            # srcaddr
            [Ace("permit ip any any"), Ace("permit ip 1.1.1.0 0.0.0.255 any")],
            [Ace("permit ip any any"), Ace("permit ip 1.1.1.0 0.0.0.3 any")],
            [Ace("permit ip any any"), Ace("permit ip host 1.1.1.1 any")],
            [Ace("permit ip any any"), Ace("permit ip object-group NAME any")],
            [Ace("permit ip 1.1.1.0 0.0.0.255 any"), Ace("permit ip 1.1.1.0 0.0.0.3 any")],
            [Ace("permit ip 1.1.1.0 0.0.0.255 any"), Ace("permit ip host 1.1.1.1 any")],
            [Ace("permit ip 1.1.1.0 0.0.0.255 any"), Ace("permit ip object-group NAME any")],
            [Ace("permit ip 1.1.1.0 0.0.0.3 any"), Ace("permit ip host 1.1.1.1 any")],
            [Ace("permit ip 1.1.1.0 0.0.0.3 any"), Ace("permit ip object-group NAME any")],
            [Ace("permit ip host 1.1.1.1 any"), Ace("permit ip object-group NAME any")],
            [Ace("permit ip object-group NAME1 any"), Ace("permit ip object-group NAME2 any")],
            # srcport
            [Ace("permit tcp any eq 1 any"), Ace("permit tcp any eq 2 any")],
            [Ace("permit tcp any eq 1 any"), Ace("permit tcp any gt 1 any")],
            [Ace("permit tcp any eq 1 any"), Ace("permit tcp any lt 1 any")],
            [Ace("permit tcp any eq 1 any"), Ace("permit tcp any neq 1 any")],
            [Ace("permit tcp any eq 1 any"), Ace("permit tcp any range 1 3 any")],
            [Ace("permit tcp any gt 1 any"), Ace("permit tcp any lt 1 any")],
            [Ace("permit tcp any gt 1 any"), Ace("permit tcp any neq 1 any")],
            [Ace("permit tcp any gt 1 any"), Ace("permit tcp any range 1 3 any")],
            [Ace("permit tcp any lt 1 any"), Ace("permit tcp any neq 1 any")],
            [Ace("permit tcp any lt 1 any"), Ace("permit tcp any range 1 3 any")],
            [Ace("permit tcp any neq 1 any"), Ace("permit tcp any range 1 3 any")],
            [Ace("permit tcp any eq 2 any"), Ace("permit tcp any eq 3 any")],
            [Ace("permit tcp any range 3 5 any"), Ace("permit tcp any range 3 6 any")],
            # dstaddr
            [Ace("permit ip any any"), Ace("permit ip any 1.1.1.0 0.0.0.255")],
            [Ace("permit ip any any"), Ace("permit ip any 1.1.1.0 0.0.0.3")],
            [Ace("permit ip any any"), Ace("permit ip any host 1.1.1.1")],
            [Ace("permit ip any any"), Ace("permit ip any object-group NAME")],
            [Ace("permit ip any 1.1.1.0 0.0.0.255"), Ace("permit ip any 1.1.1.0 0.0.0.3")],
            [Ace("permit ip any 1.1.1.0 0.0.0.255"), Ace("permit ip any host 1.1.1.1")],
            [Ace("permit ip any 1.1.1.0 0.0.0.255"), Ace("permit ip any object-group NAME")],
            [Ace("permit ip any 1.1.1.0 0.0.0.3"), Ace("permit ip any host 1.1.1.1")],
            [Ace("permit ip any 1.1.1.0 0.0.0.3"), Ace("permit ip any object-group NAME")],
            [Ace("permit ip any host 1.1.1.1"), Ace("permit ip any object-group NAME")],
            [Ace("permit ip any object-group NAME1"), Ace("permit ip any object-group NAME2")],
            # dstport
            [Ace("permit tcp any any eq 1"), Ace("permit tcp any any eq 2")],
            [Ace("permit tcp any any eq 1"), Ace("permit tcp any any gt 1")],
            [Ace("permit tcp any any eq 1"), Ace("permit tcp any any lt 1")],
            [Ace("permit tcp any any eq 1"), Ace("permit tcp any any neq 1")],
            [Ace("permit tcp any any eq 1"), Ace("permit tcp any any range 1 3")],
            [Ace("permit tcp any any gt 1"), Ace("permit tcp any any lt 1")],
            [Ace("permit tcp any any gt 1"), Ace("permit tcp any any neq 1")],
            [Ace("permit tcp any any gt 1"), Ace("permit tcp any any range 1 3")],
            [Ace("permit tcp any any lt 1"), Ace("permit tcp any any neq 1")],
            [Ace("permit tcp any any lt 1"), Ace("permit tcp any any range 1 3")],
            [Ace("permit tcp any any neq 1"), Ace("permit tcp any any range 1 3")],
            [Ace("permit tcp any any eq 2"), Ace("permit tcp any any eq 3")],
            [Ace("permit tcp any any range 3 5"), Ace("permit tcp any any range 3 6")],
            # option
            [Ace("permit ip any any ack"), Ace("permit ip any any log")],
            [Ace("permit tcp any eq 1 any eq 1 ack"), Ace("permit tcp any eq 1 any eq 1 log")],
        ]:
            req = items.copy()
            result = sorted(items)
            self.assertEqual(result, req, msg=f"{items=}")
            items[0], items[1] = items[1], items[0]
            result = sorted(items)
            self.assertEqual(result, req, msg=f"{items=}")

    def test_valid__repr__(self):
        """Ace.__repr__()"""
        for kwargs, req in [
            (dict(line=PERMIT_IP1, platform="ios", note=""), "Ace(\"1 permit ip any any\")"),
            (dict(line=PERMIT_IP1, platform="nxos", note="a", protocol_nr=True, port_nr=True),
             "Ace(\"1 permit 0 any any\", platform=\"nxos\", note=\"a\", "
             "protocol_nr=True, port_nr=True)"),
        ]:
            obj = Ace(**kwargs)
            result = obj.__repr__()
            result = self._quotation(result)
            self.assertEqual(result, req, msg=f"{result=}")

    # =========================== property ===========================

    def test_valid__line(self):
        """Ace.line"""
        icmp = "permit icmp any any"
        icmp_pr = "permit 1 any any"
        icmp_d = dict(line=icmp,
                      sequence=0,
                      action="permit",
                      protocol="icmp",
                      srcaddr="any",
                      srcport="",
                      dstaddr="any",
                      dstport="",
                      option="")
        icmp_pr_d = {**icmp_d, **{"line": icmp_pr, "protocol": "1"}}

        tcp = "permit tcp any eq ftp 443 object-group NAME neq cmd ack log"
        tcp_10 = f"10 {tcp}"
        tcp_dirty = "  " + "\t".join(tcp.split()) + "\n"
        tcp_n = "permit tcp any eq 21 443 object-group NAME neq 514 ack log"

        tcp_d = dict(line=tcp,
                     sequence=0,
                     action="permit",
                     protocol="tcp",
                     srcaddr="any",
                     srcport="eq ftp 443",
                     dstaddr="object-group NAME",
                     dstport="neq cmd",
                     option="ack log")
        tcp_10_d = {**tcp_d, **{"line": tcp_10, "sequence": 10}}
        tcp_n_d = {**tcp_d,
                   **{"line": tcp_n, "srcport": "eq 21 443", "dstport": "neq 514"}}

        udp = "deny udp host 1.1.1.1 lt syslog 2.2.2.0 0.0.0.3 range bootps tftp"
        udp_n = "deny udp host 1.1.1.1 lt 514 2.2.2.0 0.0.0.3 range 67 69"
        udp_d = dict(line=udp,
                     sequence=0,
                     action="deny",
                     protocol="udp",
                     srcaddr="host 1.1.1.1",
                     srcport="lt syslog",
                     dstaddr="2.2.2.0 0.0.0.3",
                     dstport="range bootps tftp",
                     option="")
        udp_n_d = {**udp_d,
                   **{"line": udp_n, "srcport": "lt 514", "dstport": "range 67 69"}}

        prefix0 = "permit ip 0.0.0.0/0 0.0.0.0/0"
        any_d = dict(line=PERMIT_IP,
                     sequence=0,
                     action="permit",
                     protocol="ip",
                     srcaddr="any",
                     srcport="",
                     dstaddr="any",
                     dstport="",
                     option="")

        for kwargs, req_d in [
            # indexes
            (dict(line=icmp), icmp_d),
            (dict(line=icmp_pr), icmp_d),
            (dict(line=tcp), tcp_d),
            (dict(line=tcp_10), tcp_10_d),
            (dict(line=tcp_dirty), tcp_d),
            (dict(line=tcp_n), tcp_d),
            (dict(line=udp), udp_d),
            (dict(line=udp_n), udp_d),
            # protocol_nr
            (dict(line=icmp, protocol_nr=True), icmp_pr_d),
            (dict(line=icmp_pr, protocol_nr=True), icmp_pr_d),
            (dict(line=tcp, protocol_nr=True), tcp_d),
            (dict(line=tcp_n, protocol_nr=True), tcp_d),
            (dict(line=udp, protocol_nr=True), udp_d),
            (dict(line=udp_n, protocol_nr=True), udp_d),
            # port_nr
            (dict(line=icmp, port_nr=True), icmp_d),
            (dict(line=icmp_pr, port_nr=True), icmp_d),
            (dict(line=tcp, port_nr=True), tcp_n_d),
            (dict(line=tcp_n, port_nr=True), tcp_n_d),
            (dict(line=udp, port_nr=True), udp_n_d),
            (dict(line=udp_n, port_nr=True), udp_n_d),
            # protocol_nr port_nr
            (dict(line=icmp, protocol_nr=True, port_nr=True), icmp_pr_d),
            (dict(line=icmp_pr, protocol_nr=True, port_nr=True), icmp_pr_d),
            (dict(line=tcp, protocol_nr=True, port_nr=True), tcp_n_d),
            (dict(line=tcp_n, protocol_nr=True, port_nr=True), tcp_n_d),
            (dict(line=udp, protocol_nr=True, port_nr=True), udp_n_d),
            (dict(line=udp_n, protocol_nr=True, port_nr=True), udp_n_d),
            # convert 0.0.0.0/0 to any
            (dict(line=prefix0, platform="nxos"), any_d),
        ]:
            obj = Ace(**kwargs)
            self._test_attrs(obj=obj, req_d=req_d, msg=f"{kwargs=}")
            # setter
            line = kwargs["line"]
            obj.line = line
            self._test_attrs(obj=obj, req_d=req_d, msg=f"{line=}")

    def test_invalid__line(self):
        """Ace.line"""
        for line, error in [
            ("permit ip any eq 1 any", ValueError),
            ("permit ip any any eq 1", ValueError),
            (REMARK, ValueError),
            (f"10 {REMARK}", ValueError),
            ({}, TypeError),
            ("", ValueError),
            ("typo", ValueError),
        ]:
            with self.assertRaises(error, msg=f"{line=}"):
                Ace(line)

    def test_valid__port_nr(self):
        """Ace.port_nr"""
        line_num = "10 permit tcp host 10.0.0.1 range 21 23 10.0.0.0 0.0.0.3 eq 80 443 log"
        line_name = "10 permit tcp host 10.0.0.1 range ftp telnet 10.0.0.0 0.0.0.3 eq www 443 log"
        for port_nr, req in [
            (True, line_num),
            (False, line_name),
        ]:
            before = not port_nr
            obj = Ace(line=line_name, port_nr=before)
            obj.port_nr = port_nr
            result = obj.line
            self.assertEqual(result, req, msg=f"{port_nr=}")

    def test_valid__platform(self):
        """Ace.platform"""
        prefix00 = "permit ip 0.0.0.0/0 0.0.0.0/0"
        prefix30 = "permit ip 10.0.0.0/30 10.0.0.0/30"
        prefix32 = "permit ip host 10.0.0.1 host 10.0.0.1"
        wild00 = "permit ip 0.0.0.0 255.255.255.255 0.0.0.0 255.255.255.255"
        wild30 = "permit ip 10.0.0.0 0.0.0.3 10.0.0.0 0.0.0.3"
        wild32 = "permit ip 10.0.0.1 0.0.0.0 10.0.0.1 0.0.0.0"
        wild_3_3 = "permit ip 10.0.0.0 0.0.3.3 10.0.0.0 0.0.3.3"
        wild_252 = "permit ip 0.0.0.0 255.255.255.252 0.0.0.0 255.255.255.252"
        host = "permit ip host 10.0.0.1 host 10.0.0.1"
        any_ = "permit ip any any"
        ios_addgr = "deny ip object-group A object-group B"
        cnx_addgr = "deny ip addrgroup A addrgroup B"
        eq_neq = "permit tcp any eq 1 any neq 3 log"
        gt_lt = "permit tcp any gt 65533 any lt 3 log"

        for platform, platform_new, line, req, req_new in [
            # ios to ios
            ("ios", "ios", wild00, any_, any_),
            ("ios", "ios", wild30, wild30, wild30),
            ("ios", "ios", wild32, host, host),
            ("ios", "ios", wild_3_3, wild_3_3, wild_3_3),
            ("ios", "ios", wild_252, wild_252, wild_252),
            ("ios", "ios", host, host, host),
            ("ios", "ios", any_, any_, any_),
            ("ios", "ios", ios_addgr, ios_addgr, ios_addgr),
            ("ios", "ios", eq_neq, eq_neq, eq_neq),
            ("ios", "ios", gt_lt, gt_lt, gt_lt),
            # ios to nxos
            ("ios", "nxos", wild00, any_, any_),
            ("ios", "nxos", wild30, wild30, prefix30),
            ("ios", "nxos", wild32, host, host),
            ("ios", "nxos", wild_3_3, wild_3_3, wild_3_3),
            ("ios", "nxos", wild_252, wild_252, wild_252),
            ("ios", "nxos", host, host, host),
            ("ios", "nxos", any_, any_, any_),
            ("ios", "nxos", ios_addgr, ios_addgr, cnx_addgr),
            ("ios", "nxos", eq_neq, eq_neq, eq_neq),
            ("ios", "nxos", gt_lt, gt_lt, gt_lt),
            # nxos to nxos
            ("nxos", "nxos", prefix00, any_, any_),
            ("nxos", "nxos", prefix30, prefix30, prefix30),
            ("nxos", "nxos", prefix32, host, host),
            ("nxos", "nxos", wild00, any_, any_),
            ("nxos", "nxos", wild30, prefix30, prefix30),
            ("nxos", "nxos", wild32, host, host),
            ("nxos", "nxos", wild_3_3, wild_3_3, wild_3_3),
            ("nxos", "nxos", wild_252, wild_252, wild_252),
            ("nxos", "nxos", host, host, host),
            ("nxos", "nxos", any_, any_, any_),
            ("nxos", "nxos", cnx_addgr, cnx_addgr, cnx_addgr),
            ("nxos", "nxos", eq_neq, eq_neq, eq_neq),
            ("nxos", "nxos", gt_lt, gt_lt, gt_lt),
            # nxos to ios
            ("nxos", "ios", prefix00, any_, any_),
            ("nxos", "ios", prefix30, prefix30, wild30),
            ("nxos", "ios", prefix32, host, host),
            ("nxos", "ios", wild00, any_, any_),
            ("nxos", "ios", wild30, prefix30, wild30),
            ("nxos", "ios", wild32, host, host),
            ("nxos", "ios", wild_3_3, wild_3_3, wild_3_3),
            ("nxos", "ios", wild_252, wild_252, wild_252),
            ("nxos", "ios", host, host, host),
            ("nxos", "ios", any_, any_, any_),
            ("nxos", "ios", cnx_addgr, cnx_addgr, ios_addgr),
            ("nxos", "ios", eq_neq, eq_neq, eq_neq),
            ("nxos", "ios", gt_lt, gt_lt, gt_lt),
        ]:
            msg = f"{platform=} {platform_new=} {line=}"
            obj = Ace(line, platform=platform, max_ncwb=30)
            result = obj.line
            self.assertEqual(result, req, msg=msg)

            # platform
            obj.platform = platform_new
            result = obj.line
            self.assertEqual(result, req_new, msg=msg)

    def test_valid__platform__addrgroup_items(self):
        """Ace.platform"""
        ios_addgr = "permit ip object-group A object-group A"
        cnx_addgr = "permit ip addrgroup A addrgroup A"
        for platform, line, items, platform_new, req in [
            ("ios", ios_addgr, [WILD30], "ios", [WILD30]),
            ("ios", ios_addgr, [WILD30], "cnx", [PREFIX30]),
            ("cnx", cnx_addgr, [PREFIX30], "cnx", [PREFIX30]),
            ("cnx", cnx_addgr, [PREFIX30], "ios", [WILD30]),
        ]:
            msg = f"{platform=} {line=} {items=} {platform_new=}"
            obj = Ace(line, platform=platform)
            obj.srcaddr.items = [Address(s, platform=platform) for s in items]
            obj.dstaddr.items = [Address(s, platform=platform) for s in items]
            for item in [*obj.srcaddr.items, *obj.dstaddr.items]:
                item.uuid = UUID

            obj.platform = platform_new
            result = [o.line for o in obj.srcaddr.items]
            self.assertEqual(result, req, msg=msg)
            result = [o.line for o in obj.dstaddr.items]
            self.assertEqual(result, req, msg=msg)
            # uids
            result_ = [o.uuid for o in obj.srcaddr.items]
            self.assertEqual(result_, [UUID], msg=msg)
            result_ = [o.uuid for o in obj.dstaddr.items]
            self.assertEqual(result_, [UUID], msg=msg)

    def test_invalid__platform(self):
        """Ace.platform"""
        for platform, platform_new, line, error in [
            ("ios", "typo", PERMIT_IP, ValueError),
            ("ios", "nxos", "permit tcp any eq 1 2 any", ValueError),
            ("ios", "nxos", "permit tcp any any eq 1 2", ValueError),
        ]:
            obj = Ace(line, platform=platform)
            with self.assertRaises(error, msg=f"{platform=} {platform_new=} {line=}"):
                obj.platform = platform_new

    def test_valid__type(self):
        """Ace.type"""
        host_ext = "permit tcp host 10.0.0.1 eq 1 host 10.0.0.2 eq 2 ack log"
        host_std = "permit host 10.0.0.1"
        host_ext_ = "permit ip host 10.0.0.1 any"
        wild_ext = "permit tcp 10.0.0.0 0.0.0.3 eq 1 10.0.0.4 0.0.0.3 eq 2 ack log"
        wild_std = "permit 10.0.0.0 0.0.0.3"
        wild_ext_ = "permit ip 10.0.0.0 0.0.0.3 any"
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
            obj = Ace(line, platform="ios", type=type_)
            obj.type = type_new
            result = obj.line
            self.assertEqual(result, req, msg=f"{type_=} {type_new=} {line=}")

    def test_invalid__type(self):
        """Ace.type"""
        addrgroup = "permit ip object-group NAME any"

        for platform, type_, type_new, line, error in [
            ("nxos", "extended", "standard", PERMIT_IP, ValueError),  # nxos
            ("ios", "extended", "standard", addrgroup, ValueError),  # addrgroup
        ]:
            obj = Ace(line, platform=platform, type=type_)
            with self.assertRaises(error, msg=f"{platform=} {type_=} {type_new=} {line=}"):
                obj.type = type_new

    # =========================== method =============================

    def test_valid__copy(self):
        """Ace.copy()"""
        obj1 = Ace(line="10 permit tcp host 10.0.0.1 10.0.0.0 0.0.0.3 eq www 443 log",
                   platform="ios", note="a", protocol_nr=True, port_nr=True)
        obj2 = obj1.copy()

        # change obj1 to check obj1 does not depend on obj2
        new_obj1_kwargs = dict(line="20 deny udp any eq 80 10.0.0.0 0.0.0.255 range 2 3",
                               note="b", protocol_nr=False, port_nr=False, platform="nxos")
        for arg, value in new_obj1_kwargs.items():
            setattr(obj1, arg, value)

        self._test_attrs(obj1, REQ_COPY1, msg="obj1 does not depend on obj2")
        self._test_attrs(obj2, REQ_COPY2, msg="obj2 copied from obj1")

    def test_valid__data(self):
        """Ace.data()"""
        line1 = "10 permit tcp host 10.0.0.1 10.0.0.0 0.0.0.3 eq 80 443 log"
        kwargs1 = dict(line=line1, platform="ios", note="a")
        req_uuid1 = [("remove", "protocol", [("uuid", "ID1")]),
                     ("remove", "srcaddr", [("uuid", "ID1")]),
                     ("remove", "srcport", [("uuid", "ID1")]),
                     ("remove", "dstaddr", [("uuid", "ID1")]),
                     ("remove", "dstport", [("uuid", "ID1")]),
                     ("remove", "option", [("uuid", "ID1")]),
                     ("remove", "", [("uuid", "ID1")])]

        for kwargs, req_d, req_uuid in [
            (kwargs1, REQ_DATA1, req_uuid1),
        ]:
            obj = Ace(**kwargs)
            obj.uuid = UUID
            obj.protocol.uuid = UUID
            obj.srcaddr.uuid = UUID
            obj.srcport.uuid = UUID
            obj.dstaddr.uuid = UUID
            obj.dstport.uuid = UUID
            obj.option.uuid = UUID
            for item in [*obj.srcaddr.items, *obj.dstaddr.items]:
                item.uuid = UUID

            result = obj.data()
            diff = list(dictdiffer.diff(first=result, second=req_d))
            self.assertEqual(diff, [], msg=f"{kwargs=}")

            result = obj.data(uuid=True)
            diff = list(dictdiffer.diff(first=result, second=req_d))
            self.assertEqual(diff, req_uuid, msg=f"{kwargs=}")

    def test_valid__shadow_of(self):
        """Ace.shadow_of()"""
        for top, bottom, req in [
            # protocol
            ("permit ip any any", "permit ip any any", True),
            ("permit ip any any", "permit icmp any any", True),
            ("permit ip any any", "permit tcp any any", True),
            ("permit icmp any any", "permit ip any any", False),
            ("permit icmp any any", "permit icmp any any", True),
            ("permit icmp any any", "permit tcp any any", False),
            ("permit icmp any any", "permit tcp any any ack", False),
            # tcp any
            ("permit tcp any any", "permit ip any any", False),
            ("permit tcp any any", "permit icmp any any", False),
            ("permit tcp any any", "permit tcp any any", True),
            ("permit tcp any any", "permit tcp any any ack", True),
            ("permit tcp any any", "permit tcp any eq 1 any", True),
            ("permit tcp any any", "permit tcp any neq 1 any", True),
            ("permit tcp any any", "permit tcp any gt 1 any", True),
            ("permit tcp any any", "permit tcp any lt 2 any", True),
            ("permit tcp any any", "permit tcp any range 1 2 any", True),
            ("permit tcp any any", "permit tcp any range 1 2 any", True),
            ("permit tcp any any", "permit udp any any", False),
            ("permit tcp any any", "permit udp any any ack", False),
            ("permit tcp any any", "permit udp any eq 1 any", False),
            ("permit tcp any any", "permit udp any neq 1 any", False),
            ("permit tcp any any", "permit udp any gt 1 any", False),
            ("permit tcp any any", "permit udp any lt 2 any", False),
            ("permit tcp any any", "permit udp any range 1 2 any", False),
            # udp any
            ("permit udp any any", "permit ip any any", False),
            ("permit udp any any", "permit icmp any any", False),
            ("permit udp any any", "permit tcp any any", False),
            ("permit udp any any", "permit tcp any any ack", False),
            ("permit udp any any", "permit tcp any eq 1 any", False),
            ("permit udp any any", "permit tcp any neq 1 any", False),
            ("permit udp any any", "permit tcp any gt 1 any", False),
            ("permit udp any any", "permit tcp any lt 2 any", False),
            ("permit udp any any", "permit tcp any range 1 2 any", False),
            ("permit udp any any", "permit tcp any range 1 2 any", False),
            ("permit udp any any", "permit udp any any", True),
            ("permit udp any any", "permit udp any eq 1 any", True),
            ("permit udp any any", "permit udp any neq 1 any", True),
            ("permit udp any any", "permit udp any gt 1 any", True),
            ("permit udp any any", "permit udp any lt 2 any", True),
            ("permit udp any any", "permit udp any range 1 2 any", True),

            # srcaddr prefix 0.0.0.0/0
            ("permit ip 0.0.0.0/0 any", "permit ip 0.0.0.0/0 any", True),
            ("permit ip 0.0.0.0/0 any", "permit ip 10.0.0.0/24 any", True),
            ("permit ip 0.0.0.0/0 any", "permit ip 10.0.1.0/24 any", True),
            ("permit ip 0.0.0.0/0 any", "permit ip 0.0.0.0 255.255.255.255 any", True),
            ("permit ip 0.0.0.0/0 any", "permit ip 10.0.0.0 0.0.0.255 any", True),
            ("permit ip 0.0.0.0/0 any", "permit ip 10.0.1.0 0.0.0.255 any", True),
            ("permit ip 0.0.0.0/0 any", "permit ip 10.0.0.0 0.0.0.3 any", True),
            ("permit ip 0.0.0.0/0 any", "permit ip 10.0.1.0 0.0.0.3 any", True),
            ("permit ip 0.0.0.0/0 any", "permit ip 10.0.0.1 0.0.0.0 any", True),
            ("permit ip 0.0.0.0/0 any", "permit ip 10.0.1.1 0.0.0.0 any", True),
            ("permit ip 0.0.0.0/0 any", "permit ip any any", True),
            ("permit ip 0.0.0.0/0 any", "permit ip host 10.0.0.1 any", True),
            ("permit ip 0.0.0.0/0 any", "permit ip host 10.0.1.1 any", True),
            ("permit ip 0.0.0.0/0 any", "permit ip 10.0.0.0 0.0.3.3 any", True),
            ("permit ip 0.0.0.0/0 any", "permit ip addrgroup NAME00 any", True),
            ("permit ip 0.0.0.0/0 any", "permit ip addrgroup NAME24_2 any", True),
            ("permit ip 0.0.0.0/0 any", "permit ip addrgroup NAME24 any", True),
            ("permit ip 0.0.0.0/0 any", "permit ip addrgroup NAME30 any", True),
            ("permit ip 0.0.0.0/0 any", "permit ip addrgroup NAME32 any", True),
            # srcaddr prefix 10.0.0.0/24
            ("permit ip 10.0.0.0/24 any", "permit ip 0.0.0.0/0 any", False),
            ("permit ip 10.0.0.0/24 any", "permit ip 10.0.0.0/24 any", True),
            ("permit ip 10.0.0.0/24 any", "permit ip 10.0.1.0/24 any", False),
            ("permit ip 10.0.0.0/24 any", "permit ip 0.0.0.0 255.255.255.255 any", False),
            ("permit ip 10.0.0.0/24 any", "permit ip 10.0.0.0 0.0.0.255 any", True),
            ("permit ip 10.0.0.0/24 any", "permit ip 10.0.1.0 0.0.0.255 any", False),
            ("permit ip 10.0.0.0/24 any", "permit ip 10.0.0.0 0.0.0.3 any", True),
            ("permit ip 10.0.0.0/24 any", "permit ip 10.0.1.0 0.0.0.3 any", False),
            ("permit ip 10.0.0.0/24 any", "permit ip 10.0.0.1 0.0.0.0 any", True),
            ("permit ip 10.0.0.0/24 any", "permit ip 10.0.1.1 0.0.0.0 any", False),
            ("permit ip 10.0.0.0/24 any", "permit ip any any", False),
            ("permit ip 10.0.0.0/24 any", "permit ip host 10.0.0.1 any", True),
            ("permit ip 10.0.0.0/24 any", "permit ip host 10.0.1.1 any", False),
            ("permit ip 10.0.0.0/24 any", "permit ip 10.0.0.0 0.0.3.3 any", False),
            ("permit ip 10.0.0.0/24 any", "permit ip addrgroup NAME00 any", False),
            ("permit ip 10.0.0.0/24 any", "permit ip addrgroup NAME24_2 any", False),
            ("permit ip 10.0.0.0/24 any", "permit ip addrgroup NAME24 any", True),
            ("permit ip 10.0.0.0/24 any", "permit ip addrgroup NAME30 any", True),
            ("permit ip 10.0.0.0/24 any", "permit ip addrgroup NAME32 any", True),
            # srcaddr prefix 10.0.0.0/24
            ("permit ip 10.0.0.0/30 any", "permit ip 0.0.0.0/0 any", False),
            ("permit ip 10.0.0.0/30 any", "permit ip 10.0.0.0/24 any", False),
            ("permit ip 10.0.0.0/30 any", "permit ip 10.0.1.0/24 any", False),
            ("permit ip 10.0.0.0/30 any", "permit ip 0.0.0.0 255.255.255.255 any", False),
            ("permit ip 10.0.0.0/30 any", "permit ip 10.0.0.0 0.0.0.255 any", False),
            ("permit ip 10.0.0.0/30 any", "permit ip 10.0.1.0 0.0.0.255 any", False),
            ("permit ip 10.0.0.0/30 any", "permit ip 10.0.0.0 0.0.0.3 any", True),
            ("permit ip 10.0.0.0/30 any", "permit ip 10.0.1.0 0.0.0.3 any", False),
            ("permit ip 10.0.0.0/30 any", "permit ip 10.0.0.1 0.0.0.0 any", True),
            ("permit ip 10.0.0.0/30 any", "permit ip 10.0.1.1 0.0.0.0 any", False),
            ("permit ip 10.0.0.0/30 any", "permit ip any any", False),
            ("permit ip 10.0.0.0/30 any", "permit ip host 10.0.0.1 any", True),
            ("permit ip 10.0.0.0/30 any", "permit ip host 10.0.1.1 any", False),
            ("permit ip 10.0.0.0/30 any", "permit ip 10.0.0.0 0.0.3.3 any", False),
            ("permit ip 10.0.0.0/30 any", "permit ip addrgroup NAME00 any", False),
            ("permit ip 10.0.0.0/30 any", "permit ip addrgroup NAME24_2 any", False),
            ("permit ip 10.0.0.0/30 any", "permit ip addrgroup NAME24 any", False),
            ("permit ip 10.0.0.0/30 any", "permit ip addrgroup NAME30 any", True),
            ("permit ip 10.0.0.0/30 any", "permit ip addrgroup NAME32 any", True),
            # srcaddr prefix 10.0.0.1/32
            ("permit ip 10.0.0.1/32 any", "permit ip 0.0.0.0/0 any", False),
            ("permit ip 10.0.0.1/32 any", "permit ip 10.0.0.0/24 any", False),
            ("permit ip 10.0.0.1/32 any", "permit ip 10.0.1.0/24 any", False),
            ("permit ip 10.0.0.1/32 any", "permit ip 0.0.0.0 255.255.255.255 any", False),
            ("permit ip 10.0.0.1/32 any", "permit ip 10.0.0.0 0.0.0.255 any", False),
            ("permit ip 10.0.0.1/32 any", "permit ip 10.0.1.0 0.0.0.255 any", False),
            ("permit ip 10.0.0.1/32 any", "permit ip 10.0.0.0 0.0.0.3 any", False),
            ("permit ip 10.0.0.1/32 any", "permit ip 10.0.1.0 0.0.0.3 any", False),
            ("permit ip 10.0.0.1/32 any", "permit ip 10.0.0.1 0.0.0.0 any", True),
            ("permit ip 10.0.0.1/32 any", "permit ip 10.0.1.1 0.0.0.0 any", False),
            ("permit ip 10.0.0.1/32 any", "permit ip any any", False),
            ("permit ip 10.0.0.1/32 any", "permit ip host 10.0.0.1 any", True),
            ("permit ip 10.0.0.1/32 any", "permit ip host 10.0.1.1 any", False),
            ("permit ip 10.0.0.1/32 any", "permit ip 10.0.0.0 0.0.3.3 any", False),
            ("permit ip 10.0.0.1/32 any", "permit ip addrgroup NAME00 any", False),
            ("permit ip 10.0.0.1/32 any", "permit ip addrgroup NAME24_2 any", False),
            ("permit ip 10.0.0.1/32 any", "permit ip addrgroup NAME24 any", False),
            ("permit ip 10.0.0.1/32 any", "permit ip addrgroup NAME30 any", False),
            ("permit ip 10.0.0.1/32 any", "permit ip addrgroup NAME32 any", True),
            # srcaddr non-contiguous wildcard
            ("permit ip 10.0.0.0 0.0.3.3 any", "permit ip 0.0.0.0/0 any", False),
            ("permit ip 10.0.0.0 0.0.3.3 any", "permit ip 10.0.0.0/24 any", False),
            ("permit ip 10.0.0.0 0.0.3.3 any", "permit ip 10.0.1.0/24 any", False),
            ("permit ip 10.0.0.0 0.0.3.3 any", "permit ip 0.0.0.0 255.255.255.255 any", False),
            ("permit ip 10.0.0.0 0.0.3.3 any", "permit ip 10.0.0.0 0.0.0.255 any", False),
            ("permit ip 10.0.0.0 0.0.3.3 any", "permit ip 10.0.1.0 0.0.0.255 any", False),
            ("permit ip 10.0.0.0 0.0.3.3 any", "permit ip 10.0.0.0 0.0.0.3 any", True),
            ("permit ip 10.0.0.0 0.0.3.3 any", "permit ip 10.0.1.0 0.0.0.3 any", True),
            ("permit ip 10.0.0.0 0.0.3.3 any", "permit ip 10.0.0.1 0.0.0.0 any", True),
            ("permit ip 10.0.0.0 0.0.3.3 any", "permit ip 10.0.1.1 0.0.0.0 any", True),
            ("permit ip 10.0.0.0 0.0.3.3 any", "permit ip any any", False),
            ("permit ip 10.0.0.0 0.0.3.3 any", "permit ip 10.0.0.0 0.0.3.3 any", True),
            ("permit ip 10.0.0.0 0.0.3.3 any", "permit ip host 10.0.1.1 any", True),
            ("permit ip 10.0.0.0 0.0.3.3 any", "permit ip addrgroup NAME00 any", False),
            ("permit ip 10.0.0.0 0.0.3.3 any", "permit ip addrgroup NAME24_2 any", False),
            ("permit ip 10.0.0.0 0.0.3.3 any", "permit ip addrgroup NAME24 any", False),
            ("permit ip 10.0.0.0 0.0.3.3 any", "permit ip addrgroup NAME30 any", True),
            ("permit ip 10.0.0.0 0.0.3.3 any", "permit ip addrgroup NAME32 any", True),
            # srcaddr any
            ("permit ip any any", "permit ip 0.0.0.0/0 any", True),
            ("permit ip any any", "permit ip 10.0.0.0/24 any", True),
            ("permit ip any any", "permit ip 10.0.1.0/24 any", True),
            ("permit ip any any", "permit ip 0.0.0.0 255.255.255.255 any", True),
            ("permit ip any any", "permit ip 10.0.0.0 0.0.0.255 any", True),
            ("permit ip any any", "permit ip 10.0.1.0 0.0.0.255 any", True),
            ("permit ip any any", "permit ip 10.0.0.0 0.0.0.3 any", True),
            ("permit ip any any", "permit ip 10.0.1.0 0.0.0.3 any", True),
            ("permit ip any any", "permit ip 10.0.0.1 0.0.0.0 any", True),
            ("permit ip any any", "permit ip 10.0.1.1 0.0.0.0 any", True),
            ("permit ip any any", "permit ip any any", True),
            ("permit ip any any", "permit ip host 10.0.0.1 any", True),
            ("permit ip any any", "permit ip host 10.0.1.1 any", True),
            ("permit ip any any", "permit ip 10.0.0.0 0.0.3.3 any", True),
            ("permit ip any any", "permit ip addrgroup NAME00 any", True),
            ("permit ip any any", "permit ip addrgroup NAME24_2 any", True),
            ("permit ip any any", "permit ip addrgroup NAME24 any", True),
            ("permit ip any any", "permit ip addrgroup NAME30 any", True),
            ("permit ip any any", "permit ip addrgroup NAME32 any", True),
            # srcaddr host
            ("permit ip host 10.0.0.1 any", "permit ip 0.0.0.0/0 any", False),
            ("permit ip host 10.0.0.1 any", "permit ip 10.0.0.0/24 any", False),
            ("permit ip host 10.0.0.1 any", "permit ip 10.0.1.0/24 any", False),
            ("permit ip host 10.0.0.1 any", "permit ip 0.0.0.0 255.255.255.255 any", False),
            ("permit ip host 10.0.0.1 any", "permit ip 10.0.0.0 0.0.0.255 any", False),
            ("permit ip host 10.0.0.1 any", "permit ip 10.0.1.0 0.0.0.255 any", False),
            ("permit ip host 10.0.0.1 any", "permit ip 10.0.0.0 0.0.0.3 any", False),
            ("permit ip host 10.0.0.1 any", "permit ip 10.0.1.0 0.0.0.3 any", False),
            ("permit ip host 10.0.0.1 any", "permit ip 10.0.0.1 0.0.0.0 any", True),
            ("permit ip host 10.0.0.1 any", "permit ip 10.0.1.1 0.0.0.0 any", False),
            ("permit ip host 10.0.0.1 any", "permit ip any any", False),
            ("permit ip host 10.0.0.1 any", "permit ip host 10.0.0.1 any", True),
            ("permit ip host 10.0.0.1 any", "permit ip host 10.0.1.1 any", False),
            ("permit ip host 10.0.0.1 any", "permit ip 10.0.0.0 0.0.3.3 any", False),
            ("permit ip host 10.0.0.1 any", "permit ip addrgroup NAME00 any", False),
            ("permit ip host 10.0.0.1 any", "permit ip addrgroup NAME24_2 any", False),
            ("permit ip host 10.0.0.1 any", "permit ip addrgroup NAME24 any", False),
            ("permit ip host 10.0.0.1 any", "permit ip addrgroup NAME30 any", False),
            ("permit ip host 10.0.0.1 any", "permit ip addrgroup NAME32 any", True),
            # srcaddr addrgroup 10.0.0.0/24
            ("permit ip addrgroup NAME24 any", "permit ip 0.0.0.0/0 any", False),
            ("permit ip addrgroup NAME24 any", "permit ip 10.0.0.0/24 any", True),
            ("permit ip addrgroup NAME24 any", "permit ip 10.0.1.0/24 any", False),
            ("permit ip addrgroup NAME24 any", "permit ip 0.0.0.0 255.255.255.255 any", False),
            ("permit ip addrgroup NAME24 any", "permit ip 10.0.0.0 0.0.0.255 any", True),
            ("permit ip addrgroup NAME24 any", "permit ip 10.0.1.0 0.0.0.255 any", False),
            ("permit ip addrgroup NAME24 any", "permit ip 10.0.0.0 0.0.0.3 any", True),
            ("permit ip addrgroup NAME24 any", "permit ip 10.0.1.0 0.0.0.3 any", False),
            ("permit ip addrgroup NAME24 any", "permit ip 10.0.0.1 0.0.0.0 any", True),
            ("permit ip addrgroup NAME24 any", "permit ip 10.0.1.1 0.0.0.0 any", False),
            ("permit ip addrgroup NAME24 any", "permit ip any any", False),
            ("permit ip addrgroup NAME24 any", "permit ip host 10.0.0.1 any", True),
            ("permit ip addrgroup NAME24 any", "permit ip host 10.0.1.1 any", False),
            ("permit ip addrgroup NAME24 any", "permit ip 10.0.0.0 0.0.3.3 any", False),
            ("permit ip addrgroup NAME24 any", "permit ip addrgroup NAME00 any", False),
            ("permit ip addrgroup NAME24 any", "permit ip addrgroup NAME24_2 any", False),
            ("permit ip addrgroup NAME24 any", "permit ip addrgroup NAME24 any", True),
            ("permit ip addrgroup NAME24 any", "permit ip addrgroup NAME30 any", True),
            ("permit ip addrgroup NAME24 any", "permit ip addrgroup NAME32 any", True),
            # srcaddr addrgroup 10.0.0.0/24, 10.0.1.0/24
            ("permit ip addrgroup NAME24_2 any", "permit ip 0.0.0.0/0 any", False),
            ("permit ip addrgroup NAME24_2 any", "permit ip 10.0.0.0/24 any", True),
            ("permit ip addrgroup NAME24_2 any", "permit ip 10.0.1.0/24 any", True),
            ("permit ip addrgroup NAME24_2 any", "permit ip 0.0.0.0 255.255.255.255 any", False),
            ("permit ip addrgroup NAME24_2 any", "permit ip 10.0.0.0 0.0.0.255 any", True),
            ("permit ip addrgroup NAME24_2 any", "permit ip 10.0.1.0 0.0.0.255 any", True),
            ("permit ip addrgroup NAME24_2 any", "permit ip 10.0.0.0 0.0.0.3 any", True),
            ("permit ip addrgroup NAME24_2 any", "permit ip 10.0.1.0 0.0.0.3 any", True),
            ("permit ip addrgroup NAME24_2 any", "permit ip 10.0.0.1 0.0.0.0 any", True),
            ("permit ip addrgroup NAME24_2 any", "permit ip 10.0.1.1 0.0.0.0 any", True),
            ("permit ip addrgroup NAME24_2 any", "permit ip any any", False),
            ("permit ip addrgroup NAME24_2 any", "permit ip host 10.0.0.1 any", True),
            ("permit ip addrgroup NAME24_2 any", "permit ip host 10.0.1.1 any", True),
            ("permit ip addrgroup NAME24_2 any", "permit ip 10.0.0.0 0.0.3.3 any", False),
            ("permit ip addrgroup NAME24_2 any", "permit ip addrgroup NAME00 any", False),
            ("permit ip addrgroup NAME24_2 any", "permit ip addrgroup NAME24_2 any", True),
            ("permit ip addrgroup NAME24_2 any", "permit ip addrgroup NAME24 any", True),
            ("permit ip addrgroup NAME24_2 any", "permit ip addrgroup NAME30 any", True),
            ("permit ip addrgroup NAME24_2 any", "permit ip addrgroup NAME32 any", True),

            # dstaddr prefix 0.0.0.0/0
            ("permit ip any 0.0.0.0/0", "permit ip any 0.0.0.0/0", True),
            ("permit ip any 0.0.0.0/0", "permit ip any 10.0.0.0/24", True),
            ("permit ip any 0.0.0.0/0", "permit ip any 10.0.1.0/24", True),
            ("permit ip any 0.0.0.0/0", "permit ip any 0.0.0.0 255.255.255.255", True),
            ("permit ip any 0.0.0.0/0", "permit ip any 10.0.0.0 0.0.0.255", True),
            ("permit ip any 0.0.0.0/0", "permit ip any 10.0.1.0 0.0.0.255", True),
            ("permit ip any 0.0.0.0/0", "permit ip any 10.0.0.0 0.0.0.3", True),
            ("permit ip any 0.0.0.0/0", "permit ip any 10.0.1.0 0.0.0.3", True),
            ("permit ip any 0.0.0.0/0", "permit ip any 10.0.0.1 0.0.0.0", True),
            ("permit ip any 0.0.0.0/0", "permit ip any 10.0.1.1 0.0.0.0", True),
            ("permit ip any 0.0.0.0/0", "permit ip any 10.0.0.0 0.0.3.3", True),
            ("permit ip any 0.0.0.0/0", "permit ip any any", True),
            ("permit ip any 0.0.0.0/0", "permit ip any host 10.0.0.1", True),
            ("permit ip any 0.0.0.0/0", "permit ip any host 10.0.1.1", True),
            ("permit ip any 0.0.0.0/0", "permit ip any addrgroup NAME00", True),
            ("permit ip any 0.0.0.0/0", "permit ip any addrgroup NAME24_2", True),
            ("permit ip any 0.0.0.0/0", "permit ip any addrgroup NAME24", True),
            ("permit ip any 0.0.0.0/0", "permit ip any addrgroup NAME30", True),
            ("permit ip any 0.0.0.0/0", "permit ip any addrgroup NAME32", True),
            # dstaddr prefix 10.0.0.0/24
            ("permit ip any 10.0.0.0/24", "permit ip any 0.0.0.0/0", False),
            ("permit ip any 10.0.0.0/24", "permit ip any 10.0.0.0/24", True),
            ("permit ip any 10.0.0.0/24", "permit ip any 10.0.1.0/24", False),
            ("permit ip any 10.0.0.0/24", "permit ip any 0.0.0.0 255.255.255.255", False),
            ("permit ip any 10.0.0.0/24", "permit ip any 10.0.0.0 0.0.0.255", True),
            ("permit ip any 10.0.0.0/24", "permit ip any 10.0.1.0 0.0.0.255", False),
            ("permit ip any 10.0.0.0/24", "permit ip any 10.0.0.0 0.0.0.3", True),
            ("permit ip any 10.0.0.0/24", "permit ip any 10.0.1.0 0.0.0.3", False),
            ("permit ip any 10.0.0.0/24", "permit ip any 10.0.0.1 0.0.0.0", True),
            ("permit ip any 10.0.0.0/24", "permit ip any 10.0.1.1 0.0.0.0", False),
            ("permit ip any 10.0.0.0/24", "permit ip any 10.0.0.0 0.0.3.3", False),
            ("permit ip any 10.0.0.0/24", "permit ip any any", False),
            ("permit ip any 10.0.0.0/24", "permit ip any host 10.0.0.1", True),
            ("permit ip any 10.0.0.0/24", "permit ip any host 10.0.1.1", False),
            ("permit ip any 10.0.0.0/24", "permit ip any addrgroup NAME00", False),
            ("permit ip any 10.0.0.0/24", "permit ip any addrgroup NAME24_2", False),
            ("permit ip any 10.0.0.0/24", "permit ip any addrgroup NAME24", True),
            ("permit ip any 10.0.0.0/24", "permit ip any addrgroup NAME30", True),
            ("permit ip any 10.0.0.0/24", "permit ip any addrgroup NAME32", True),
            # dstaddr prefix 10.0.0.0/24
            ("permit ip any 10.0.0.0/30", "permit ip any 0.0.0.0/0", False),
            ("permit ip any 10.0.0.0/30", "permit ip any 10.0.0.0/24", False),
            ("permit ip any 10.0.0.0/30", "permit ip any 10.0.1.0/24", False),
            ("permit ip any 10.0.0.0/30", "permit ip any 0.0.0.0 255.255.255.255", False),
            ("permit ip any 10.0.0.0/30", "permit ip any 10.0.0.0 0.0.0.255", False),
            ("permit ip any 10.0.0.0/30", "permit ip any 10.0.1.0 0.0.0.255", False),
            ("permit ip any 10.0.0.0/30", "permit ip any 10.0.0.0 0.0.0.3", True),
            ("permit ip any 10.0.0.0/30", "permit ip any 10.0.1.0 0.0.0.3", False),
            ("permit ip any 10.0.0.0/30", "permit ip any 10.0.0.1 0.0.0.0", True),
            ("permit ip any 10.0.0.0/30", "permit ip any 10.0.1.1 0.0.0.0", False),
            ("permit ip any 10.0.0.0/30", "permit ip any 10.0.0.0 0.0.3.3", False),
            ("permit ip any 10.0.0.0/30", "permit ip any any", False),
            ("permit ip any 10.0.0.0/30", "permit ip any host 10.0.0.1", True),
            ("permit ip any 10.0.0.0/30", "permit ip any host 10.0.1.1", False),
            ("permit ip any 10.0.0.0/30", "permit ip any addrgroup NAME00", False),
            ("permit ip any 10.0.0.0/30", "permit ip any addrgroup NAME24_2", False),
            ("permit ip any 10.0.0.0/30", "permit ip any addrgroup NAME24", False),
            ("permit ip any 10.0.0.0/30", "permit ip any addrgroup NAME30", True),
            ("permit ip any 10.0.0.0/30", "permit ip any addrgroup NAME32", True),
            # dstaddr prefix 10.0.0.1/32
            ("permit ip any 10.0.0.1/32", "permit ip any 0.0.0.0/0", False),
            ("permit ip any 10.0.0.1/32", "permit ip any 10.0.0.0/24", False),
            ("permit ip any 10.0.0.1/32", "permit ip any 10.0.1.0/24", False),
            ("permit ip any 10.0.0.1/32", "permit ip any 0.0.0.0 255.255.255.255", False),
            ("permit ip any 10.0.0.1/32", "permit ip any 10.0.0.0 0.0.0.255", False),
            ("permit ip any 10.0.0.1/32", "permit ip any 10.0.1.0 0.0.0.255", False),
            ("permit ip any 10.0.0.1/32", "permit ip any 10.0.0.0 0.0.0.3", False),
            ("permit ip any 10.0.0.1/32", "permit ip any 10.0.1.0 0.0.0.3", False),
            ("permit ip any 10.0.0.1/32", "permit ip any 10.0.0.1 0.0.0.0", True),
            ("permit ip any 10.0.0.1/32", "permit ip any 10.0.1.1 0.0.0.0", False),
            ("permit ip any 10.0.0.1/32", "permit ip any 10.0.0.0 0.0.3.3", False),
            ("permit ip any 10.0.0.1/32", "permit ip any any", False),
            ("permit ip any 10.0.0.1/32", "permit ip any host 10.0.0.1", True),
            ("permit ip any 10.0.0.1/32", "permit ip any host 10.0.1.1", False),
            ("permit ip any 10.0.0.1/32", "permit ip any addrgroup NAME00", False),
            ("permit ip any 10.0.0.1/32", "permit ip any addrgroup NAME24_2", False),
            ("permit ip any 10.0.0.1/32", "permit ip any addrgroup NAME24", False),
            ("permit ip any 10.0.0.1/32", "permit ip any addrgroup NAME30", False),
            ("permit ip any 10.0.0.1/32", "permit ip any addrgroup NAME32", True),
            # dstaddr any
            ("permit ip any any", "permit ip any 0.0.0.0/0", True),
            ("permit ip any any", "permit ip any 10.0.0.0/24", True),
            ("permit ip any any", "permit ip any 10.0.1.0/24", True),
            ("permit ip any any", "permit ip any 0.0.0.0 255.255.255.255", True),
            ("permit ip any any", "permit ip any 10.0.0.0 0.0.0.255", True),
            ("permit ip any any", "permit ip any 10.0.1.0 0.0.0.255", True),
            ("permit ip any any", "permit ip any 10.0.0.0 0.0.0.3", True),
            ("permit ip any any", "permit ip any 10.0.1.0 0.0.0.3", True),
            ("permit ip any any", "permit ip any 10.0.0.1 0.0.0.0", True),
            ("permit ip any any", "permit ip any 10.0.1.1 0.0.0.0", True),
            ("permit ip any any", "permit ip any 10.0.0.0 0.0.3.3", True),
            ("permit ip any any", "permit ip any any", True),
            ("permit ip any any", "permit ip any host 10.0.0.1", True),
            ("permit ip any any", "permit ip any host 10.0.1.1", True),
            ("permit ip any any", "permit ip any addrgroup NAME00", True),
            ("permit ip any any", "permit ip any addrgroup NAME24_2", True),
            ("permit ip any any", "permit ip any addrgroup NAME24", True),
            ("permit ip any any", "permit ip any addrgroup NAME30", True),
            ("permit ip any any", "permit ip any addrgroup NAME32", True),
            # dstaddr host
            ("permit ip any host 10.0.0.1", "permit ip any 0.0.0.0/0", False),
            ("permit ip any host 10.0.0.1", "permit ip any 10.0.0.0/24", False),
            ("permit ip any host 10.0.0.1", "permit ip any 10.0.1.0/24", False),
            ("permit ip any host 10.0.0.1", "permit ip any 0.0.0.0 255.255.255.255", False),
            ("permit ip any host 10.0.0.1", "permit ip any 10.0.0.0 0.0.0.255", False),
            ("permit ip any host 10.0.0.1", "permit ip any 10.0.1.0 0.0.0.255", False),
            ("permit ip any host 10.0.0.1", "permit ip any 10.0.0.0 0.0.0.3", False),
            ("permit ip any host 10.0.0.1", "permit ip any 10.0.1.0 0.0.0.3", False),
            ("permit ip any host 10.0.0.1", "permit ip any 10.0.0.1 0.0.0.0", True),
            ("permit ip any host 10.0.0.1", "permit ip any 10.0.1.1 0.0.0.0", False),
            ("permit ip any host 10.0.0.1", "permit ip any 10.0.0.0 0.0.3.3", False),
            ("permit ip any host 10.0.0.1", "permit ip any any", False),
            ("permit ip any host 10.0.0.1", "permit ip any host 10.0.0.1", True),
            ("permit ip any host 10.0.0.1", "permit ip any host 10.0.1.1", False),
            ("permit ip any host 10.0.0.1", "permit ip any addrgroup NAME00", False),
            ("permit ip any host 10.0.0.1", "permit ip any addrgroup NAME24_2", False),
            ("permit ip any host 10.0.0.1", "permit ip any addrgroup NAME24", False),
            ("permit ip any host 10.0.0.1", "permit ip any addrgroup NAME30", False),
            ("permit ip any host 10.0.0.1", "permit ip any addrgroup NAME32", True),
            # dstaddr non-contiguous wildcard
            ("permit ip any 10.0.0.0 0.0.3.3", "permit ip any 0.0.0.0/0", False),
            ("permit ip any 10.0.0.0 0.0.3.3", "permit ip any 10.0.0.0/24", False),
            ("permit ip any 10.0.0.0 0.0.3.3", "permit ip any 10.0.1.0/24", False),
            ("permit ip any 10.0.0.0 0.0.3.3", "permit ip any 0.0.0.0 255.255.255.255", False),
            ("permit ip any 10.0.0.0 0.0.3.3", "permit ip any 10.0.0.0 0.0.0.255", False),
            ("permit ip any 10.0.0.0 0.0.3.3", "permit ip any 10.0.1.0 0.0.0.255", False),
            ("permit ip any 10.0.0.0 0.0.3.3", "permit ip any 10.0.0.0 0.0.0.3", True),
            ("permit ip any 10.0.0.0 0.0.3.3", "permit ip any 10.0.1.0 0.0.0.3", True),
            ("permit ip any 10.0.0.0 0.0.3.3", "permit ip any 10.0.0.1 0.0.0.0", True),
            ("permit ip any 10.0.0.0 0.0.3.3", "permit ip any 10.0.1.1 0.0.0.0", True),
            ("permit ip any 10.0.0.0 0.0.3.3", "permit ip any any", False),
            ("permit ip any 10.0.0.0 0.0.3.3", "permit ip any 10.0.0.0 0.0.3.3", True),
            ("permit ip any 10.0.0.0 0.0.3.3", "permit ip any host 10.0.1.1", True),
            ("permit ip any 10.0.0.0 0.0.3.3", "permit ip any addrgroup NAME00", False),
            ("permit ip any 10.0.0.0 0.0.3.3", "permit ip any addrgroup NAME24_2", False),
            ("permit ip any 10.0.0.0 0.0.3.3", "permit ip any addrgroup NAME24", False),
            ("permit ip any 10.0.0.0 0.0.3.3", "permit ip any addrgroup NAME30", True),
            ("permit ip any 10.0.0.0 0.0.3.3", "permit ip any addrgroup NAME32", True),

            # srcport any
            ("permit tcp any any", "permit tcp any any", True),
            ("permit tcp any any", "permit tcp any eq 1 any", True),
            ("permit tcp any any", "permit tcp any eq 2 any", True),
            ("permit tcp any any", "permit tcp any neq 1 any", True),
            ("permit tcp any any", "permit tcp any neq 2 any", True),
            ("permit tcp any any", "permit tcp any gt 1 any", True),
            ("permit tcp any any", "permit tcp any gt 2 any", True),
            ("permit tcp any any", "permit tcp any lt 2 any", True),
            ("permit tcp any any", "permit tcp any lt 3 any", True),
            ("permit tcp any any", "permit tcp any range 1 2 any", True),
            ("permit tcp any any", "permit tcp any range 3 4 any", True),
            # srcport eq
            ("permit tcp any eq 2 any", "permit tcp any any", False),
            ("permit tcp any eq 2 any", "permit tcp any eq 1 any", False),
            ("permit tcp any eq 2 any", "permit tcp any eq 2 any", True),
            ("permit tcp any eq 2 any", "permit tcp any neq 1 any", False),
            ("permit tcp any eq 2 any", "permit tcp any neq 2 any", False),
            ("permit tcp any eq 2 any", "permit tcp any gt 1 any", False),
            ("permit tcp any eq 2 any", "permit tcp any gt 2 any", False),
            ("permit tcp any eq 2 any", "permit tcp any lt 2 any", False),
            ("permit tcp any eq 2 any", "permit tcp any lt 3 any", False),
            ("permit tcp any eq 2 any", "permit tcp any range 1 2 any", False),
            ("permit tcp any eq 2 any", "permit tcp any range 3 4 any", False),
            # srcport neq
            ("permit tcp any neq 2 any", "permit tcp any any", False),
            ("permit tcp any neq 2 any", "permit tcp any eq 1 any", True),
            ("permit tcp any neq 2 any", "permit tcp any eq 2 any", False),
            ("permit tcp any neq 2 any", "permit tcp any neq 1 any", False),
            ("permit tcp any neq 2 any", "permit tcp any neq 2 any", True),
            ("permit tcp any neq 2 any", "permit tcp any gt 1 any", False),
            ("permit tcp any neq 2 any", "permit tcp any gt 2 any", True),
            ("permit tcp any neq 2 any", "permit tcp any lt 2 any", True),
            ("permit tcp any neq 2 any", "permit tcp any lt 3 any", False),
            ("permit tcp any neq 2 any", "permit tcp any range 1 2 any", False),
            ("permit tcp any neq 2 any", "permit tcp any range 3 4 any", True),
            # srcport gt
            ("permit tcp any gt 2 any", "permit tcp any any", False),
            ("permit tcp any gt 2 any", "permit tcp any eq 1 any", False),
            ("permit tcp any gt 2 any", "permit tcp any eq 2 any", False),
            ("permit tcp any gt 2 any", "permit tcp any neq 1 any", False),
            ("permit tcp any gt 2 any", "permit tcp any neq 2 any", False),
            ("permit tcp any gt 2 any", "permit tcp any gt 1 any", False),
            ("permit tcp any gt 2 any", "permit tcp any gt 2 any", True),
            ("permit tcp any gt 2 any", "permit tcp any lt 2 any", False),
            ("permit tcp any gt 2 any", "permit tcp any lt 3 any", False),
            ("permit tcp any gt 2 any", "permit tcp any range 1 2 any", False),
            ("permit tcp any gt 2 any", "permit tcp any range 3 4 any", True),
            # srcport lt
            ("permit tcp any lt 2 any", "permit tcp any any", False),
            ("permit tcp any lt 2 any", "permit tcp any eq 1 any", True),
            ("permit tcp any lt 2 any", "permit tcp any eq 2 any", False),
            ("permit tcp any lt 2 any", "permit tcp any neq 1 any", False),
            ("permit tcp any lt 2 any", "permit tcp any neq 2 any", False),
            ("permit tcp any lt 2 any", "permit tcp any gt 1 any", False),
            ("permit tcp any lt 2 any", "permit tcp any gt 2 any", False),
            ("permit tcp any lt 2 any", "permit tcp any lt 2 any", True),
            ("permit tcp any lt 2 any", "permit tcp any lt 3 any", False),
            ("permit tcp any lt 2 any", "permit tcp any range 1 2 any", False),
            ("permit tcp any lt 2 any", "permit tcp any range 3 4 any", False),
            # srcport range
            ("permit tcp any range 1 2 any", "permit tcp any any", False),
            ("permit tcp any range 1 2 any", "permit tcp any eq 1 any", True),
            ("permit tcp any range 1 2 any", "permit tcp any eq 2 any", True),
            ("permit tcp any range 1 2 any", "permit tcp any neq 1 any", False),
            ("permit tcp any range 1 2 any", "permit tcp any neq 2 any", False),
            ("permit tcp any range 1 2 any", "permit tcp any gt 1 any", False),
            ("permit tcp any range 1 2 any", "permit tcp any gt 2 any", False),
            ("permit tcp any range 1 2 any", "permit tcp any lt 2 any", True),
            ("permit tcp any range 1 2 any", "permit tcp any lt 3 any", True),
            ("permit tcp any range 1 2 any", "permit tcp any range 1 2 any", True),
            ("permit tcp any range 1 2 any", "permit tcp any range 3 4 any", False),
            ("permit tcp any range 1 2 any", "permit tcp any range 2 3 any", False),
            # dstport any
            ("permit tcp any any", "permit tcp any any", True),
            ("permit tcp any any", "permit tcp any any eq 1", True),
            ("permit tcp any any", "permit tcp any any eq 2", True),
            ("permit tcp any any", "permit tcp any any neq 1", True),
            ("permit tcp any any", "permit tcp any any neq 2", True),
            ("permit tcp any any", "permit tcp any any gt 1", True),
            ("permit tcp any any", "permit tcp any any gt 2", True),
            ("permit tcp any any", "permit tcp any any lt 2", True),
            ("permit tcp any any", "permit tcp any any lt 3", True),
            ("permit tcp any any", "permit tcp any any range 1 2", True),
            ("permit tcp any any", "permit tcp any any range 3 4", True),
            # dstport eq
            ("permit tcp any any eq 2", "permit tcp any any", False),
            ("permit tcp any any eq 2", "permit tcp any any eq 1", False),
            ("permit tcp any any eq 2", "permit tcp any any eq 2", True),
            ("permit tcp any any eq 2", "permit tcp any any neq 1", False),
            ("permit tcp any any eq 2", "permit tcp any any neq 2", False),
            ("permit tcp any any eq 2", "permit tcp any any gt 1", False),
            ("permit tcp any any eq 2", "permit tcp any any gt 2", False),
            ("permit tcp any any eq 2", "permit tcp any any lt 2", False),
            ("permit tcp any any eq 2", "permit tcp any any lt 3", False),
            ("permit tcp any any eq 2", "permit tcp any any range 1 2", False),
            ("permit tcp any any eq 2", "permit tcp any any range 3 4", False),
            # dstport neq
            ("permit tcp any any neq 2", "permit tcp any any", False),
            ("permit tcp any any neq 2", "permit tcp any any eq 1", True),
            ("permit tcp any any neq 2", "permit tcp any any eq 2", False),
            ("permit tcp any any neq 2", "permit tcp any any neq 1", False),
            ("permit tcp any any neq 2", "permit tcp any any neq 2", True),
            ("permit tcp any any neq 2", "permit tcp any any gt 1", False),
            ("permit tcp any any neq 2", "permit tcp any any gt 2", True),
            ("permit tcp any any neq 2", "permit tcp any any lt 2", True),
            ("permit tcp any any neq 2", "permit tcp any any lt 3", False),
            ("permit tcp any any neq 2", "permit tcp any any range 1 2", False),
            ("permit tcp any any neq 2", "permit tcp any any range 3 4", True),
            # dstport gt
            ("permit tcp any any gt 2", "permit tcp any any", False),
            ("permit tcp any any gt 2", "permit tcp any any eq 1", False),
            ("permit tcp any any gt 2", "permit tcp any any eq 2", False),
            ("permit tcp any any gt 2", "permit tcp any any neq 1", False),
            ("permit tcp any any gt 2", "permit tcp any any neq 2", False),
            ("permit tcp any any gt 2", "permit tcp any any gt 1", False),
            ("permit tcp any any gt 2", "permit tcp any any gt 2", True),
            ("permit tcp any any gt 2", "permit tcp any any lt 2", False),
            ("permit tcp any any gt 2", "permit tcp any any lt 3", False),
            ("permit tcp any any gt 2", "permit tcp any any range 1 2", False),
            ("permit tcp any any gt 2", "permit tcp any any range 3 4", True),
            # dstport lt
            ("permit tcp any any lt 2", "permit tcp any any", False),
            ("permit tcp any any lt 2", "permit tcp any any eq 1", True),
            ("permit tcp any any lt 2", "permit tcp any any eq 2", False),
            ("permit tcp any any lt 2", "permit tcp any any neq 1", False),
            ("permit tcp any any lt 2", "permit tcp any any neq 2", False),
            ("permit tcp any any lt 2", "permit tcp any any gt 1", False),
            ("permit tcp any any lt 2", "permit tcp any any gt 2", False),
            ("permit tcp any any lt 2", "permit tcp any any lt 2", True),
            ("permit tcp any any lt 2", "permit tcp any any lt 3", False),
            ("permit tcp any any lt 2", "permit tcp any any range 1 2", False),
            ("permit tcp any any lt 2", "permit tcp any any range 3 4", False),
            # dstport range
            ("permit tcp any any range 1 2", "permit tcp any any", False),
            ("permit tcp any any range 1 2", "permit tcp any any eq 1", True),
            ("permit tcp any any range 1 2", "permit tcp any any eq 2", True),
            ("permit tcp any any range 1 2", "permit tcp any any neq 1", False),
            ("permit tcp any any range 1 2", "permit tcp any any neq 2", False),
            ("permit tcp any any range 1 2", "permit tcp any any gt 1", False),
            ("permit tcp any any range 1 2", "permit tcp any any gt 2", False),
            ("permit tcp any any range 1 2", "permit tcp any any lt 2", True),
            ("permit tcp any any range 1 2", "permit tcp any any lt 3", True),
            ("permit tcp any any range 1 2", "permit tcp any any range 1 2", True),
            ("permit tcp any any range 1 2", "permit tcp any any range 3 4", False),
            ("permit tcp any any range 1 2", "permit tcp any any range 2 3", False),
            # option
            ("permit tcp any any", "permit tcp any any", True),
            ("permit tcp any any", "permit tcp any any syn", True),
            ("permit tcp any any", "permit tcp any any syn log", True),
            ("permit tcp any any", "permit tcp any any ack", True),
            # option syn
            ("permit tcp any any syn", "permit tcp any any", False),
            ("permit tcp any any syn", "permit tcp any any syn", True),
            ("permit tcp any any syn", "permit tcp any any syn log", True),
            ("permit tcp any any syn", "permit tcp any any ack", False),
            # option syn log
            ("permit tcp any any syn log", "permit tcp any any", False),
            ("permit tcp any any syn log", "permit tcp any any syn", True),
            ("permit tcp any any syn log", "permit tcp any any syn log", True),
            ("permit tcp any any syn log", "permit tcp any any ack", False),
            # option ack
            ("permit tcp any any ack", "permit tcp any any", False),
            ("permit tcp any any ack", "permit tcp any any syn", False),
            ("permit tcp any any ack", "permit tcp any any syn log", False),
            ("permit tcp any any ack", "permit tcp any any ack", True),
        ]:
            top_o = Ace(top, platform="nxos")
            bottom_o = Ace(bottom, platform="nxos")
            for addr_o in [top_o.srcaddr, top_o.dstaddr, bottom_o.srcaddr, bottom_o.dstaddr]:
                if addr_o.addrgroup == "NAME00":
                    addr_o.items.append(Address("0.0.0.0/0", platform="nxos"))
                elif addr_o.addrgroup == "NAME24_2":
                    addr_o.items.extend([Address("10.0.0.0/24", platform="nxos"),
                                         Address("10.0.1.0/24", platform="nxos")])
                elif addr_o.addrgroup == "NAME24":
                    addr_o.items.append(Address("10.0.0.0/24", platform="nxos"))
                elif addr_o.addrgroup == "NAME30":
                    addr_o.items.append(Address("10.0.0.0/30", platform="nxos"))
                elif addr_o.addrgroup == "NAME32":
                    addr_o.items.append(Address("10.0.0.1/32", platform="nxos"))

            result = bottom_o.shadow_of(top_o)
            self.assertEqual(result, req, msg=f"{top=} {bottom=}")

    def test_valid__shadow_of__skip(self):
        """Ace.shadow_of() skip"""
        for top, bot, skip, req in [
            # nc_wildcard
            ("permit ip any 10.0.0.0 0.0.3.3", "permit ip any any", None, False),
            ("permit ip 10.0.0.0 0.0.3.3 any", "permit ip any any", None, False),
            ("permit ip any any", "permit ip any 10.0.0.0 0.0.3.3", None, True),
            ("permit ip any any", "permit ip 10.0.0.0 0.0.3.3 any", None, True),
            # skip
            ("permit ip any addrgroup NAME", "permit ip any any", ["addrgroup"], False),
            ("permit ip addrgroup NAME any", "permit ip any any", ["addrgroup"], False),
            ("permit ip any any", "permit ip any addrgroup NAME", ["addrgroup"], False),
            ("permit ip any any", "permit ip addrgroup NAME any", ["addrgroup"], False),
            ("permit ip any 10.0.0.0 0.0.3.3", "permit ip any any", ["nc_wildcard"], False),
            ("permit ip 10.0.0.0 0.0.3.3 any", "permit ip any any", ["nc_wildcard"], False),
            ("permit ip any any", "permit ip any 10.0.0.0 0.0.3.3", ["nc_wildcard"], False),
            ("permit ip any any", "permit ip 10.0.0.0 0.0.3.3 any", ["nc_wildcard"], False),
        ]:
            top_o = Ace(top, platform="nxos")
            bot_o = Ace(bot, platform="nxos")
            result = bot_o.shadow_of(other=top_o, skip=skip)
            self.assertEqual(result, req, msg=f"{top=} {bot=}")

    def test_valid__shadow_of__srcaddr(self):
        """Ace._shadow_of__srcaddr()"""
        src_addgr = "permit ip addrgroup NAME24 any"
        src_nc_wildcard = "permit ip 10.0.0.0 0.0.3.3 any"
        addr = "10.0.0.0/24"
        for top, bot, top_addr, bot_addr, skip, req in [
            # no skip
            (src_addgr, "permit ip any any", addr, [], [], False),
            (src_addgr, "permit ip 10.0.0.0/24 any", addr, [], [], True),
            (src_addgr, "permit ip 10.0.1.0/24 any", addr, [], [], False),
            (src_addgr, src_addgr, addr, addr, [], True),
            # skip addrgroup
            (src_addgr, "permit ip any any", addr, [], ["addrgroup"], False),
            (src_addgr, "permit ip 10.0.0.0/24 any", [], [], ["addrgroup"], False),
            (src_addgr, "permit ip any any", addr, [], ["addrgroup"], False),
            (src_addgr, "permit ip 10.0.0.0/24 any", [], [], ["addrgroup"], False),
            # skip nc_wildcard
            (src_nc_wildcard, "permit ip any any", [], [], ["nc_wildcard"], False),
            ("permit ip any any", src_nc_wildcard, [], [], ["nc_wildcard"], False),
        ]:
            top_o = Ace(top, platform="nxos")
            bot_o = Ace(bot, platform="nxos")
            if re.search("addrgroup", top):
                top_o.srcaddr.items = top_addr
            if re.search("addrgroup", bot):
                bot_o.srcaddr.items = bot_addr

            result = bot_o._shadow_of__srcaddr(other=top_o, skip=skip)
            self.assertEqual(result, req, msg=f"{top=} {bot=}")

    def test_valid__shadow_of__dstaddr(self):
        """Ace._shadow_of__dstaddr()"""
        dst_addgr = "permit ip any addrgroup NAME24"
        dst_nc_wildcard = "permit ip any 10.0.0.0 0.0.3.3"
        addr = "10.0.0.0/24"
        for top, bot, top_addr, bot_addr, skip, req in [
            # no skip
            (dst_addgr, "permit ip any any", addr, [], [], False),
            (dst_addgr, "permit ip any 10.0.0.0/24", addr, [], [], True),
            (dst_addgr, "permit ip any 10.0.1.0/24", addr, [], [], False),
            (dst_addgr, dst_addgr, addr, addr, [], True),
            # skip addrgroup
            (dst_addgr, "permit ip any any", addr, [], ["addrgroup"], False),
            (dst_addgr, "permit ip any 10.0.0.0/24", addr, [], ["addrgroup"], False),
            (dst_addgr, "permit ip any any", addr, [], ["addrgroup"], False),
            (dst_addgr, "permit ip any 10.0.0.0/24", addr, [], ["addrgroup"], False),
            # skip nc_wildcard
            (dst_nc_wildcard, "permit ip any any", [], [], ["nc_wildcard"], False),
            ("permit ip any any", dst_nc_wildcard, [], [], ["nc_wildcard"], False),
        ]:
            top_o = Ace(top, platform="nxos")
            bot_o = Ace(bot, platform="nxos")
            if re.search("addrgroup", top):
                top_o.dstaddr.items = [Address(top_addr)]
            if re.search("addrgroup", bot):
                bot_o.dstaddr.items = [Address(bot_addr)]

            result = bot_o._shadow_of__dstaddr(other=top_o, skip=skip)
            self.assertEqual(result, req, msg=f"{top=} {bot=}")

    def test_valid__ungroup_ports(self):
        """Ace.ungroup_ports()"""
        for line, req in [
            ("permit tcp any any", ["permit tcp any any"]),
            ("permit tcp any eq 1 any eq 2", ["permit tcp any eq 1 any eq 2"]),
            ("permit tcp any eq 1 2 any", ["permit tcp any eq 1 any", "permit tcp any eq 2 any"]),
            ("permit tcp any any eq 1 2", ["permit tcp any any eq 1", "permit tcp any any eq 2"]),
            ("permit tcp any eq 1 2 any eq 3 4", ["permit tcp any eq 1 any eq 3",
                                                  "permit tcp any eq 1 any eq 4",
                                                  "permit tcp any eq 2 any eq 3",
                                                  "permit tcp any eq 2 any eq 4"]),
        ]:
            obj = Ace(line, platform="ios")
            aces = obj.ungroup_ports()
            result = [o.line for o in aces]
            self.assertEqual(result, req, msg=f"{line=}")

    def test_valid__check_parsed_elements(self):
        """Ace._check_parsed_elements()"""
        for data, req, in [
            (dict(protocol="ip", srcport="", dstport=""), True),
        ]:
            result = Ace._check_parsed_elements(line="", data=data)
            self.assertEqual(result, req, msg=f"{data=}")

    def test_invalid__check_parsed_elements(self):
        """Ace._check_parsed_elements()"""
        for data, error, in [
            (dict(protocol="", srcport="", dstport=""), ValueError),
            (dict(protocol="ip", srcport="1", dstport=""), ValueError),
            (dict(protocol="ip", srcport="", dstport="1"), ValueError),
            (dict(protocol="ip", srcport="1", dstport="1"), ValueError),
        ]:
            with self.assertRaises(error, msg=f"{data=}"):
                Ace._check_parsed_elements(line="", data=data)


if __name__ == "__main__":
    unittest.main()
