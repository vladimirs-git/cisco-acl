"""Unittest ace.py"""

import unittest

from cisco_acl import Ace, Remark
from tests.helpers_test import (
    DENY_IP,
    DENY_IP_1,
    Helpers,
    PERMIT_IP,
    PERMIT_IP_1,
    PERMIT_IP_2,
    REMARK,
)


# noinspection DuplicatedCode
class Test(Helpers):
    """Ace"""

    # ========================== redefined ===========================

    def test_valid__hash__(self):
        """Ace.__hash__()"""
        line = PERMIT_IP
        ace_o = Ace(line)
        result = ace_o.__hash__()
        req = line.__hash__()
        self.assertEqual(result, req, msg=f"{line=}")

    def test_valid__eq__(self):
        """Ace.__eq__() __ne__()"""
        ace_o = Ace(PERMIT_IP_1)
        for other_o, req, in [
            (Ace(PERMIT_IP_1), True),
            (Ace(PERMIT_IP_2), False),
            (Ace(DENY_IP_1), False),
            (Remark(REMARK), False),
            (PERMIT_IP_1, False),
        ]:
            result = ace_o.__eq__(other_o)
            self.assertEqual(result, req, msg=f"{ace_o=} {other_o=}")
            result = ace_o.__ne__(other_o)
            self.assertEqual(result, not req, msg=f"{ace_o=} {other_o=}")

    def test_valid__lt__(self):
        """Ace.__lt__() __le__() __gt__() __ge__()"""
        for ace_o, other_o, req_lt, req_le, req_gt, req_ge in [
            (Ace(PERMIT_IP), Ace(PERMIT_IP), False, True, False, True),
            (Ace(PERMIT_IP), Ace(DENY_IP), False, False, True, True),
            (Ace(PERMIT_IP_1), Ace(PERMIT_IP_2), True, True, False, False),
            (Ace(PERMIT_IP_2), Ace(DENY_IP_1), False, False, True, True),
        ]:
            result = ace_o.__lt__(other_o)
            self.assertEqual(result, req_lt, msg=f"{ace_o=} {other_o=}")
            result = ace_o.__le__(other_o)
            self.assertEqual(result, req_le, msg=f"{ace_o=} {other_o=}")
            result = ace_o.__gt__(other_o)
            self.assertEqual(result, req_gt, msg=f"{ace_o=} {other_o=}")
            result = ace_o.__ge__(other_o)
            self.assertEqual(result, req_ge, msg=f"{ace_o=} {other_o=}")

    def test_valid__lt__sort(self):
        """Ace.__lt__(), Ace.__le__()"""
        for items in [
            # action
            [Remark("remark text1"), Remark("remark text2")],
            [Remark("remark text1"), Ace("permit ip any any")],
            [Remark("remark text1"), Ace("deny ip any any")],
            [Ace("deny ip any any"), Ace("permit ip any any")],
            # protocol
            [Ace("permit ip any any"), Ace("permit ahp any any")],
            # srcaddr
            [Ace("permit ip any any"), Ace("permit ip 1.1.1.0 0.0.0.255 any")],
            [Ace("permit ip any any"), Ace("permit ip 1.1.1.0 0.0.0.3 any")],
            [Ace("permit ip any any"), Ace("permit ip host 1.1.1.1 any")],
            [Ace("permit ip any any"), Ace("permit ip addrgroup NAME any")],
            [Ace("permit ip 1.1.1.0 0.0.0.255 any"), Ace("permit ip 1.1.1.0 0.0.0.3 any")],
            [Ace("permit ip 1.1.1.0 0.0.0.255 any"), Ace("permit ip host 1.1.1.1 any")],
            [Ace("permit ip 1.1.1.0 0.0.0.255 any"), Ace("permit ip addrgroup NAME any")],
            [Ace("permit ip 1.1.1.0 0.0.0.3 any"), Ace("permit ip host 1.1.1.1 any")],
            [Ace("permit ip 1.1.1.0 0.0.0.3 any"), Ace("permit ip addrgroup NAME any")],
            [Ace("permit ip host 1.1.1.1 any"), Ace("permit ip addrgroup NAME any")],
            [Ace("permit ip addrgroup NAME1 any"), Ace("permit ip addrgroup NAME2 any")],
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
            [Ace("permit ip any any"), Ace("permit ip any addrgroup NAME")],
            [Ace("permit ip any 1.1.1.0 0.0.0.255"), Ace("permit ip any 1.1.1.0 0.0.0.3")],
            [Ace("permit ip any 1.1.1.0 0.0.0.255"), Ace("permit ip any host 1.1.1.1")],
            [Ace("permit ip any 1.1.1.0 0.0.0.255"), Ace("permit ip any addrgroup NAME")],
            [Ace("permit ip any 1.1.1.0 0.0.0.3"), Ace("permit ip any host 1.1.1.1")],
            [Ace("permit ip any 1.1.1.0 0.0.0.3"), Ace("permit ip any addrgroup NAME")],
            [Ace("permit ip any host 1.1.1.1"), Ace("permit ip any addrgroup NAME")],
            [Ace("permit ip any addrgroup NAME1"), Ace("permit ip any addrgroup NAME2")],
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

    # =========================== property ===========================

    def test_valid__line(self):
        """Ace.line"""
        icmp = "permit icmp any any"
        icmp_pr = "permit 1 any any"
        icmp_d = dict(line=icmp,
                      sequence="",
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
                     sequence="",
                     action="permit",
                     protocol="tcp",
                     srcaddr="any",
                     srcport="eq ftp 443",
                     dstaddr="object-group NAME",
                     dstport="neq cmd",
                     option="ack log")
        tcp_10_d = {**tcp_d, **{"line": tcp_10, "sequence": "10"}}
        tcp_n_d = {**tcp_d,
                   **{"line": tcp_n, "srcport": "eq 21 443", "dstport": "neq 514"}}

        udp = "deny udp host 1.1.1.1 lt syslog 2.2.2.0 0.0.0.3 range bootps tftp"
        udp_n = "deny udp host 1.1.1.1 lt 514 2.2.2.0 0.0.0.3 range 67 69"
        udp_d = dict(line=udp,
                     sequence="",
                     action="deny",
                     protocol="udp",
                     srcaddr="host 1.1.1.1",
                     srcport="lt syslog",
                     dstaddr="2.2.2.0 0.0.0.3",
                     dstport="range bootps tftp",
                     option="")
        udp_n_d = {**udp_d,
                   **{"line": udp_n, "srcport": "lt 514", "dstport": "range 67 69"}}

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
        ]:
            # getter
            ace_o = Ace(**kwargs)
            self._test_attrs(obj=ace_o, req_d=req_d, msg=f"getter {kwargs=}")

            # setter
            line = kwargs["line"]
            ace_o.line = line
            self._test_attrs(obj=ace_o, req_d=req_d, msg=f"setter {line=}")

        # deleter
        with self.assertRaises(AttributeError, msg="deleter line"):
            # noinspection PyPropertyAccess
            del ace_o.line

    def test_invalid__line(self):
        """Ace.line"""
        for line, error in [
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
        ace_o = Ace(line_name)
        for port_nr, req in [
            (True, line_num),
            (False, line_name),
        ]:
            ace_o.port_nr = port_nr
            result = ace_o.line
            self.assertEqual(result, req, msg=f"{port_nr=}")

    def test_valid__platform(self):
        """Ace.platform"""
        ios_grp = "deny ip object-group A object-group B"
        nxos_grp = "deny ip addrgroup A addrgroup B"
        ios_host = "permit ip host 1.1.1.1 host 2.2.2.2"
        nxos_host = "permit ip 1.1.1.1/32 2.2.2.2/32"
        ios_prefix = "permit ip 1.1.1.0 0.0.0.255 2.2.2.0 0.0.0.255"
        nxos_prefix = "permit ip 1.1.1.0/24 2.2.2.0/24"
        any_wild = "permit ip 1.1.0.0 0.0.3.3 2.2.0.0 0.0.3.3"
        any_eq = "permit tcp any eq 1 any neq 3 log"
        any_gt = "permit tcp any gt 65533 any lt 3 log"

        for platform, to_platform, line, req in [
            ("ios", "ios", ios_grp, ios_grp),
            ("ios", "ios", ios_host, ios_host),
            ("ios", "ios", ios_prefix, ios_prefix),
            ("ios", "ios", any_wild, any_wild),
            ("ios", "ios", any_eq, any_eq),
            ("ios", "ios", any_gt, any_gt),

            ("ios", "nxos", ios_grp, nxos_grp),
            ("ios", "nxos", ios_host, nxos_host),
            ("ios", "nxos", ios_prefix, nxos_prefix),
            ("ios", "nxos", any_wild, any_wild),
            ("ios", "nxos", any_eq, any_eq),
            ("ios", "nxos", any_gt, any_gt),

            ("nxos", "ios", nxos_grp, ios_grp),
            ("nxos", "ios", nxos_host, ios_host),
            ("nxos", "ios", nxos_prefix, ios_prefix),
            ("nxos", "ios", any_wild, any_wild),
            ("nxos", "ios", any_eq, any_eq),
            ("nxos", "ios", any_gt, any_gt),

            ("nxos", "nxos", nxos_grp, nxos_grp),
            ("nxos", "nxos", nxos_host, nxos_host),
            ("nxos", "nxos", nxos_prefix, nxos_prefix),
            ("nxos", "nxos", any_wild, any_wild),
            ("nxos", "nxos", any_eq, any_eq),
            ("nxos", "nxos", any_gt, any_gt),
        ]:
            # getter
            ace_o = Ace(line, platform=platform)
            result = ace_o.platform
            req_ = platform
            self.assertEqual(result, req_, msg=f"{platform=} {line=}")

            # setter
            ace_o.platform = to_platform
            result = ace_o.platform
            req_ = to_platform
            self.assertEqual(result, req_, msg=f"{platform=} {to_platform=} {line=}")
            result = ace_o.line
            self.assertEqual(result, req, msg=f"{platform=} {to_platform=} {line=}")

        # deleter
        ace_o = Ace(PERMIT_IP)
        with self.assertRaises(AttributeError, msg="deleter line"):
            # noinspection PyPropertyAccess
            del ace_o.line

    def test_invalid__platform(self):
        """Ace.platform"""
        ace_o = Ace(PERMIT_IP)
        with self.assertRaises(ValueError, msg="platform"):
            ace_o.platform = "typo"
        with self.assertRaises(ValueError, msg="platform"):
            Ace(PERMIT_IP, platform="typo")

    # =========================== methods ============================

    def test_valid__copy(self):
        """Ace.copy()"""
        kwargs1 = dict(line=PERMIT_IP, platform="ios", port_nr=True, note="a")
        kwargs2 = dict(line=DENY_IP, platform="nxos", port_nr=False, note="b")
        ace_o1 = Ace(**kwargs1)
        ace_o2 = ace_o1.copy()
        for arg, value in kwargs2.items():
            setattr(ace_o1, arg, value)
        self._test_attrs(ace_o2, kwargs1, msg="ace_o2 copy of ace_o1")
        self._test_attrs(ace_o1, kwargs2, msg="ace_o1 does not depend on ace_o2")

    def test_valid__range(self):
        """Ace.range()"""
        proto = ["permit 1 any any", "permit 2 any any"]
        src_tcp_eq = ["permit tcp any eq 20 any", "permit tcp any eq 21 any"]
        src_tcp_neq = ["permit tcp any neq 20 any", "permit tcp any neq 21 any"]
        dst_tcp_eq = ["permit tcp any any eq 20", "permit tcp any any eq 21"]
        dst_tcp_neq = ["permit tcp any any neq 20", "permit tcp any any neq 21"]
        src_udp_eq = ["permit udp any eq 67 any", "permit udp any eq 68 any"]
        dst_udp_eq = ["permit udp any any eq 67", "permit udp any any eq 68"]
        src_combo_eq = ["permit tcp any eq 20 any", "permit tcp any eq 21 any",
                        "permit tcp any any eq 20", "permit tcp any any eq 21"]
        src_combo_neq = ["permit tcp any neq 20 any", "permit tcp any neq 21 any",
                         "permit tcp any neq 1 any eq 20", "permit tcp any neq 1 any eq 21"]
        for kwargs, line, req in [
            ({}, "permit ip any any", []),
            (dict(protocol="1-2"), "permit ip any any", proto),
            (dict(protocol="1-2"), "permit 0 any any", proto),
            # tcp
            (dict(srcport="20-21"), "permit tcp any any", src_tcp_eq),
            (dict(srcport="20-21"), "permit tcp any eq 1 any", src_tcp_eq),
            (dict(srcport="20-21"), "permit tcp any neq 1 any", src_tcp_neq),
            (dict(dstport="20-21"), "permit tcp any any", dst_tcp_eq),
            (dict(dstport="20-21"), "permit tcp any any eq 1 ", dst_tcp_eq),
            (dict(dstport="20-21"), "permit tcp any any neq 1 ", dst_tcp_neq),
            # udp
            (dict(srcport="67-68"), "permit udp any any", src_udp_eq),
            (dict(srcport="67-68"), "permit udp any eq 1 any", src_udp_eq),
            (dict(dstport="67-68"), "permit udp any any", dst_udp_eq),
            (dict(dstport="67-68"), "permit udp any any eq 1 ", dst_udp_eq),
            # combo
            (dict(srcport="20-21", dstport="20,21"), "permit tcp any any", src_combo_eq),
            (dict(srcport="20-21", dstport="20,21"), "permit tcp any neq 1 any", src_combo_neq),
        ]:
            ace_o = Ace(line=line)
            results = ace_o.range(protocol_nr=True, port_nr=True, **kwargs)
            result = [str(o) for o in results]
            self.assertEqual(result, req, msg=f"{line=} {kwargs=}")

    def test_invalid__range(self):
        """Ace.range()"""
        for line, kwargs, error in [
            ("permit icmp any any", dict(protocol="1-2", srcport="1-2"), ValueError),
            ("permit icmp any any", dict(protocol="1-2", dstport="1-2"), ValueError),
        ]:
            ace_o = Ace(line=line, port_nr=True)
            with self.assertRaises(error, msg=f"{line=} {kwargs=}"):
                ace_o.range(**kwargs)

    def test_valid__rule(self):
        """Ace.rule()"""
        allow_ip = dict(action="allow")
        allow_tcp = dict(
            action="allow",
            srcaddrs=["10.0.0.1/32"],
            dstaddrs=["10.0.0.0/30"],
            protocols=["tcp"],
            tcp_srcports=[1, 2, 3],
            tcp_dstports=[80, 443],
            udp_srcports=[],
            udp_dstports=[],
            options=["log"],
        )
        deny_udp = dict(
            action="deny",
            srcaddrs=[],
            dstaddrs=["0.0.0.0/0"],
            protocols=["udp"],
            tcp_srcports=[],
            tcp_dstports=[],
            udp_srcports=[1],
            udp_dstports=[2],
            options=[],
        )
        allow_group = dict(
            action="allow",
            srcaddrs=["10.0.0.1/32", "10.0.0.2/32"],
            dstaddrs=["10.0.0.0/30", "10.0.0.4/30"],
            protocols=["icmp", "tcp", "udp"],
            tcp_srcports=[1, 2],
            tcp_dstports=[3, 4],
            udp_srcports=[5, 6],
            udp_dstports=[7, 8],
            options=["log"],
        )
        permit_ip = ["permit ip any any"]
        permit_tcp_ios = ["permit tcp host 10.0.0.1 eq 1 2 3 10.0.0.0 0.0.0.3 eq www 443 log"]
        permit_tcp_nxos = [
            "permit tcp 10.0.0.1/32 eq 1 10.0.0.0/30 eq www log",
            "permit tcp 10.0.0.1/32 eq 1 10.0.0.0/30 eq 443 log",
            "permit tcp 10.0.0.1/32 eq 2 10.0.0.0/30 eq www log",
            "permit tcp 10.0.0.1/32 eq 2 10.0.0.0/30 eq 443 log",
            "permit tcp 10.0.0.1/32 eq 3 10.0.0.0/30 eq www log",
            "permit tcp 10.0.0.1/32 eq 3 10.0.0.0/30 eq 443 log",
        ]
        deny_udp_ = ["deny udp any eq 1 any eq 2"]
        permit_group_ios = [
            "permit icmp host 10.0.0.1 10.0.0.0 0.0.0.3 log",
            "permit icmp host 10.0.0.1 10.0.0.4 0.0.0.3 log",
            "permit icmp host 10.0.0.2 10.0.0.0 0.0.0.3 log",
            "permit icmp host 10.0.0.2 10.0.0.4 0.0.0.3 log",
            "permit tcp host 10.0.0.1 eq 1 2 10.0.0.0 0.0.0.3 eq 3 4 log",
            "permit tcp host 10.0.0.1 eq 1 2 10.0.0.4 0.0.0.3 eq 3 4 log",
            "permit tcp host 10.0.0.2 eq 1 2 10.0.0.0 0.0.0.3 eq 3 4 log",
            "permit tcp host 10.0.0.2 eq 1 2 10.0.0.4 0.0.0.3 eq 3 4 log",
            "permit udp host 10.0.0.1 eq 5 6 10.0.0.0 0.0.0.3 eq echo 8 log",
            "permit udp host 10.0.0.1 eq 5 6 10.0.0.4 0.0.0.3 eq echo 8 log",
            "permit udp host 10.0.0.2 eq 5 6 10.0.0.0 0.0.0.3 eq echo 8 log",
            "permit udp host 10.0.0.2 eq 5 6 10.0.0.4 0.0.0.3 eq echo 8 log",
        ]
        permit_group_nxos = [
            "permit icmp 10.0.0.1/32 10.0.0.0/30 log",
            "permit icmp 10.0.0.1/32 10.0.0.4/30 log",
            "permit icmp 10.0.0.2/32 10.0.0.0/30 log",
            "permit icmp 10.0.0.2/32 10.0.0.4/30 log",

            "permit tcp 10.0.0.1/32 eq 1 10.0.0.0/30 eq 3 log",
            "permit tcp 10.0.0.1/32 eq 1 10.0.0.0/30 eq 4 log",
            "permit tcp 10.0.0.1/32 eq 1 10.0.0.4/30 eq 3 log",
            "permit tcp 10.0.0.1/32 eq 1 10.0.0.4/30 eq 4 log",
            "permit tcp 10.0.0.1/32 eq 2 10.0.0.0/30 eq 3 log",
            "permit tcp 10.0.0.1/32 eq 2 10.0.0.0/30 eq 4 log",
            "permit tcp 10.0.0.1/32 eq 2 10.0.0.4/30 eq 3 log",
            "permit tcp 10.0.0.1/32 eq 2 10.0.0.4/30 eq 4 log",

            "permit tcp 10.0.0.2/32 eq 1 10.0.0.0/30 eq 3 log",
            "permit tcp 10.0.0.2/32 eq 1 10.0.0.0/30 eq 4 log",
            "permit tcp 10.0.0.2/32 eq 1 10.0.0.4/30 eq 3 log",
            "permit tcp 10.0.0.2/32 eq 1 10.0.0.4/30 eq 4 log",
            "permit tcp 10.0.0.2/32 eq 2 10.0.0.0/30 eq 3 log",
            "permit tcp 10.0.0.2/32 eq 2 10.0.0.0/30 eq 4 log",
            "permit tcp 10.0.0.2/32 eq 2 10.0.0.4/30 eq 3 log",
            "permit tcp 10.0.0.2/32 eq 2 10.0.0.4/30 eq 4 log",

            "permit udp 10.0.0.1/32 eq 5 10.0.0.0/30 eq echo log",
            "permit udp 10.0.0.1/32 eq 5 10.0.0.0/30 eq 8 log",
            "permit udp 10.0.0.1/32 eq 5 10.0.0.4/30 eq echo log",
            "permit udp 10.0.0.1/32 eq 5 10.0.0.4/30 eq 8 log",
            "permit udp 10.0.0.1/32 eq 6 10.0.0.0/30 eq echo log",
            "permit udp 10.0.0.1/32 eq 6 10.0.0.0/30 eq 8 log",
            "permit udp 10.0.0.1/32 eq 6 10.0.0.4/30 eq echo log",
            "permit udp 10.0.0.1/32 eq 6 10.0.0.4/30 eq 8 log",

            "permit udp 10.0.0.2/32 eq 5 10.0.0.0/30 eq echo log",
            "permit udp 10.0.0.2/32 eq 5 10.0.0.0/30 eq 8 log",
            "permit udp 10.0.0.2/32 eq 5 10.0.0.4/30 eq echo log",
            "permit udp 10.0.0.2/32 eq 5 10.0.0.4/30 eq 8 log",
            "permit udp 10.0.0.2/32 eq 6 10.0.0.0/30 eq echo log",
            "permit udp 10.0.0.2/32 eq 6 10.0.0.0/30 eq 8 log",
            "permit udp 10.0.0.2/32 eq 6 10.0.0.4/30 eq echo log",
            "permit udp 10.0.0.2/32 eq 6 10.0.0.4/30 eq 8 log",
        ]
        for kwargs, platform, req in [
            (allow_ip, "ios", permit_ip),
            (allow_ip, "nxos", permit_ip),
            (allow_tcp, "ios", permit_tcp_ios),
            (allow_tcp, "nxos", permit_tcp_nxos),
            (deny_udp, "ios", deny_udp_),
            (deny_udp, "nxos", deny_udp_),
            (allow_group, "ios", permit_group_ios),
            (allow_group, "nxos", permit_group_nxos),
        ]:
            result_lo = Ace.rule(platform=platform, **kwargs)
            result = [o.line for o in result_lo]
            for id_, req_ in enumerate(req):
                result_ = result[id_]
                if result_ != req_:
                    self.assertEqual(result_, req_, msg=f"{id_=} {req_=}")
            self.assertEqual(result, req, msg=f"{kwargs=}")

    def test_invalid__rule(self):
        """Ace.rule()"""
        for kwargs, error in [
            ({}, KeyError),
            (dict(action="remark"), KeyError),
            (dict(action="permit"), KeyError),
            (dict(action="allow", srcaddrs=[None]), TypeError),
            (dict(action="allow", dstaddrs=[{}]), TypeError),
            (dict(action="allow", protocols=[{}]), ValueError),
            (dict(action="allow", protocols=["tcp"], tcp_srcports=[{}]), ValueError),
            (dict(action="allow", protocols=["tcp"], tcp_dstports=[{}]), ValueError),
            (dict(action="allow", protocols=["udp"], udp_dstports=[{}]), ValueError),
            (dict(action="allow", protocols=["udp"], udp_dstports=[{}]), ValueError),
        ]:
            with self.assertRaises(error, msg=f"{kwargs=}"):
                Ace.rule(**kwargs)

    # =========================== helpers ============================

    def test_valid__range__port(self):
        """Ace._range__port()"""
        src_tcp_eq = ["permit tcp any eq 20 any", "permit tcp any eq 21 any"]
        src_tcp_gt = ["permit tcp any gt 20 any", "permit tcp any gt 21 any"]
        src_tcp_lt = ["permit tcp any lt 20 any", "permit tcp any lt 21 any"]
        src_tcp_neq = ["permit tcp any neq 20 any", "permit tcp any neq 21 any"]
        src_udp_eq = ["permit udp any eq 67 any", "permit udp any eq 68 any"]
        src_udp_gt = ["permit udp any gt 67 any", "permit udp any gt 68 any"]
        src_udp_lt = ["permit udp any lt 67 any", "permit udp any lt 68 any"]
        src_udp_neq = ["permit udp any neq 67 any", "permit udp any neq 68 any"]
        dst_tcp_eq = ["permit tcp any any eq 20", "permit tcp any any eq 21"]
        dst_tcp_gt = ["permit tcp any any gt 20", "permit tcp any any gt 21"]
        dst_tcp_lt = ["permit tcp any any lt 20", "permit tcp any any lt 21"]
        dst_tcp_neq = ["permit tcp any any neq 20", "permit tcp any any neq 21"]
        dst_udp_eq = ["permit udp any any eq 67", "permit udp any any eq 68"]
        dst_udp_gt = ["permit udp any any gt 67", "permit udp any any gt 68"]
        dst_udp_lt = ["permit udp any any lt 67", "permit udp any any lt 68"]
        dst_udp_neq = ["permit udp any any neq 67", "permit udp any any neq 68"]
        for kwargs, line, req in [
            # src tcp
            (dict(sdst="src", range_=""), "permit tcp any any", []),
            (dict(sdst="src", range_="20-21"), "permit tcp any any", src_tcp_eq),
            (dict(sdst="src", range_="20-21"), "permit tcp any eq 1 any", src_tcp_eq),
            (dict(sdst="src", range_="20-21"), "permit tcp any gt 1 any", src_tcp_gt),
            (dict(sdst="src", range_="20-21"), "permit tcp any lt 1 any", src_tcp_lt),
            (dict(sdst="src", range_="20-21"), "permit tcp any neq 1 any", src_tcp_neq),
            # src udp
            (dict(sdst="src", range_=""), "permit udp any any", []),
            (dict(sdst="src", range_="67-68"), "permit udp any any", src_udp_eq),
            (dict(sdst="src", range_="67-68"), "permit udp any eq 1 any", src_udp_eq),
            (dict(sdst="src", range_="67-68"), "permit udp any gt 1 any", src_udp_gt),
            (dict(sdst="src", range_="67-68"), "permit udp any lt 1 any", src_udp_lt),
            (dict(sdst="src", range_="67-68"), "permit udp any neq 1 any", src_udp_neq),
            # dst tcp
            (dict(sdst="src", range_=""), "permit tcp any any", []),
            (dict(sdst="dst", range_="20,21"), "permit tcp any any", dst_tcp_eq),
            (dict(sdst="dst", range_="20,21"), "permit tcp any any eq 1 ", dst_tcp_eq),
            (dict(sdst="dst", range_="20,21"), "permit tcp any any gt 1 ", dst_tcp_gt),
            (dict(sdst="dst", range_="20,21"), "permit tcp any any lt 1 ", dst_tcp_lt),
            (dict(sdst="dst", range_="20,21"), "permit tcp any any neq 1 ", dst_tcp_neq),
            # dst udp
            (dict(sdst="src", range_=""), "permit udp any any", []),
            (dict(sdst="dst", range_="67,68"), "permit udp any any", dst_udp_eq),
            (dict(sdst="dst", range_="67,68"), "permit udp any any eq 1 ", dst_udp_eq),
            (dict(sdst="dst", range_="67,68"), "permit udp any any gt 1 ", dst_udp_gt),
            (dict(sdst="dst", range_="67,68"), "permit udp any any lt 1 ", dst_udp_lt),
            (dict(sdst="dst", range_="67,68"), "permit udp any any neq 1 ", dst_udp_neq),
        ]:
            ace_o = Ace(line=line)
            results = ace_o._range__port(**kwargs, port_nr=True)
            result = [str(o) for o in results]
            self.assertEqual(result, req, msg=f"{line=} {kwargs=}")

        src_tcp_eq = ["permit tcp any eq ftp-data any", "permit tcp any eq ftp any"]
        for kwargs, line, req in [
            (dict(sdst="src", range_="20-21"), "permit tcp any any", src_tcp_eq),
        ]:
            ace_o = Ace(line=line)
            results = ace_o._range__port(**kwargs, port_nr=False)
            result = [str(o) for o in results]
            self.assertEqual(result, req, msg=f"{line=} {kwargs=}")

    def test_invalid__range__port(self):
        """Ace._range__port()"""
        for kwargs, line, error in [
            (dict(sdst="src", range_="20-21"), "permit tcp any range 1 2 any", ValueError),
            (dict(sdst="dst", range_="20-21"), "permit tcp any any range 1 2", ValueError),
        ]:
            ace_o = Ace(line=line)
            with self.assertRaises(error, msg=f"{line=} {kwargs=}"):
                ace_o._range__port(port_nr=True, **kwargs)

    def test_valid__range__protocol(self):
        """Ace._range__protocol()"""
        req1 = ["permit icmp any any", "permit igmp any any", "permit 3 any any"]
        req2 = ["permit 1 any any", "permit 3 any any", "permit 4 any any", "permit 5 any any"]
        for kwargs, line, req in [
            (dict(range_="", protocol_nr=False), "permit icmp any any", []),
            (dict(range_="1-3", protocol_nr=False), "permit ip any any", req1),
            (dict(range_="1-3", protocol_nr=False), "permit 0 any any", req1),
            (dict(range_="1-3", protocol_nr=False), "permit icmp any any", req1),
            (dict(range_="1-3", protocol_nr=False), "permit 1 any any", req1),
            # protocol_nr
            (dict(range_="", protocol_nr=True), "permit icmp any any", []),
            (dict(range_="1,3-5", protocol_nr=True), "permit ip any any", req2),
            (dict(range_="1,3-5", protocol_nr=True), "permit 0 any any", req2),
            (dict(range_="1,3-5", protocol_nr=True), "permit icmp any any", req2),
            (dict(range_="1,3-5", protocol_nr=True), "permit 1 any any", req2),
        ]:
            ace_o = Ace(line=line, protocol_nr=True, port_nr=True)
            results = ace_o._range__protocol(**kwargs)
            result = [str(o) for o in results]
            self.assertEqual(result, req, msg=f"{line=} {kwargs=}")


if __name__ == "__main__":
    unittest.main()
