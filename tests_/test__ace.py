"""unittest ace.py"""

import unittest

from cisco_acl import Ace, Remark
from tests_.helpers_test import (
    DENY_IP,
    DENY_IP_1,
    PERMIT_IP,
    PERMIT_IP_1,
    PERMIT_IP_2,
    REMARK,
)


# noinspection DuplicatedCode
class Test(unittest.TestCase):
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
        for ace_o, other_o, req, in [
            (Ace(PERMIT_IP_1), Ace(PERMIT_IP_1), True),
            (Ace(PERMIT_IP_1), Ace(PERMIT_IP_2), False),
            (Ace(PERMIT_IP_1), Ace(DENY_IP_1), False),
            (Ace(PERMIT_IP_1), Remark(REMARK), False),
            (Ace(PERMIT_IP_1), PERMIT_IP_1, False),
        ]:
            msg = f"{ace_o=} {other_o=}"
            result = ace_o.__eq__(other_o)
            self.assertEqual(result, req, msg=msg)
            result = ace_o.__ne__(other_o)
            self.assertEqual(result, not req, msg=msg)

    def test_valid__lt__(self):
        """Ace.__lt__() __le__() __gt__() __ge__()"""
        for ace_o, other_o, req_lt, req_le, req_gt, req_ge in [
            (Ace(PERMIT_IP), Ace(PERMIT_IP), False, True, False, True),
            (Ace(PERMIT_IP), Ace(DENY_IP), False, False, True, True),
            (Ace(PERMIT_IP_1), Ace(PERMIT_IP_2), True, True, False, False),
            (Ace(PERMIT_IP_2), Ace(DENY_IP_1), False, False, True, True),
        ]:
            result = ace_o.__lt__(other_o)
            self.assertEqual(result, req_lt, msg=f"{ace_o=}")
            result = ace_o.__le__(other_o)
            self.assertEqual(result, req_le, msg=f"{ace_o=}")
            result = ace_o.__gt__(other_o)
            self.assertEqual(result, req_gt, msg=f"{ace_o=}")
            result = ace_o.__ge__(other_o)
            self.assertEqual(result, req_ge, msg=f"{ace_o=}")

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
        permit_0 = "permit tcp any eq www 443 object-group NAME neq 22 ack log"
        permit_0b = " permit\ttcp any eq www 443 object-group NAME neq 22 ack log\n"
        permit_10 = f"10 {permit_0}"
        permit_0_d = dict(line=permit_0,
                          idx=0,
                          action="permit",
                          protocol="tcp",
                          srcaddr="any",
                          srcport="eq www 443",
                          dstaddr="object-group NAME",
                          dstport="neq 22",
                          option="ack log")
        permit_10_d = {**permit_0_d, **{"line": permit_10, "idx": 10}}

        deny_0 = "deny udp host 1.1.1.1 lt 3 2.2.2.0 0.0.0.3 range www bgp"
        deny_0b = " deny\tudp host 1.1.1.1 lt 3 2.2.2.0 0.0.0.3 range www bgp\n"
        deny_10 = f"10 {deny_0}"
        deny_0_d = dict(line=deny_0,
                        idx=0,
                        action="deny",
                        protocol="udp",
                        srcaddr="host 1.1.1.1",
                        srcport="lt 3",
                        dstaddr="2.2.2.0 0.0.0.3",
                        dstport="range www bgp",
                        option="")
        deny_10_d = {**deny_0_d, **{"line": deny_10, "idx": 10}}

        for line, req, req_d in [
            (permit_0, permit_0, permit_0_d),
            (permit_10, permit_10, permit_10_d),
            (permit_0b, permit_0, permit_0_d),
            (deny_0, deny_0, deny_0_d),
            (deny_10, deny_10, deny_10_d),
            (deny_0b, deny_0, deny_0_d),
        ]:
            ace_o = Ace(line)
            result = ace_o.line
            self.assertEqual(result, req, msg=f"{line=}")
            result = str(ace_o)
            self.assertEqual(result, req, msg=f"{line=}")
            for attr, req_ in req_d.items():
                result_ = getattr(ace_o, attr)
                if not isinstance(result_, (int, str)):
                    result_ = str(result_)
                self.assertEqual(result_, req_, msg=f"{line=} {attr=}")
            ace_o.line = " ".join(line.split())
            result = str(ace_o)
            self.assertEqual(result, req, msg=f"setter {line=}")
            with self.assertRaises(AttributeError, msg=f"deleter {line=}"):
                # noinspection PyPropertyAccess
                del ace_o.line

    def test_invalid__line(self):
        """Ace.line"""
        for line, error in [
            ("remark text", ValueError),
            ("10 remark text", ValueError),
            ({}, TypeError),
            ("", ValueError),
            ("typo", ValueError),
        ]:
            with self.assertRaises(error, msg=f"{line=}"):
                Ace(line)

    # =========================== methods ============================

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
        permit_tcp_ios = ["permit tcp host 10.0.0.1 eq 1 2 3 10.0.0.0 0.0.0.3 eq 80 443 log"]
        permit_tcp_cnx = [
            "permit tcp 10.0.0.1/32 eq 1 10.0.0.0/30 eq 80 log",
            "permit tcp 10.0.0.1/32 eq 1 10.0.0.0/30 eq 443 log",
            "permit tcp 10.0.0.1/32 eq 2 10.0.0.0/30 eq 80 log",
            "permit tcp 10.0.0.1/32 eq 2 10.0.0.0/30 eq 443 log",
            "permit tcp 10.0.0.1/32 eq 3 10.0.0.0/30 eq 80 log",
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
            "permit udp host 10.0.0.1 eq 5 6 10.0.0.0 0.0.0.3 eq 7 8 log",
            "permit udp host 10.0.0.1 eq 5 6 10.0.0.4 0.0.0.3 eq 7 8 log",
            "permit udp host 10.0.0.2 eq 5 6 10.0.0.0 0.0.0.3 eq 7 8 log",
            "permit udp host 10.0.0.2 eq 5 6 10.0.0.4 0.0.0.3 eq 7 8 log",
        ]
        permit_group_cnx = [
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

            "permit udp 10.0.0.1/32 eq 5 10.0.0.0/30 eq 7 log",
            "permit udp 10.0.0.1/32 eq 5 10.0.0.0/30 eq 8 log",
            "permit udp 10.0.0.1/32 eq 5 10.0.0.4/30 eq 7 log",
            "permit udp 10.0.0.1/32 eq 5 10.0.0.4/30 eq 8 log",
            "permit udp 10.0.0.1/32 eq 6 10.0.0.0/30 eq 7 log",
            "permit udp 10.0.0.1/32 eq 6 10.0.0.0/30 eq 8 log",
            "permit udp 10.0.0.1/32 eq 6 10.0.0.4/30 eq 7 log",
            "permit udp 10.0.0.1/32 eq 6 10.0.0.4/30 eq 8 log",

            "permit udp 10.0.0.2/32 eq 5 10.0.0.0/30 eq 7 log",
            "permit udp 10.0.0.2/32 eq 5 10.0.0.0/30 eq 8 log",
            "permit udp 10.0.0.2/32 eq 5 10.0.0.4/30 eq 7 log",
            "permit udp 10.0.0.2/32 eq 5 10.0.0.4/30 eq 8 log",
            "permit udp 10.0.0.2/32 eq 6 10.0.0.0/30 eq 7 log",
            "permit udp 10.0.0.2/32 eq 6 10.0.0.0/30 eq 8 log",
            "permit udp 10.0.0.2/32 eq 6 10.0.0.4/30 eq 7 log",
            "permit udp 10.0.0.2/32 eq 6 10.0.0.4/30 eq 8 log",
        ]
        for kwargs, platform, req in [
            (allow_ip, "ios", permit_ip),
            (allow_ip, "cnx", permit_ip),
            (allow_tcp, "ios", permit_tcp_ios),
            (allow_tcp, "cnx", permit_tcp_cnx),
            (deny_udp, "ios", deny_udp_),
            (deny_udp, "cnx", deny_udp_),
            (allow_group, "ios", permit_group_ios),
            (allow_group, "cnx", permit_group_cnx),
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


if __name__ == "__main__":
    unittest.main()
