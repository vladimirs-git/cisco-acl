"""unittest functions.py"""

import re
import unittest
from ipaddress import NetmaskValueError

import dictdiffer

from cisco_acl import functions as f
from cisco_acl.types_ import LStr, LLStr
from tests.helpers_test import DENY_IP, PERMIT_IP, REMARK, PERMIT_NUM, PERMIT_WILD_252
from tests.test__functions__helpers import CNX_ACEG_EXT_D, IOS_ACE_EXT_D, IOS_ACEG_EXT_D
from tests.test__functions__helpers import CNX_ACL_EXT_CFG, IOS_ADDGR_D, CNX_ACE_EXT_D
from tests.test__functions__helpers import CNX_ADDGR_WILD_252
from tests.test__functions__helpers import IOS_ACE_STD_D, IOS_ACEG_STD_D, IOS_ACL_WILD_252
from tests.test__functions__helpers import IOS_ADDGR_CFG, IOS_ACL_EXT_CFG, IOS_ACL_STD_CFG


def _expected__range_ports__port_nr(srcs: LStr, dsts: LStr) -> LStr:
    """Return expected data for range_ports()"""
    expected = [f"permit tcp any eq {s} any" for s in srcs]
    expected.extend([f"permit tcp any any eq {s}" for s in dsts])
    return expected


def _expected__range_ports__port_count(srcs: LLStr, dsts: LLStr) -> LStr:
    """Return expected data for range_ports()"""
    expected: LStr = []
    for ports in srcs:
        ports_ = " ".join([s for s in ports])
        operator = "range" if re.match(r"\d+-", ports_) else "eq"
        if re.match(r"\d+-", ports_):
            ports_ = ports_.replace("-", " ")
        expected.append(f"permit tcp any {operator} {ports_} any")
    for ports in dsts:
        ports_ = " ".join([s for s in ports])
        operator = "range" if re.match(r"\d+-", ports_) else "eq"
        if re.match(r"\d+-", ports_):
            ports_ = ports_.replace("-", " ")
        expected.append(f"permit tcp any any {operator} {ports_}")
    return expected


class Test(unittest.TestCase):
    """functions.py"""

    def test_valid__acls(self):
        """functions.acls()"""
        for kwargs, req_d in [
            (dict(config=CNX_ACL_EXT_CFG, platform="nxos"), CNX_ACE_EXT_D),
            (dict(config=IOS_ACL_EXT_CFG, platform="ios"), IOS_ACE_EXT_D),
            (dict(config=IOS_ACL_STD_CFG, platform="ios"), IOS_ACE_STD_D),
            # group_by
            (dict(config=CNX_ACL_EXT_CFG, platform="nxos", group_by="=== "), CNX_ACEG_EXT_D),
            (dict(config=IOS_ACL_EXT_CFG, platform="ios", group_by="=== "), IOS_ACEG_EXT_D),
            (dict(config=IOS_ACL_STD_CFG, platform="ios", group_by="=== "), IOS_ACEG_STD_D),
            # names
            (dict(config=IOS_ACL_STD_CFG, names=None), IOS_ACE_STD_D),
            (dict(config=IOS_ACL_STD_CFG, names=[]), {}),
            (dict(config=IOS_ACL_STD_CFG, names=["ACL_NAME2"]), IOS_ACE_STD_D),
            (dict(config=IOS_ACL_STD_CFG, names=["typo"]), {}),
        ]:
            acls = f.acls(**kwargs)
            if req_d:
                self.assertEqual(len(acls), 1, msg="1 acl expected")
                acl_o = acls[0]
                result = acl_o.data()
                diff = list(dictdiffer.diff(first=result, second=req_d))
                self.assertEqual(diff, [], msg=f"{kwargs=}")
            else:
                self.assertEqual(len(acls), 0, msg="1 acl expected")

    def test_valid__acls_2(self):
        """functions.acls(kwargs)"""
        # max_ncwb, 30 instead of 16
        acls = f.acls(config=IOS_ACL_WILD_252, max_ncwb=30)
        self.assertEqual(len(acls), 1, msg="max_ncwb")

        # indent, " " instead of "  "
        acls = f.acls(config=CNX_ACL_EXT_CFG, platform="nxos", indent=" ")
        result = acls[0].indent
        self.assertEqual(result, " ", msg="indent")

        # protocol_nr, "0" instead of "ip"
        acls = f.acls(config=IOS_ACL_STD_CFG, protocol_nr=True)
        result = acls[0].items[1].protocol.line
        self.assertEqual(result, "0", msg="protocol_nr")

        # port_nr, "80" instead of "www"
        acls = f.acls(config=CNX_ACL_EXT_CFG, platform="nxos", port_nr=True)
        result = acls[0].items[1].dstport.line
        self.assertEqual(result, "eq 80", msg="port_nr")

    def test_invalid__acls(self):
        """functions.acls()"""
        for kwargs, error in [
            (dict(config=IOS_ACL_WILD_252), NetmaskValueError),  # max_ncwb
        ]:
            with self.assertRaises(error, msg=f"{kwargs=}"):
                f.acls(**kwargs)

    def test_valid__aces(self):
        """functions.aces()"""
        aces = f"{REMARK}\n{PERMIT_IP}\n{DENY_IP}"
        dirty = f"  \n  {PERMIT_IP}\ntext\n\t{REMARK}\t\ntext"
        acegs = f"remark = C1\n{PERMIT_IP}\nremark = C2\n{DENY_IP}"
        acegs_req = ["remark = C1\npermit ip any any", "remark = C2\ndeny ip any any"]
        for kwargs, req in [
            (dict(config=aces, platform="nxos"), [REMARK, PERMIT_IP, DENY_IP]),
            (dict(config=dirty, platform="nxos"), [PERMIT_IP, REMARK]),
            (dict(config=acegs, platform="nxos", group_by="= "), acegs_req),
        ]:
            aces = f.aces(**kwargs)
            result = [o.line for o in aces]
            self.assertEqual(result, req, msg=f"{kwargs=}")

    def test_valid__aces_2(self):
        """functions.aces(kwargs)"""
        # max_ncwb, 30 instead of 16
        aces = f.aces(config=PERMIT_WILD_252, max_ncwb=30)
        self.assertEqual(len(aces), 1, msg="max_ncwb")

        # protocol_nr, "0" instead of "ip"
        aces = f.aces(config=PERMIT_IP, protocol_nr=True)
        result = aces[0].protocol.line
        self.assertEqual(result, "0", msg="protocol_nr")

        # port_nr, "80" instead of "www"
        aces = f.aces(config=PERMIT_NUM, platform="nxos", port_nr=True)
        result = aces[0].dstport.line
        self.assertEqual(result, "eq 80", msg="port_nr")

    def test_invalid__acs(self):
        """functions.acls()"""
        for kwargs, error in [
            (dict(config=PERMIT_WILD_252), NetmaskValueError),  # max_ncwb
        ]:
            with self.assertRaises(error, msg=f"{kwargs=}"):
                f.aces(**kwargs)

    def test_valid__addrgroups(self):
        """functions.addrgroups()"""
        for kwargs, req_d in [
            (dict(config=IOS_ADDGR_CFG, platform="ios"), IOS_ADDGR_D),
        ]:
            aces = f.addrgroups(**kwargs)
            result = [o.data() for o in aces]
            diff = list(dictdiffer.diff(first=result, second=req_d))
            self.assertEqual(diff, [], msg=f"{kwargs=}")

    def test_valid__addrgroups_2(self):
        """functions.addrgroups(kwargs)"""
        # max_ncwb, 30 instead of 16
        addrgroups = f.addrgroups(config=CNX_ADDGR_WILD_252, platform="nxos", max_ncwb=30)
        self.assertEqual(len(addrgroups), 1, msg="max_ncwb")

        # indent, " " instead of "  "
        addrgroups = f.addrgroups(config=IOS_ADDGR_CFG, indent=" ")
        result = addrgroups[0].indent
        self.assertEqual(result, " ", msg="indent")

    def test_invalid__addrgroups(self):
        """functions.addrgroups()"""
        for kwargs, error in [
            (dict(config=CNX_ADDGR_WILD_252, platform="nxos"), NetmaskValueError),  # max_ncwb
        ]:
            with self.assertRaises(error, msg=f"{kwargs=}"):
                f.addrgroups(**kwargs)

    def test_valid__range_protocol(self):
        """functions.range_protocol()"""
        for kwargs, req in [
            ({}, []),
            (dict(protocols="0"), ["permit ip any any"]),
            (dict(protocols="1", line="deny 1 any any", protocol_nr=False), ["deny icmp any any"]),
            (dict(protocols="2", line="permit tcp any eq 1 any eq 2"), ["permit igmp any any"]),
            (dict(protocols="0-1,6", line="permit ip any any", protocol_nr=False),
             ["permit ip any any",
              "permit icmp any any",
              "permit tcp any any"]),
            (dict(protocols="1-2,6", line="permit ip host 10.0.0.1 any", protocol_nr=True),
             ["permit 1 host 10.0.0.1 any",
              "permit 2 host 10.0.0.1 any",
              "permit 6 host 10.0.0.1 any"]),
        ]:
            result = f.range_protocols(**kwargs)
            self.assertEqual(result, req, msg=f"{kwargs=}")

    def test_valid__range_ports(self):
        """functions.range_ports()"""
        deny_udp1 = ["deny udp host 10.0.0.1 eq 1 any"]
        src_tcp_eq = ["permit tcp any eq ftp-data any", "permit tcp any eq ftp any"]
        src_tcp_eq_ = ["permit tcp any eq 20 any", "permit tcp any eq 21 any"]
        src_udp_neq = ["permit udp any neq 67 any", "permit udp any neq 68 any"]
        dst_tcp_eq = ["permit tcp any any eq ftp-data", "permit tcp any any eq ftp"]
        dst_tcp_eq_ = ["permit tcp any any eq 20", "permit tcp any any eq 21"]
        dst_udp_neq = ["permit udp any any neq 67", "permit udp any any neq 68"]
        combo = ["permit tcp any eq 20 any", "permit tcp any eq 21 any",
                 "permit tcp any any eq 22", "permit tcp any any eq 23"]
        for kwargs, req in [
            ({}, []),
            # src
            (dict(srcports=""), []),
            (dict(srcports="1", line="deny udp host 10.0.0.1 any"), deny_udp1),
            (dict(srcports="20-21", port_nr=False), src_tcp_eq),
            (dict(srcports="20-21", port_nr=True), src_tcp_eq_),
            (dict(srcports="67,68", line="permit udp any neq 1 any", port_nr=True), src_udp_neq),
            # dst
            (dict(dstports=""), []),
            (dict(dstports="20,21", port_nr=False), dst_tcp_eq),
            (dict(dstports="20,21", port_nr=True), dst_tcp_eq_),
            (dict(dstports="67,68", line="permit udp any any neq 1", port_nr=True), dst_udp_neq),
            # combo
            (dict(srcports="20-21", dstports="22-23", port_nr=True), combo),
        ]:
            result = f.range_ports(port_range=False, **kwargs)
            self.assertEqual(result, req, msg=f"{kwargs=}")

    def test_invalid__range_ports(self):
        """functions.range_ports()"""
        for kwargs, error in [
            (dict(srcports="20-21", line="permit tcp any gt 1 any"), ValueError),
            (dict(srcports="20-21", line="permit tcp any lt 1 any"), ValueError),
            # (dict(srcports="20-21", line="permit tcp any range 1 2 any"), ValueError),  # TODO
            (dict(dstports="20-21", line="permit tcp any any gt 1"), ValueError),
            (dict(dstports="20-21", line="permit tcp any any lt 1"), ValueError),
            # (dict(dstports="20-21", line="permit tcp any any range 1 2"), ValueError),  # TODO
        ]:
            with self.assertRaises(error, msg=f"{kwargs=}"):
                f.range_ports(**kwargs)

    def test_valid__range_ports__port_nr(self):
        """functions.range_ports(port_nr)"""
        for kwargs, srcs, dsts in [
            # port_nr=True
            (dict(srcports="20-22,80", port_nr=True), ["20", "21", "22", "80"], []),
            (dict(dstports="20-22,80", port_nr=True), [], ["20", "21", "22", "80"]),
            (dict(srcports="20-21", dstports="22-23", port_nr=True), ["20", "21"], ["22", "23"]),
            # port_nr=False
            (dict(srcports="20-22,80", port_nr=False), ["ftp-data", "ftp", "22", "www"], []),
            (dict(dstports="20-22,80", port_nr=False), [], ["ftp-data", "ftp", "22", "www"]),
            (dict(srcports="20-21", dstports="22-23", port_nr=False),
             ["ftp-data", "ftp"], ["22", "telnet"]),
        ]:
            result = f.range_ports(port_range=False, **kwargs)
            expected = _expected__range_ports__port_nr(srcs, dsts)
            self.assertEqual(result, expected, msg=f"{kwargs=}")

    def test_valid__range_ports__port_count(self):
        """functions.range_ports(port_count)"""
        for kwargs, srcs, dsts in [
            # port_nr=True
            # src
            (dict(srcports="20-22", port_nr=True, platfprm="ios"), [["20"], ["21"], ["22"]], []),
            (dict(srcports="20-22", port_nr=True, platfprm="cnx"), [["20"], ["21"], ["22"]], []),
            (dict(srcports="20-22", port_nr=True, port_count=0), [["20"], ["21"], ["22"]], []),
            (dict(srcports="20-22", port_nr=True, port_count=1), [["20"], ["21"], ["22"]], []),
            (dict(srcports="20-22", port_nr=True, port_count=2), [["20", "21"], ["22"]], []),
            (dict(srcports="20-22", port_nr=True, port_count=3), [["20", "21", "22"]], []),
            (dict(srcports="20-22", port_nr=True, port_count=4), [["20", "21", "22"]], []),
            # dst
            (dict(dstports="20-22", port_nr=True), [], [["20"], ["21"], ["22"]]),
            (dict(dstports="20-22", port_nr=True, port_count=0), [], [["20"], ["21"], ["22"]]),
            (dict(dstports="20-22", port_nr=True, port_count=1), [], [["20"], ["21"], ["22"]]),
            (dict(dstports="20-22", port_nr=True, port_count=2), [], [["20", "21"], ["22"]]),
            (dict(dstports="20-22", port_nr=True, port_count=3), [], [["20", "21", "22"]]),
            (dict(dstports="20-22", port_nr=True, port_count=4), [], [["20", "21", "22"]]),
            # combo
            (dict(srcports="20-21", dstports="22-23", port_nr=True),
             [["20"], ["21"]], [["22"], ["23"]]),
            (dict(srcports="20-21", dstports="22-23", port_nr=True, port_count=2),
             [["20", "21"]], [["22", "23"]]),
            # port_nr=False
            # src
            (dict(srcports="20-21", port_nr=False, platfprm="ios"), [["ftp-data"], ["ftp"]], []),
            (dict(srcports="20-21", port_nr=False, platfprm="cnx"), [["ftp-data"], ["ftp"]], []),
            (dict(srcports="20-21", port_nr=False, port_count=0), [["ftp-data"], ["ftp"]], []),
            (dict(srcports="20-21", port_nr=False, port_count=1), [["ftp-data"], ["ftp"]], []),
            (dict(srcports="20-21", port_nr=False, port_count=2), [["ftp-data", "ftp"]], []),
            (dict(srcports="20-21", port_nr=False, port_count=3), [["ftp-data", "ftp"]], []),
            (dict(srcports="20-21", port_nr=False, port_count=4), [["ftp-data", "ftp"]], []),
            # dst
            (dict(dstports="20-21", port_nr=False), [], [["ftp-data"], ["ftp"]]),
            (dict(dstports="20-21", port_nr=False, port_count=0), [], [["ftp-data"], ["ftp"]]),
            (dict(dstports="20-21", port_nr=False, port_count=1), [], [["ftp-data"], ["ftp"]]),
            (dict(dstports="20-21", port_nr=False, port_count=2), [], [["ftp-data", "ftp"]]),
            (dict(dstports="20-21", port_nr=False, port_count=3), [], [["ftp-data", "ftp"]]),
            (dict(dstports="20-21", port_nr=False, port_count=4), [], [["ftp-data", "ftp"]]),
            # combo
            (dict(srcports="20-21", dstports="22-23", port_nr=False),
             [["ftp-data"], ["ftp"]], [["22"], ["telnet"]]),
            (dict(srcports="20-21", dstports="22-23", port_nr=False, port_count=2),
             [["ftp-data", "ftp"]], [["22", "telnet"]]),
        ]:
            result = f.range_ports(port_range=False, **kwargs)
            expected = _expected__range_ports__port_count(srcs, dsts)
            self.assertEqual(result, expected, msg=f"{kwargs=}")

    def test_valid__range_ports__port_range(self):
        """functions.range_ports(port_range)"""
        for kwargs, srcs, dsts in [
            # port_range=True
            # src
            (dict(srcports="20-22,80,81", port_nr=True, port_range=True), [["20-22"], ["80"], ["81"]], []),
            (dict(srcports="20-22,80,81", port_nr=True, platfprm="ios", port_range=True), [["20-22"], ["80"], ["81"]], []),
            (dict(srcports="20-22,80,81", port_nr=True, platfprm="cnx", port_range=True), [["20-22"], ["80"], ["81"]], []),
            (dict(srcports="20-22,80,81,82", port_nr=True, port_count=2, port_range=True), [["20-22"], ["80", "81"], ["82"]], []),
            # dst
            (dict(dstports="20-22,80,81", port_nr=True, port_range=True), [], [["20-22"], ["80"], ["81"]]),
            (dict(dstports="20-22,80,81", port_nr=True, platfprm="ios", port_range=True), [], [["20-22"], ["80"], ["81"]]),
            (dict(dstports="20-22,80,81", port_nr=True, platfprm="cnx", port_range=True), [], [["20-22"], ["80"], ["81"]]),
            (dict(dstports="20-22,80,81,82", port_nr=True, port_count=2, port_range=True), [], [["20-22"], ["80", "81"], ["82"]]),
            # combo
            (dict(srcports="20-21,80,81,82", dstports="30-31,90,91,92", port_nr=True, port_range=True),
             [["20-21"], ["80"], ["81"], ["82"]], [["30-31"], ["90"], ["91"], ["92"]]),
            (dict(srcports="20-21,80,81,82", dstports="30-31,90,91,92", port_nr=True, port_count=2, port_range=True),
             [["20-21"], ["80", "81"], ["82"]], [["30-31"], ["90", "91"], ["92"]]),
            # port_range=False
            # src
            (dict(srcports="20-22,80,81", port_nr=True, port_range=False), [["20"], ["21"], ["22"], ["80"], ["81"]], []),
            (dict(srcports="20-22,80,81", port_nr=True, platfprm="ios", port_range=False), [["20"], ["21"], ["22"], ["80"], ["81"]], []),
            (dict(srcports="20-22,80,81", port_nr=True, platfprm="cnx", port_range=False), [["20"], ["21"], ["22"], ["80"], ["81"]], []),
            (dict(srcports="20-22,80,81", port_nr=True, port_count=2, port_range=False), [["20", "21"], ["22", "80"], ["81"]], []),
            # dst
            (dict(dstports="20-22,80,81", port_nr=True, port_range=False), [], [["20"], ["21"], ["22"], ["80"], ["81"]]),
            (dict(dstports="20-22,80,81", port_nr=True, platfprm="ios", port_range=False), [], [["20"], ["21"], ["22"], ["80"], ["81"]]),
            (dict(dstports="20-22,80,81", port_nr=True, platfprm="cnx", port_range=False), [], [["20"], ["21"], ["22"], ["80"], ["81"]]),
            (dict(dstports="20-22,80,81", port_nr=True, port_count=2, port_range=False), [], [["20", "21"], ["22", "80"], ["81"]]),
            # combo
            (dict(srcports="20-21,80,81,82", dstports="30-31,90,91,92", port_nr=True, port_range=True),
             [["20-21"], ["80"], ["81"], ["82"]], [["30-31"], ["90"], ["91"], ["92"]]),
            (dict(srcports="20-21,80,81,82", dstports="30-31,90,91,92", port_nr=True, port_count=2, port_range=False),
             [["20", "21"], ["80", "81"], ["82"]], [["30", "31"], ["90", "91"], ["92"]]),
        ]:
            result = f.range_ports(**kwargs)
            expected = _expected__range_ports__port_count(srcs, dsts)
            self.assertEqual(result, expected, msg=f"{kwargs=}")

    def test_valid__split_range_for_ace(self):
        """functions._split_range_for_ace()"""
        for ports_range, port_count, port_range, expected in [
            # ports unlimited
            ("", 0, True, []),
            ("10,11", 0, True, [["10", "11"]]),
            ("11,10", 0, True, [["11", "10"]]),
            ("10-11,20,21", 0, True, [["10-11"], ["20", "21"]]),
            ("10-11,20-21", 0, True, [["10-11"], ["20-21"]]),
            ("10,11,20-21", 0, True, [["10", "11"], ["20-21"]]),
            ("10,20-21,30,31", 0, True, [["10"], ["20-21"], ["30", "31"]]),
            # port_range=True
            ("", 2, True, []),
            ("10,11,12", 2, True, [["10", "11"], ["12"]]),
            ("10,11,12,20-21,30,31,32,40-41", 2, True, [["10", "11"], ["12"], ["20-21"], ["30", "31"], ["32"], ["40-41"]]),
            # port_range=False
            ("", 2, False, []),
            ("10,11,12", 2, False, [["10", "11"], ["12"]]),
            ("10,11,12,20-21,30,31,32,40-41", 2, False, [["10", "11"], ["12", "20"], ["21", "30"], ["31", "32"], ["40", "41"]]),
        ]:
            result = f._split_range_for_ace(ports_range=ports_range, port_count=port_count, port_range=port_range)
            self.assertEqual(result, expected, msg=f"{ports_range=} {port_count=} {port_range}")


if __name__ == "__main__":
    unittest.main()
