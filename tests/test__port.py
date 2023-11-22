"""Unittest port.py"""

import unittest

import dictdiffer  # type: ignore

from cisco_acl import Port
from cisco_acl import helpers as h
from tests.helpers_test import Helpers, UUID, UUID_R

ALL_PORTS = list(range(1, 65535 + 1))
WO_1 = [i for i in ALL_PORTS if i not in [1]]
WO_12 = [i for i in ALL_PORTS if i not in [1, 2]]
WO_13 = [i for i in ALL_PORTS if i not in [1, 3]]
WO_123 = [i for i in ALL_PORTS if i not in [1, 2, 3]]
GT_65532 = [65533, 65534, 65535]

EQ1 = "eq 1"
EQ2 = "eq 2"
EQ_21 = "eq 21"
EQ12 = "eq 1 2"
EQ13 = "eq 1 3"
EQ_21_23 = "eq 21 23"
EQ123 = "eq 1 2 3"
EQ2456 = "eq 2 4 5 6"
EQ_FTP = "eq ftp"
EQ_FTP_T = "eq ftp telnet"

NEQ1 = "neq 1"
NEQ2 = "neq 2"
NEQ13 = "neq 1 3"
GT = "gt 65532"
GT1 = "gt 1"
LT1 = "lt 1"
LT3 = "lt 3"
R13 = "range 1 3"
R24 = "range 2 4"
R_21_23 = "range 21 23"
R_FTP_T = "range ftp telnet"

EQ0_D = dict(line="", operator="", items=[], ports=[], sport="")
EQ1_D = dict(line="eq 1", operator="eq", items=[1], ports=[1], sport="1")
EQ514_D = dict(line="eq 514", operator="eq", items=[514], ports=[514], sport="514")
EQ12_D = dict(line="eq 1 2", operator="eq", items=[1, 2], ports=[1, 2], sport="1-2")
EQ13_D = dict(line="eq 1 3", operator="eq", items=[1, 3], ports=[1, 3], sport="1,3")
EQ123_D = dict(line="eq 1 2 3", operator="eq", items=[1, 2, 3], ports=[1, 2, 3], sport="1-3")
EQ2456_D = dict(line=EQ2456, operator="eq", items=[2, 4, 5, 6], ports=[2, 4, 5, 6], sport="2,4-6")
EQ_21_D = dict(line="eq 21", operator="eq", items=[21], ports=[21], sport="21")
EQ_FTP_D = dict(line="eq ftp", operator="eq", items=[21], ports=[21], sport="21")
EQ_443_D = dict(line="eq 443", operator="eq", items=[443], ports=[443], sport="443")
EQ_HTTPS_D = dict(line="eq https", operator="eq", items=[443], ports=[443], sport="443")
EQ_21_23_D = dict(line="eq 21 23", operator="eq", items=[21, 23], ports=[21, 23], sport="21,23")
EQ_FTP_T_D = dict(line=EQ_FTP_T, operator="eq", items=[21, 23], ports=[21, 23], sport="21,23")
EQ_CMD_D = dict(line="eq cmd", operator="eq", items=[514], ports=[514], sport="514")
EQ_RSH_D = dict(line="eq rsh", operator="eq", items=[514], ports=[514], sport="514")
EQ_SYSL_D = dict(line="eq syslog", operator="eq", items=[514], ports=[514], sport="514")

NEQ1_D = dict(line="neq 1", operator="neq", items=[1], ports=WO_1, sport="2-65535")
NEQ13_D = dict(line="neq 1 3", operator="neq", items=[1, 3], ports=WO_13, sport="2,4-65535")
GT_D = dict(line="gt 65532", operator="gt", items=[65532], ports=GT_65532, sport="65533-65535")
GT1_D = dict(line="gt 1", operator="gt", items=[1], ports=WO_1, sport="2-65535")
LT1_D = dict(line="lt 1", operator="lt", items=[1], ports=[], sport="")
LT3_D = dict(line="lt 3", operator="lt", items=[3], ports=[1, 2], sport="1-2")
R24_D = dict(line="range 2 4", operator="range", items=[2, 4], ports=[2, 3, 4], sport="2-4")
R_21_23_D = dict(line=R_21_23, operator="range", items=[21, 23], ports=[21, 22, 23], sport="21-23")
R_FTP_T_D = dict(line=R_FTP_T, operator="range", items=[21, 23], ports=[21, 22, 23], sport="21-23")


# noinspection DuplicatedCode
class Test(Helpers):
    """Port"""

    # ========================== redefined ===========================

    def test_valid__hash__(self):
        """Port.__hash__()"""
        line = "eq 1"
        obj = Port(line, protocol="tcp")
        result = obj.__hash__()
        req = "eq 1".__hash__()
        self.assertEqual(result, req, msg=f"{line=}")

    def test_valid__eq__(self):
        """Port.__eq__() __ne__()"""
        obj1 = Port("eq 1", protocol="tcp")
        for obj2, req, in [
            ("eq 1", True),
            (Port("eq 1", protocol="tcp"), True),
            (Port("eq 1", protocol="udp"), True),
            (Port("eq 2", protocol="tcp"), False),
            (Port("range 1 3", protocol="tcp"), False),
        ]:
            result = obj1.__eq__(obj2)
            self.assertEqual(result, req, msg=f"{obj1=} {obj2=}")
            result = obj1.__ne__(obj2)
            self.assertEqual(result, not req, msg=f"{obj1=} {obj2=}")

    def test_valid__lt__(self):
        """Port.__lt__() __le__() __gt__() __ge__()"""
        for obj1, obj2, req_lt, req_le, req_gt, req_ge in [
            (Port("eq 1"), Port("eq 1"), False, True, False, True),
            (Port("eq 1"), Port("eq 2"), True, True, False, False),
            (Port("eq 1"), Port("range 1 3"), True, True, False, False),
            (Port("eq 1 3"), Port("range 1 3"), True, True, False, False),
            (Port("range 1 3"), Port("range 2 4"), True, True, False, False),
        ]:
            result = obj1.__lt__(obj2)
            self.assertEqual(result, req_lt, msg=f"{obj1=} {obj2=}")
            result = obj1.__le__(obj2)
            self.assertEqual(result, req_le, msg=f"{obj1=} {obj2=}")
            result = obj1.__gt__(obj2)
            self.assertEqual(result, req_gt, msg=f"{obj1=} {obj2=}")
            result = obj1.__ge__(obj2)
            self.assertEqual(result, req_ge, msg=f"{obj1=} {obj2=}")

    def test_valid__repr__(self):
        """Port.__repr__()"""
        for kwargs, req in [
            (dict(line="eq 80", platform="asa", protocol="tcp", note="a"),
             "Port(\"eq www\", platform=\"asa\", note=\"a\", protocol=\"tcp\")"),
            (dict(line="eq 80", platform="ios", protocol="", note=""), "Port(\"\")"),
            (dict(line="eq 80 443", platform="ios", protocol="tcp", note=""),
             "Port(\"eq www 443\", protocol=\"tcp\")"),
            (dict(line="eq 80", platform="nxos", protocol="tcp", note="a"),
             "Port(\"eq www\", platform=\"nxos\", note=\"a\", protocol=\"tcp\")"),
        ]:
            obj = Port(**kwargs)
            result = obj.__repr__()
            result = self._quotation(result)
            self.assertEqual(result, req, msg=f"{result=}")

    # =========================== property ===========================

    def test_valid__line(self):
        """Port.line"""
        for kwargs, req_d in [
            (dict(line="eq 1", platform="ios", protocol="", port_nr=False), dict(line="")),
            # range asa
            (dict(line="", platform="asa", protocol="tcp", port_nr=False), EQ0_D),
            (dict(line="eq 1", platform="asa", protocol="tcp", port_nr=False), EQ1_D),
            (dict(line="neq 1", platform="asa", protocol="tcp", port_nr=False), NEQ1_D),
            (dict(line="gt 65532", platform="asa", protocol="tcp", port_nr=False), GT_D),
            (dict(line="lt 3", platform="asa", protocol="tcp", port_nr=False), LT3_D),
            (dict(line="range 2 4", platform="asa", protocol="tcp", port_nr=False), R24_D),
            # range ios
            (dict(line="", platform="ios", protocol="tcp", port_nr=False), EQ0_D),
            (dict(line="eq 1", platform="ios", protocol="tcp", port_nr=False), EQ1_D),
            (dict(line="eq 1 2", platform="ios", protocol="tcp", port_nr=False), EQ12_D),
            (dict(line="eq 1 3", platform="ios", protocol="tcp", port_nr=False), EQ13_D),
            (dict(line="eq 1 2 3", platform="ios", protocol="tcp", port_nr=False), EQ123_D),
            (dict(line="eq 2 4 5 6", platform="ios", protocol="tcp", port_nr=False), EQ2456_D),
            (dict(line="neq 1", platform="ios", protocol="tcp", port_nr=False), NEQ1_D),
            (dict(line="neq 1 3", platform="ios", protocol="tcp", port_nr=False), NEQ13_D),
            (dict(line="gt 65532", platform="ios", protocol="tcp", port_nr=False), GT_D),
            (dict(line="lt 3", platform="ios", protocol="tcp", port_nr=False), LT3_D),
            (dict(line="range 2 4", platform="ios", protocol="tcp", port_nr=False), R24_D),
            # range nxos
            (dict(line="", platform="nxos", protocol="tcp", port_nr=False), EQ0_D),
            (dict(line="eq 1", platform="nxos", protocol="tcp", port_nr=False), EQ1_D),
            (dict(line="neq 1", platform="nxos", protocol="tcp", port_nr=False), NEQ1_D),
            (dict(line="gt 65532", platform="nxos", protocol="tcp", port_nr=False), GT_D),
            (dict(line="lt 3", platform="nxos", protocol="tcp", port_nr=False), LT3_D),
            (dict(line="range 2 4", platform="nxos", protocol="tcp", port_nr=False), R24_D),

            # port_nr asa
            (dict(line="eq 443", platform="asa", protocol="tcp", port_nr=False), EQ_HTTPS_D),
            (dict(line="eq https", platform="asa", protocol="tcp", port_nr=False), EQ_HTTPS_D),
            (dict(line="eq 21", platform="asa", protocol="tcp", port_nr=False), EQ_FTP_D),
            (dict(line="eq ftp", platform="asa", protocol="tcp", port_nr=False), EQ_FTP_D),
            (dict(line="range 21 23", platform="asa", protocol="tcp", port_nr=False), R_FTP_T_D),
            (dict(line=R_FTP_T, platform="asa", protocol="tcp", port_nr=False), R_FTP_T_D),

            (dict(line="eq 443", platform="asa", protocol="tcp", port_nr=True), EQ_443_D),
            (dict(line="eq https", platform="asa", protocol="tcp", port_nr=True), EQ_443_D),
            (dict(line="eq 21", platform="asa", protocol="tcp", port_nr=True), EQ_21_D),
            (dict(line="eq ftp", platform="asa", protocol="tcp", port_nr=True), EQ_21_D),
            (dict(line="range 21 23", platform="asa", protocol="tcp", port_nr=True), R_21_23_D),
            (dict(line=R_FTP_T, platform="asa", protocol="tcp", port_nr=True), R_21_23_D),

            # port_nr ios
            (dict(line="eq 21", platform="ios", protocol="tcp", port_nr=False), EQ_FTP_D),
            (dict(line="eq ftp", platform="ios", protocol="tcp", port_nr=False), EQ_FTP_D),
            (dict(line="eq 21 23", platform="ios", protocol="tcp", port_nr=False), EQ_FTP_T_D),
            (dict(line=EQ_FTP_T, platform="ios", protocol="tcp", port_nr=False), EQ_FTP_T_D),
            (dict(line="range 21 23", platform="ios", protocol="tcp", port_nr=False), R_FTP_T_D),
            (dict(line=R_FTP_T, platform="ios", protocol="tcp", port_nr=False), R_FTP_T_D),

            (dict(line="eq 21", platform="ios", protocol="tcp", port_nr=True), EQ_21_D),
            (dict(line="eq ftp", platform="ios", protocol="tcp", port_nr=True), EQ_21_D),
            (dict(line="eq 21 23", platform="ios", protocol="tcp", port_nr=True), EQ_21_23_D),
            (dict(line=EQ_FTP_T, platform="ios", protocol="tcp", port_nr=True), EQ_21_23_D),
            (dict(line="range 21 23", platform="ios", protocol="tcp", port_nr=True), R_21_23_D),
            (dict(line=R_FTP_T, platform="ios", protocol="tcp", port_nr=True), R_21_23_D),

            # port_nr nxos
            (dict(line="eq 21", platform="nxos", protocol="tcp", port_nr=False), EQ_FTP_D),
            (dict(line="eq ftp", platform="nxos", protocol="tcp", port_nr=False), EQ_FTP_D),
            (dict(line="range 21 23", platform="nxos", protocol="tcp", port_nr=False), R_FTP_T_D),
            (dict(line=R_FTP_T, platform="nxos", protocol="tcp", port_nr=False), R_FTP_T_D),

            (dict(line="eq 21", platform="nxos", protocol="tcp", port_nr=True), EQ_21_D),
            (dict(line="eq ftp", platform="nxos", protocol="tcp", port_nr=True), EQ_21_D),
            (dict(line="range 21 23", platform="nxos", protocol="tcp", port_nr=True), R_21_23_D),
            (dict(line=R_FTP_T, platform="nxos", protocol="tcp", port_nr=True), R_21_23_D),

            # tcp/udp 514 cmd/syslog/rsh ios
            (dict(line="eq 514", platform="asa", protocol="tcp", port_nr=False), EQ_RSH_D),
            (dict(line="eq rsh", platform="asa", protocol="tcp", port_nr=False), EQ_RSH_D),
            (dict(line="eq 514", platform="asa", protocol="udp", port_nr=False), EQ_SYSL_D),
            (dict(line="eq syslog", platform="asa", protocol="udp", port_nr=False), EQ_SYSL_D),
            # tcp/udp 514 cmd/syslog/rsh asa
            (dict(line="eq 514", platform="ios", protocol="tcp", port_nr=False), EQ_CMD_D),
            (dict(line="eq cmd", platform="ios", protocol="tcp", port_nr=False), EQ_CMD_D),
            (dict(line="eq syslog", platform="ios", protocol="tcp", port_nr=False), EQ_CMD_D),
            (dict(line="eq 514", platform="ios", protocol="udp", port_nr=False), EQ_SYSL_D),
            (dict(line="eq syslog", platform="ios", protocol="udp", port_nr=False), EQ_SYSL_D),
            # tcp/udp 514 cmd/syslog/rsh nxos
            (dict(line="eq 514", platform="nxos", protocol="tcp", port_nr=False), EQ_CMD_D),
            (dict(line="eq cmd", platform="nxos", protocol="tcp", port_nr=False), EQ_CMD_D),
            (dict(line="eq 514", platform="nxos", protocol="udp", port_nr=False), EQ_SYSL_D),
            (dict(line="eq syslog", platform="nxos", protocol="udp", port_nr=False), EQ_SYSL_D),
        ]:
            obj = Port(**kwargs)
            self._test_attrs(obj=obj, req_d=req_d, msg=f"{kwargs=}")
            # setter
            obj.line = kwargs["line"]
            self._test_attrs(obj=obj, req_d=req_d, msg=f"{kwargs=}")

    def test_invalid__line(self):
        """Port.line"""
        for platform in h.PLATFORMS:
            for line, error in [
                (1, TypeError),
                ("eq", ValueError),
                ("typo 1", ValueError),
                ("lt 1 2", ValueError),
                ("gt 1 2", ValueError),
                ("range 1", ValueError),
                ("range 1 2 3", ValueError),
            ]:
                with self.assertRaises(error, msg=f"{line=} {platform=}"):
                    Port(line=line, platform=platform)

        # nxos
        for kwargs, error in [
            (dict(line="eq 1 2", platform="nxos"), ValueError),
            (dict(line="eq 1 3", platform="nxos"), ValueError),
            (dict(line="eq 1 2 3", platform="nxos"), ValueError),
            (dict(line="eq 2 4 5 6", platform="nxos"), ValueError),
            (dict(line="neq 1 3", platform="nxos"), ValueError),
            (dict(line="eq syslog", platform="nxos", protocol="tcp", port_nr=False), ValueError),
        ]:
            with self.assertRaises(error, msg=f"{kwargs=}"):
                Port(**kwargs)

    def test_valid__items(self):
        """Port.items"""
        for platform, line, items, req_d in [
            # ios
            ("ios", "eq 2", [1, 2, 3], EQ123_D),
            ("ios", "neq 2", [1, 3], NEQ13_D),
            ("ios", "gt 1", [65532], GT_D),
            ("ios", "lt 1", [3], LT3_D),
            ("ios", "range 1 3", [2, 4], R24_D),
            # nxos
            ("nxos", "eq 2", [1], EQ1_D),
            ("nxos", "neq 2", [1], NEQ1_D),
            ("nxos", "gt 1", [65532], GT_D),
            ("nxos", "lt 1", [3], LT3_D),
            ("nxos", "range 1 3", [2, 4], R24_D),
        ]:
            # setter
            obj = Port(line=line, platform=platform, protocol="tcp")
            obj.items = items
            self._test_attrs(obj=obj, req_d=req_d, msg=f"{line=}")

    def test_invalid__items(self):
        """Port.items"""
        for platform, line, items, error in [
            ("ios", "eq 2", 1, TypeError),
            ("ios", "eq 2", [], ValueError),
            ("ios", "gt 1", [1, 2], ValueError),
            ("ios", "lt 1", [1, 2], ValueError),
            ("ios", "lt 1", [1, 2], ValueError),
            ("nxos", "range 1 3", [1, 2, 3], ValueError),
            ("nxos", "neq 2", [1, 2], ValueError),
        ]:
            obj = Port(line, platform=platform)
            with self.assertRaises(error, msg=f"{items=}"):
                obj.items = items

    def test_valid__operator(self):
        """Port.operator"""
        for platform, line, req_d in [
            # asa
            ("asa", "eq 1", EQ1_D),
            ("asa", "neq 1", NEQ1_D),
            ("asa", "gt 1", GT1_D),
            ("asa", "lt 1", LT1_D),
            ("asa", "range 2 4", R24_D),
            # ios
            ("ios", "eq 1", EQ1_D),
            ("ios", "eq 1 3", EQ13_D),
            ("ios", "neq 1", NEQ1_D),
            ("ios", "neq 1 3", NEQ13_D),
            ("ios", "gt 1", GT1_D),
            ("ios", "lt 1", LT1_D),
            ("ios", "range 2 4", R24_D),
            # nxos
            ("nxos", "eq 1", EQ1_D),
            ("nxos", "neq 1", NEQ1_D),
            ("nxos", "gt 1", GT1_D),
            ("nxos", "lt 1", LT1_D),
            ("nxos", "range 2 4", R24_D),
        ]:
            obj = Port(line=line, platform=platform, protocol="tcp")
            self._test_attrs(obj=obj, req_d=req_d, msg=f"{line=}")

    def test_invalid__operator(self):
        """Port.operator"""
        for line, platform, error in [
            # ios
            ("typo", "ios", ValueError),
            ("eq typo", "ios", ValueError),
            # asa
            ("typo", "asa", ValueError),
            ("eq typo", "asa", ValueError),
            ("eq 1 3", "asa", ValueError),
            ("neq 1 3", "asa", ValueError),
            # nxos
            ("typo", "nxos", ValueError),
            ("eq typo", "nxos", ValueError),
            ("eq 1 3", "nxos", ValueError),
            ("neq 1 3", "nxos", ValueError),
        ]:
            with self.assertRaises(error, msg=f"{line=} {platform=}"):
                Port(line=line, platform=platform)

        with self.assertRaises(TypeError):
            # noinspection PyTypeChecker
            Port(1)

    def test_valid__platform(self):
        """Port.platform()"""
        port_d = dict(line="eq 2")
        for platform, platform_new, line, req_d in [
            # asa
            ("asa", "asa", "eq 2", port_d),
            ("asa", "asa", "eq 2", port_d),
            ("asa", "nxos", "eq 2", port_d),
            # ios
            ("ios", "asa", "eq 2", port_d),
            ("ios", "ios", "eq 2", port_d),
            ("ios", "nxos", "eq 2", port_d),
            # nxos
            ("nxos", "asa", "eq 2", port_d),
            ("nxos", "ios", "eq 2", port_d),
            ("nxos", "nxos", "eq 2", port_d),
        ]:
            msg = f"{platform=} {platform_new=} {line=}"
            obj = Port(line, platform=platform, protocol="tcp")
            self._test_attrs(obj=obj, req_d=req_d, msg=msg)
            # setter
            obj.platform = platform_new
            self._test_attrs(obj=obj, req_d=req_d, msg=msg)

    def test_valid__ports(self):
        """Port.ports"""
        for platform, line, ports, req_d in [
            # asa
            ("asa", "eq 2", [1], EQ1_D),
            ("asa", "neq 2", WO_1, NEQ1_D),
            ("asa", "gt 1", GT_65532, GT_D),
            ("asa", "lt 1", [1, 2], LT3_D),
            ("asa", "range 1 3", [2, 3, 4], R24_D),
            # ios
            ("ios", "eq 2", [1, 2, 3], EQ123_D),
            ("ios", "neq 2", WO_13, NEQ13_D),
            ("ios", "gt 1", GT_65532, GT_D),
            ("ios", "lt 1", [1, 2], LT3_D),
            ("ios", "range 1 3", [2, 3, 4], R24_D),
            # nxos
            ("nxos", "eq 2", [1], EQ1_D),
            ("nxos", "neq 2", WO_1, NEQ1_D),
            ("nxos", "gt 1", GT_65532, GT_D),
            ("nxos", "lt 1", [1, 2], LT3_D),
            ("nxos", "range 1 3", [2, 3, 4], R24_D),
            # type
            ("ios", "eq 2", (1, 2, 3), EQ123_D),
            ("ios", "eq 2", {1, 2, 3}, EQ123_D),
        ]:
            # setter
            obj = Port(line=line, platform=platform, protocol="tcp")
            obj.ports = ports
            self._test_attrs(obj=obj, req_d=req_d, msg=f"{line=}")

    def test_invalid__ports(self):
        """Port.ports"""
        for platform, ports, error in [
            # asa
            ("asa", 1, TypeError),
            ("asa", [], ValueError),
            ("asa", [1, 2, 3], ValueError),
            ("asa", WO_13, ValueError),
            # ios
            ("ios", 1, TypeError),
            ("ios", [], ValueError),
            # nxos
            ("nxos", 1, TypeError),
            ("nxos", [], ValueError),
            ("nxos", [1, 2, 3], ValueError),
            ("nxos", WO_13, ValueError),
        ]:
            obj = Port("eq 1", platform=platform)
            with self.assertRaises(error, msg=f"{ports=}"):
                obj.ports = ports

    def test_valid__port_nr(self):
        """Port.port_nr"""
        for port_nr, protocol, line, req_d in [
            (True, "tcp", "eq 21", dict(line="eq 21", port_nr=True, ports=[21])),
            (True, "tcp", "eq ftp", dict(line="eq 21", port_nr=True, ports=[21])),
            (True, "udp", "eq 67", dict(line="eq 67", port_nr=True, ports=[67])),
            (True, "udp", "eq bootps", dict(line="eq 67", port_nr=True, ports=[67])),
            (False, "tcp", "eq 21", dict(line="eq ftp", port_nr=False, ports=[21])),
            (False, "tcp", "eq ftp", dict(line="eq ftp", port_nr=False, ports=[21])),
            (False, "udp", "eq 67", dict(line="eq bootps", port_nr=False, ports=[67])),
            (False, "udp", "eq bootps", dict(line="eq bootps", port_nr=False, ports=[67])),
        ]:
            obj = Port(line=line, protocol=protocol)
            # setter
            obj.port_nr = port_nr
            self._test_attrs(obj=obj, req_d=req_d, msg=f"{line=}")

    def test_valid__protocol(self):
        """Port.protocol"""
        for protocol, req_d in [
            ("", dict(line="", protocol="")),
            ("ip", dict(line="", protocol="")),
            ("tcp", dict(line="eq 1", protocol="tcp")),
            ("udp", dict(line="eq 1", protocol="udp")),
        ]:
            # setter
            obj = Port(line="eq 1", protocol="tcp")
            obj.protocol = protocol
            self._test_attrs(obj=obj, req_d=req_d, msg=f"{protocol=}")

    def test_valid__sport(self):
        """Port.sport"""
        for platform in h.PLATFORMS:
            for line, sport, req_d in [
                ("eq 2", "1", EQ1_D),
                ("neq 2", "2-65535", NEQ1_D),
                ("gt 1", "65533-65535", GT_D),
                ("lt 1", "1-2", LT3_D),
                ("range 1 3", "2-4", R24_D),
            ]:
                # setter
                obj = Port(line=line, platform=platform, protocol="tcp")
                obj.sport = sport
                self._test_attrs(obj=obj, req_d=req_d, msg=f"{line=}")

        for line, sport, req_d in [
            ("eq 2", "1-3", EQ123_D),
            ("neq 2", "2,4-65535", NEQ13_D),
        ]:
            # setter
            obj = Port(line=line, platform="ios", protocol="tcp")
            obj.sport = sport
            self._test_attrs(obj=obj, req_d=req_d, msg=f"{line=}")

    def test_invalid__sport(self):
        """Port.sport"""
        for platform in h.PLATFORMS:
            for sport, error in [
                ("", ValueError),
            ]:
                obj = Port("eq 1", platform=platform)
                with self.assertRaises(error, msg=f"{sport=}"):
                    obj.sport = sport

        for platform in ["asa", "nxos"]:
            for sport, error in [
                ("1-3", ValueError),
                ("2,4-65535", ValueError),
            ]:
                obj = Port("eq 1", platform=platform)
                with self.assertRaises(error, msg=f"{sport=}"):
                    obj.sport = sport

    # =========================== method =============================

    def test_valid__copy(self):
        """Port.copy()"""
        obj1 = Port("eq www", platform="ios", protocol="tcp", note="a", port_nr=True)
        obj2 = obj1.copy()

        # change obj1 to check obj1 does not depend on obj2
        new_obj1_kwargs = dict(line="eq telnet", platform="nxos", protocol="udp", note="b",
                               port_nr=False)
        for arg, value in new_obj1_kwargs.items():
            setattr(obj1, arg, value)

        req1_d = dict(line="eq 23", platform="nxos", protocol="udp", note="b", port_nr=False)
        req2_d = dict(line="eq 80", platform="ios", protocol="tcp", note="a", port_nr=True)
        self._test_attrs(obj1, req1_d, msg="obj1 does not depend on obj2")
        self._test_attrs(obj2, req2_d, msg="obj2 copied from obj1")

    def test_valid__data(self):
        """Port.data()"""
        kwargs1 = dict(line="eq www 443", platform="ios", protocol="tcp", note="a", port_nr=True)
        req1 = dict(line="eq 80 443", platform="ios", protocol="tcp", note="a", port_nr=True,
                    items=[80, 443], operator="eq", ports=[80, 443], sport="80,443")

        for kwargs, req_d in [
            (kwargs1, req1),
        ]:
            obj = Port(**kwargs)
            obj.uuid = UUID

            result = obj.data()
            diff = list(dictdiffer.diff(first=result, second=req_d))
            self.assertEqual(diff, [], msg=f"{kwargs=}")

            result = obj.data(uuid=True)
            diff = list(dictdiffer.diff(first=result, second=req_d))
            self.assertEqual(diff, UUID_R, msg=f"{kwargs=}")

    # =========================== helper =============================

    def test_valid__line__operator(self):
        """Port._line__operator()"""
        obj = Port("eq 1")
        for items, req in [
            (["eq", "1"], "eq"),
            (["neq", "1"], "neq"),
            (["lt", "1"], "lt"),
            (["gt", "1"], "gt"),
            (["range", "1", "2"], "range"),
        ]:
            result = obj._line__operator(items)
            self.assertEqual(result, req, msg=f"{items=}")

    def test_invalid__line__operator(self):
        """Port._line__operator()"""
        obj = Port("eq 1")
        for items, error in [
            ([], ValueError),
            (["typo", "1"], ValueError),
        ]:
            with self.assertRaises(error, msg=f"{items=}"):
                obj._line__operator(items)

    def test_valid__line__items_to_ints(self):
        """Port._line__items_to_ints()"""
        for platform in h.PLATFORMS:
            for line, items, req in [
                ("eq 1", ["1"], [1]),
                ("neq 1", ["1"], [1]),
                ("lt 1", ["1"], [1]),
                ("gt 1", ["1"], [1]),
                ("range 2 4", ["1", "3"], [1, 3]),
            ]:
                obj = Port(line, platform=platform)
                result = obj._line__items_to_ints(items)
                self.assertEqual(result, req, msg=f"{items=}")
        # ios
        for line, items, req in [
            ("eq 1", ["1", "2"], [1, 2]),
            ("neq 1", ["1", "2"], [1, 2]),
        ]:
            obj = Port(line, platform="ios")
            result = obj._line__items_to_ints(items)
            self.assertEqual(result, req, msg=f"{items=}")

    def test_invalid__line__items_to_ints(self):
        """Port._line__items_to_ints()"""
        for platform, line, ports, error in [
            # asa
            ("asa", "eq 1", ["1", "2"], ValueError),
            ("asa", "neq 1", ["1", "2"], ValueError),
            # ios
            ("ios", "eq 1", [], ValueError),
            ("ios", "lt 1", ["1", "2"], ValueError),
            ("ios", "gt 1", ["1", "2"], ValueError),
            ("ios", "range 2 4", ["1"], ValueError),
            ("ios", "range 2 4", ["1", "2", "3"], ValueError),
            # nxos
            ("nxos", "eq 1", ["1", "2"], ValueError),
            ("nxos", "neq 1", ["1", "2"], ValueError),
        ]:
            obj = Port(line, platform=platform)
            with self.assertRaises(error, msg=f"{platform=} {line=} {ports=}"):
                obj._line__items_to_ints(ports)

    def test_valid__items_to_ports(self):
        """Port._items_to_ports()"""
        for line, items, req in [
            ("eq 1", [1, 3], [1, 3]),
            ("neq 1", [1], WO_1),
            ("neq 1", [1, 2], WO_12),
            ("neq 1", [1, 3], WO_13),
            ("neq 1", [1, 2, 3], WO_123),
            ("gt 1", [1], WO_1),
            ("lt 1", [3], [1, 2]),
            ("range 1 2", [2, 4], [2, 3, 4]),
        ]:
            obj = Port(line)
            result = obj._items_to_ports(items)
            self.assertEqual(result, req, msg=f"{items=}")

    def test_valid__ports_to_items(self):
        """Port._ports_to_items()"""
        for line, items, req in [
            ("eq 1 3", [1, 3], [1, 3]),
            ("neq 1", WO_1, [1]),
            ("neq 1 2", WO_12, [1, 2]),
            ("neq 1 3", WO_13, [1, 3]),
            ("neq 1 2 3", WO_123, [1, 2, 3]),
            ("gt 1", WO_1, [1]),
            ("lt 3", [1, 2], [3]),
            ("range 2 4", [2, 3, 4], [2, 4]),
        ]:
            obj = Port(line)
            result = obj._ports_to_items(items)
            self.assertEqual(result, req, msg=f"{items=}")


if __name__ == "__main__":
    unittest.main()
