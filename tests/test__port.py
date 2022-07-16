"""Unittest port.py"""

import unittest

from cisco_acl import Port
from tests.helpers_test import Helpers

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
EQ1_D = dict(line=EQ1, operator="eq", items=[1], ports=[1], sport="1")
EQ514_D = dict(line="eq 514", operator="eq", items=[514], ports=[514], sport="514")
EQ12_D = dict(line=EQ12, operator="eq", items=[1, 2], ports=[1, 2], sport="1-2")
EQ13_D = dict(line=EQ13, operator="eq", items=[1, 3], ports=[1, 3], sport="1,3")
EQ123_D = dict(line=EQ123, operator="eq", items=[1, 2, 3], ports=[1, 2, 3], sport="1-3")
EQ2456_D = dict(line=EQ2456, operator="eq", items=[2, 4, 5, 6], ports=[2, 4, 5, 6], sport="2,4-6")
EQ_21_D = dict(line=EQ_21, operator="eq", items=[21], ports=[21], sport="21")
EQ_21_23_D = dict(line=EQ_21_23, operator="eq", items=[21, 23], ports=[21, 23], sport="21,23")
EQ_FTP_D = dict(line=EQ_FTP, operator="eq", items=[21], ports=[21], sport="21")
EQ_FTP_T_D = dict(line=EQ_FTP_T, operator="eq", items=[21, 23], ports=[21, 23], sport="21,23")
EQ_CMD_D = dict(line="eq cmd", operator="eq", items=[514], ports=[514], sport="514")
EQ_SYSL_D = dict(line="eq syslog", operator="eq", items=[514], ports=[514], sport="514")

NEQ1_D = dict(line=NEQ1, operator="neq", items=[1], ports=WO_1, sport="2-65535")
NEQ13_D = dict(line=NEQ13, operator="neq", items=[1, 3], ports=WO_13, sport="2,4-65535")
GT_D = dict(line=GT, operator="gt", items=[65532], ports=GT_65532, sport="65533-65535")
GT1_D = dict(line=GT1, operator="gt", items=[1], ports=WO_1, sport="2-65535")
LT1_D = dict(line=LT1, operator="lt", items=[1], ports=[], sport="")
LT3_D = dict(line=LT3, operator="lt", items=[3], ports=[1, 2], sport="1-2")
R24_D = dict(line=R24, operator="range", items=[2, 4], ports=[2, 3, 4], sport="2-4")
R_21_23_D = dict(line=R_21_23, operator="range", items=[21, 23], ports=[21, 22, 23], sport="21-23")
R_FTP_T_D = dict(line=R_FTP_T, operator="range", items=[21, 23], ports=[21, 22, 23], sport="21-23")


# noinspection DuplicatedCode
class Test(Helpers):
    """Port"""

    # ========================== redefined ===========================

    def test_valid__hash__(self):
        """Port.__hash__()"""
        line = EQ1
        port_o = Port(line, protocol="tcp")
        result = port_o.__hash__()
        req = EQ1.__hash__()
        self.assertEqual(result, req, msg=f"{line=}")

    def test_valid__eq__(self):
        """Port.__eq__() __ne__()"""
        port_o = Port(EQ1, protocol="tcp")
        for other_o, req, in [
            (EQ1, True),
            (Port(EQ1, protocol="tcp"), True),
            (Port(EQ1, protocol="udp"), True),
            (Port(EQ2, protocol="tcp"), False),
            (Port(R13, protocol="tcp"), False),
        ]:
            result = port_o.__eq__(other_o)
            self.assertEqual(result, req, msg=f"{port_o=} {other_o=}")
            result = port_o.__ne__(other_o)
            self.assertEqual(result, not req, msg=f"{port_o=} {other_o=}")

    def test_valid__lt__(self):
        """Port.__lt__() __le__() __gt__() __ge__()"""
        for port_o, other_o, req_lt, req_le, req_gt, req_ge in [
            (Port(EQ1), Port(EQ1), False, True, False, True),
            (Port(EQ1), Port(EQ2), True, True, False, False),
            (Port(EQ1), Port(R13), True, True, False, False),
            (Port(EQ13), Port(R13), True, True, False, False),
            (Port(R13), Port(R24), True, True, False, False),
        ]:
            result = port_o.__lt__(other_o)
            self.assertEqual(result, req_lt, msg=f"{port_o=} {other_o=}")
            result = port_o.__le__(other_o)
            self.assertEqual(result, req_le, msg=f"{port_o=} {other_o=}")
            result = port_o.__gt__(other_o)
            self.assertEqual(result, req_gt, msg=f"{port_o=} {other_o=}")
            result = port_o.__ge__(other_o)
            self.assertEqual(result, req_ge, msg=f"{port_o=} {other_o=}")

    # =========================== property ===========================

    def test_valid__line(self):
        """Port.line"""
        for kwargs, req_d in [
            (dict(line=EQ1, platform="ios", protocol="", numerically=False), dict(line="")),
            # range ios
            (dict(line="", platform="ios", protocol="tcp", numerically=False), EQ0_D),
            (dict(line=EQ1, platform="ios", protocol="tcp", numerically=False), EQ1_D),
            (dict(line=EQ12, platform="ios", protocol="tcp", numerically=False), EQ12_D),
            (dict(line=EQ13, platform="ios", protocol="tcp", numerically=False), EQ13_D),
            (dict(line=EQ123, platform="ios", protocol="tcp", numerically=False), EQ123_D),
            (dict(line=EQ2456, platform="ios", protocol="tcp", numerically=False), EQ2456_D),
            (dict(line=NEQ1, platform="ios", protocol="tcp", numerically=False), NEQ1_D),
            (dict(line=NEQ13, platform="ios", protocol="tcp", numerically=False), NEQ13_D),
            (dict(line=GT, platform="ios", protocol="tcp", numerically=False), GT_D),
            (dict(line=LT3, platform="ios", protocol="tcp", numerically=False), LT3_D),
            (dict(line=R24, platform="ios", protocol="tcp", numerically=False), R24_D),
            # range nxos
            (dict(line="", platform="nxos", protocol="tcp", numerically=False), EQ0_D),
            (dict(line=EQ1, platform="nxos", protocol="tcp", numerically=False), EQ1_D),
            (dict(line=NEQ1, platform="nxos", protocol="tcp", numerically=False), NEQ1_D),
            (dict(line=GT, platform="nxos", protocol="tcp", numerically=False), GT_D),
            (dict(line=LT3, platform="nxos", protocol="tcp", numerically=False), LT3_D),
            (dict(line=R24, platform="nxos", protocol="tcp", numerically=False), R24_D),

            # numerically ios
            (dict(line=EQ_21, platform="ios", protocol="tcp", numerically=False), EQ_FTP_D),
            (dict(line=EQ_FTP, platform="ios", protocol="tcp", numerically=False), EQ_FTP_D),
            (dict(line=EQ_21_23, platform="ios", protocol="tcp", numerically=False), EQ_FTP_T_D),
            (dict(line=EQ_FTP_T, platform="ios", protocol="tcp", numerically=False), EQ_FTP_T_D),
            (dict(line=R_21_23, platform="ios", protocol="tcp", numerically=False), R_FTP_T_D),
            (dict(line=R_FTP_T, platform="ios", protocol="tcp", numerically=False), R_FTP_T_D),

            (dict(line=EQ_21, platform="ios", protocol="tcp", numerically=True), EQ_21_D),
            (dict(line=EQ_FTP, platform="ios", protocol="tcp", numerically=True), EQ_21_D),
            (dict(line=EQ_21_23, platform="ios", protocol="tcp", numerically=True), EQ_21_23_D),
            (dict(line=EQ_FTP_T, platform="ios", protocol="tcp", numerically=True), EQ_21_23_D),
            (dict(line=R_21_23, platform="ios", protocol="tcp", numerically=True), R_21_23_D),
            (dict(line=R_FTP_T, platform="ios", protocol="tcp", numerically=True), R_21_23_D),

            # numerically nxos
            (dict(line=EQ_21, platform="nxos", protocol="tcp", numerically=False), EQ_FTP_D),
            (dict(line=EQ_FTP, platform="nxos", protocol="tcp", numerically=False), EQ_FTP_D),
            (dict(line=R_21_23, platform="nxos", protocol="tcp", numerically=False), R_FTP_T_D),
            (dict(line=R_FTP_T, platform="nxos", protocol="tcp", numerically=False), R_FTP_T_D),

            (dict(line=EQ_21, platform="nxos", protocol="tcp", numerically=True), EQ_21_D),
            (dict(line=EQ_FTP, platform="nxos", protocol="tcp", numerically=True), EQ_21_D),
            (dict(line=R_21_23, platform="nxos", protocol="tcp", numerically=True), R_21_23_D),
            (dict(line=R_FTP_T, platform="nxos", protocol="tcp", numerically=True), R_21_23_D),

            # tcp/udp 514 cmd/syslog ios
            (dict(line="eq 514", platform="ios", protocol="tcp", numerically=False), EQ_CMD_D),
            (dict(line="eq cmd", platform="ios", protocol="tcp", numerically=False), EQ_CMD_D),
            (dict(line="eq syslog", platform="ios", protocol="tcp", numerically=False), EQ_CMD_D),
            (dict(line="eq 514", platform="ios", protocol="udp", numerically=False), EQ_SYSL_D),
            (dict(line="eq syslog", platform="ios", protocol="udp", numerically=False), EQ_SYSL_D),
            # tcp/udp 514 cmd/syslog nxos
            (dict(line="eq 514", platform="nxos", protocol="tcp", numerically=False), EQ_CMD_D),
            (dict(line="eq cmd", platform="nxos", protocol="tcp", numerically=False), EQ_CMD_D),
            (dict(line="eq 514", platform="nxos", protocol="udp", numerically=False), EQ_SYSL_D),
            (dict(line="eq syslog", platform="nxos", protocol="udp", numerically=False), EQ_SYSL_D),
        ]:
            # getter
            port_o = Port(**kwargs)
            self._test_attrs(obj=port_o, req_d=req_d, msg=f"getter {kwargs=}")

            # setter
            port_o.line = kwargs["line"]
            self._test_attrs(obj=port_o, req_d=req_d, msg=f"setter {kwargs=}")

        # deleter
        port_o = Port(EQ1)
        # noinspection PyPropertyAccess
        del port_o.line
        self._test_attrs(obj=port_o, req_d=EQ0_D, msg="deleter line")

    def test_invalid__line(self):
        """Port.line"""
        for kwargs, error in [
            # all platforms
            (dict(line=1, platform="ios"), TypeError),
            (dict(line="eq", platform="ios"), ValueError),
            (dict(line="typo 1", platform="ios"), ValueError),
            (dict(line="lt 1 2", platform="ios"), ValueError),
            (dict(line="gt 1 2", platform="ios"), ValueError),
            (dict(line="range 1", platform="ios"), ValueError),
            (dict(line="range 1 2 3", platform="ios"), ValueError),
            # nxos
            (dict(line=EQ12, platform="nxos"), ValueError),
            (dict(line=EQ13, platform="nxos"), ValueError),
            (dict(line=EQ123, platform="nxos"), ValueError),
            (dict(line=EQ2456, platform="nxos"), ValueError),
            (dict(line=NEQ13, platform="nxos"), ValueError),
            (
            dict(line="eq syslog", platform="nxos", protocol="tcp", numerically=False), ValueError),
        ]:
            with self.assertRaises(error, msg=f"{kwargs=}"):
                Port(**kwargs)

    def test_valid__items(self):
        """Port.items"""
        for platform, line, items, req_d in [
            ("ios", EQ2, [1, 2, 3], EQ123_D),
            ("ios", NEQ2, [1, 3], NEQ13_D),
            ("ios", GT1, [65532], GT_D),
            ("ios", LT1, [3], LT3_D),
            ("ios", R13, [2, 4], R24_D),

            ("nxos", EQ2, [1], EQ1_D),
            ("nxos", NEQ2, [1], NEQ1_D),
            ("nxos", GT1, [65532], GT_D),
            ("nxos", LT1, [3], LT3_D),
            ("nxos", R13, [2, 4], R24_D),

        ]:
            # setter
            port_o = Port(line=line, platform=platform, protocol="tcp")
            port_o.items = items
            self._test_attrs(obj=port_o, req_d=req_d, msg=f"setter {line=}")

        # deleter
        port_o = Port(EQ1)
        with self.assertRaises(AttributeError, msg=f"{items=}"):
            # noinspection PyPropertyAccess
            del port_o.items

    def test_invalid__items(self):
        """Port.items"""
        for platform, line, items, error in [
            ("ios", EQ2, [], ValueError),
            ("ios", GT1, [1, 2], ValueError),
            ("ios", LT1, [1, 2], ValueError),
            ("ios", LT1, [1, 2], ValueError),
            ("nxos", R13, [1, 2, 3], ValueError),
            ("nxos", NEQ2, [1, 2], ValueError),
        ]:
            port_o = Port(line, platform=platform)
            with self.assertRaises(error, msg=f"{items=}"):
                port_o.items = items

    def test_valid__operator(self):
        """Port.operator"""
        for platform, line, operator, req_d in [
            ("ios", EQ1, "eq", EQ1_D),
            ("ios", EQ1, "neq", NEQ1_D),
            ("ios", EQ1, "gt", GT1_D),
            ("ios", EQ1, "lt", LT1_D),
            ("ios", EQ13, "eq", EQ13_D),
            ("ios", EQ13, "neq", NEQ13_D),
            ("ios", NEQ1, "eq", EQ1_D),
            ("ios", NEQ1, "neq", NEQ1_D),
            ("ios", NEQ1, "gt", GT1_D),
            ("ios", NEQ1, "lt", LT1_D),
            ("ios", NEQ13, "eq", EQ13_D),
            ("ios", NEQ13, "neq", NEQ13_D),
            ("ios", GT1, "eq", EQ1_D),
            ("ios", GT1, "neq", NEQ1_D),
            ("ios", GT1, "gt", GT1_D),
            ("ios", GT1, "lt", LT1_D),
            ("ios", LT1, "eq", EQ1_D),
            ("ios", LT1, "neq", NEQ1_D),
            ("ios", LT1, "gt", GT1_D),
            ("ios", LT1, "lt", LT1_D),
            ("ios", R24, "range", R24_D),

            ("nxos", EQ1, "eq", EQ1_D),
            ("nxos", EQ1, "neq", NEQ1_D),
            ("nxos", EQ1, "gt", GT1_D),
            ("nxos", EQ1, "lt", LT1_D),
            ("nxos", NEQ1, "eq", EQ1_D),
            ("nxos", NEQ1, "neq", NEQ1_D),
            ("nxos", NEQ1, "gt", GT1_D),
            ("nxos", NEQ1, "lt", LT1_D),
            ("nxos", GT1, "eq", EQ1_D),
            ("nxos", GT1, "neq", NEQ1_D),
            ("nxos", GT1, "gt", GT1_D),
            ("nxos", GT1, "lt", LT1_D),
            ("nxos", LT1, "eq", EQ1_D),
            ("nxos", LT1, "neq", NEQ1_D),
            ("nxos", LT1, "gt", GT1_D),
            ("nxos", LT1, "lt", LT1_D),
            ("nxos", R24, "range", R24_D),

        ]:
            # setter
            port_o = Port(line=line, platform=platform, protocol="tcp")
            port_o.operator = operator
            self._test_attrs(obj=port_o, req_d=req_d, msg=f"setter {line=}")

        # deleter
        port_o = Port(EQ1)
        # noinspection PyPropertyAccess
        del port_o.operator
        self._test_attrs(obj=port_o, req_d=EQ0_D, msg="deleter line")

    def test_invalid__operator(self):
        """Port.operator"""
        for platform, line, operator, error in [
            ("ios", EQ1, "range", ValueError),
            ("ios", EQ13, "gt", ValueError),
            ("ios", EQ13, "lt", ValueError),
            ("ios", EQ13, "range", ValueError),
            ("ios", NEQ1, "range", ValueError),
            ("ios", NEQ13, "gt", ValueError),
            ("ios", NEQ13, "lt", ValueError),
            ("ios", NEQ13, "range", ValueError),
            ("ios", GT1, "range", ValueError),
            ("ios", LT1, "range", ValueError),
            ("ios", R24, "eq", ValueError),
            ("ios", R24, "neq", ValueError),
            ("ios", R24, "gt", ValueError),
            ("ios", R24, "lt", ValueError),
        ]:
            port_o = Port(line, platform=platform)
            with self.assertRaises(error, msg=f"{line=}"):
                port_o.operator = operator

        with self.assertRaises(TypeError):
            # noinspection PyTypeChecker
            Port(1)

    def test_valid__ports(self):
        """Port.ports"""
        for platform, line, ports, req_d in [
            ("ios", EQ2, [1, 2, 3], EQ123_D),
            ("ios", NEQ2, WO_13, NEQ13_D),
            ("ios", GT1, GT_65532, GT_D),
            ("ios", LT1, [1, 2], LT3_D),
            ("ios", R13, [2, 3, 4], R24_D),

            ("nxos", EQ2, [1], EQ1_D),
            ("nxos", NEQ2, WO_1, NEQ1_D),
            ("nxos", GT1, GT_65532, GT_D),
            ("nxos", LT1, [1, 2], LT3_D),
            ("nxos", R13, [2, 3, 4], R24_D),

        ]:
            # setter
            port_o = Port(line=line, platform=platform, protocol="tcp")
            port_o.ports = ports
            self._test_attrs(obj=port_o, req_d=req_d, msg=f"setter {line=}")

        # deleter
        port_o = Port(EQ1)
        with self.assertRaises(AttributeError, msg=f"{ports=}"):
            # noinspection PyPropertyAccess
            del port_o.ports

    def test_invalid__ports(self):
        """Port.ports"""
        for platform, line, ports, error in [
            ("ios", EQ2, [], ValueError),
            ("nxos", EQ2, [1, 2, 3], ValueError),
            ("nxos", NEQ2, WO_13, ValueError),
        ]:
            port_o = Port(EQ1, platform=platform)
            with self.assertRaises(error, msg=f"{ports=}"):
                port_o.ports = ports

    def test_valid__protocol(self):
        """Port.protocol"""
        for protocol, req_d in [
            ("", dict(line="", protocol="")),
            ("ip", dict(line="", protocol="ip")),
            ("tcp", dict(line=EQ1, protocol="tcp")),
            ("udp", dict(line=EQ1, protocol="udp")),
        ]:
            # setter
            port_o = Port(line=EQ1, protocol="tcp")
            port_o.protocol = protocol
            self._test_attrs(obj=port_o, req_d=req_d, msg=f"setter {protocol=}")

    def test_valid__sport(self):
        """Port.sport"""
        for platform, line, sport, req_d in [
            ("ios", EQ2, "1-3", EQ123_D),
            ("ios", NEQ2, "2,4-65535", NEQ13_D),
            ("ios", GT1, "65533-65535", GT_D),
            ("ios", LT1, "1-2", LT3_D),
            ("ios", R13, "2-4", R24_D),

            ("nxos", EQ2, "1", EQ1_D),
            ("nxos", NEQ2, "2-65535", NEQ1_D),
            ("nxos", GT1, "65533-65535", GT_D),
            ("nxos", LT1, "1-2", LT3_D),
            ("nxos", R13, "2-4", R24_D),

        ]:
            # setter
            port_o = Port(line=line, platform=platform, protocol="tcp")
            port_o.sport = sport
            self._test_attrs(obj=port_o, req_d=req_d, msg=f"setter {line=}")

        # deleter
        port_o = Port(EQ1)
        with self.assertRaises(AttributeError, msg=f"{sport=}"):
            # noinspection PyPropertyAccess
            del port_o.sport

    def test_invalid__sport(self):
        """Port.sport"""
        for platform, line, sport, error in [
            ("ios", EQ2, "", ValueError),
            ("nxos", EQ2, "1-3", ValueError),
            ("nxos", NEQ2, "2,4-65535", ValueError),
        ]:
            port_o = Port(EQ1, platform=platform)
            with self.assertRaises(error, msg=f"{sport=}"):
                port_o.sport = sport

    # =========================== helpers ============================

    def test_valid__line__operator(self):
        """Port._line__operator()"""
        port_o = Port(EQ1)
        for items, req in [
            (["eq", "1"], "eq"),
            (["neq", "1"], "neq"),
            (["lt", "1"], "lt"),
            (["gt", "1"], "gt"),
            (["range", "1", "2"], "range"),
        ]:
            result = port_o._line__operator(items)
            self.assertEqual(result, req, msg=f"{items=}")

    def test_invalid__line__operator(self):
        """Port._line__operator()"""
        port_o = Port(EQ1)
        for items, error in [
            ([], ValueError),
            (["typo", "1"], ValueError),
        ]:
            with self.assertRaises(error, msg=f"{items=}"):
                port_o._line__operator(items)

    def test_valid__line__items_to_ints(self):
        """Port._line__items_to_ints()"""
        for platform, line, items, req in [
            ("ios", EQ1, ["1"], [1]),
            ("ios", EQ1, ["1", "2"], [1, 2]),
            ("ios", NEQ1, ["1"], [1]),
            ("ios", NEQ1, ["1", "2"], [1, 2]),
            ("ios", LT1, ["1"], [1]),
            ("ios", GT1, ["1"], [1]),
            ("ios", R24, ["1", "3"], [1, 3]),

            ("nxos", EQ1, ["1"], [1]),
            ("nxos", NEQ1, ["1"], [1]),
            ("nxos", LT1, ["1"], [1]),
            ("nxos", GT1, ["1"], [1]),
            ("nxos", R24, ["1", "3"], [1, 3]),
        ]:
            port_o = Port(line, platform=platform)
            result = port_o._line__items_to_ints(items)
            self.assertEqual(result, req, msg=f"{items=}")

    def test_invalid__line__items_to_ints(self):
        """Port._line__items_to_ints()"""
        for platform, line, ports, error in [
            ("ios", EQ1, [], ValueError),
            ("ios", LT1, ["1", "2"], ValueError),
            ("ios", GT1, ["1", "2"], ValueError),
            ("ios", R24, ["1"], ValueError),
            ("ios", R24, ["1", "2", "3"], ValueError),

            ("nxos", EQ1, ["1", "2"], ValueError),
            ("nxos", NEQ1, ["1", "2"], ValueError),
        ]:
            port_o = Port(line, platform=platform)
            with self.assertRaises(error, msg=f"{platform=} {line=} {ports=}"):
                port_o._line__items_to_ints(ports)

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
            port_o = Port(line)
            result = port_o._items_to_ports(items)
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
            port_o = Port(line)
            result = port_o._ports_to_items(items)
            self.assertEqual(result, req, msg=f"{items=}")


if __name__ == "__main__":
    unittest.main()
