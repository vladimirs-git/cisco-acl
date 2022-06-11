"""Unittest port.py"""

import unittest

from cisco_acl import Port
from tests_.helpers_test import Helpers

ALL_PORTS = list(range(1, 65535 + 1))
WO_1 = [i for i in ALL_PORTS if i not in [1]]
WO_12 = [i for i in ALL_PORTS if i not in [1, 2]]
WO_13 = [i for i in ALL_PORTS if i not in [1, 3]]
WO_123 = [i for i in ALL_PORTS if i not in [1, 2, 3]]
GT_65532 = [65533, 65534, 65535]

EQ1 = "eq 1"
EQ2 = "eq 2"
EQ12 = "eq 1 2"
EQ13 = "eq 1 3"
EQ123 = "eq 1 2 3"
EQ2456 = "eq 2 4 5 6"
NEQ1 = "neq 1"
NEQ2 = "neq 2"
NEQ13 = "neq 1 3"
GT = "gt 65532"
GT1 = "gt 1"
LT1 = "lt 1"
LT3 = "lt 3"
RANGE13 = "range 1 3"
RANGE24 = "range 2 4"

EQ0_D = dict(line="", operator="", items=[], ports=[], sport="")
EQ1_D = dict(line=EQ1, operator="eq", items=[1], ports=[1], sport="1")
EQ12_D = dict(line=EQ12, operator="eq", items=[1, 2], ports=[1, 2], sport="1-2")
EQ13_D = dict(line=EQ13, operator="eq", items=[1, 3], ports=[1, 3], sport="1,3")
EQ123_D = dict(line=EQ123, operator="eq", items=[1, 2, 3], ports=[1, 2, 3], sport="1-3")
EQ2456_D = dict(line=EQ2456, operator="eq", items=[2, 4, 5, 6], ports=[2, 4, 5, 6], sport="2,4-6")
NEQ1_D = dict(line=NEQ1, operator="neq", items=[1], ports=WO_1, sport="2-65535")
NEQ13_D = dict(line=NEQ13, operator="neq", items=[1, 3], ports=WO_13, sport="2,4-65535")
GT_D = dict(line=GT, operator="gt", items=[65532], ports=GT_65532, sport="65533-65535")
GT1_D = dict(line=GT1, operator="gt", items=[1], ports=WO_1, sport="2-65535")
LT1_D = dict(line=LT1, operator="lt", items=[1], ports=[], sport="")
LT3_D = dict(line=LT3, operator="lt", items=[3], ports=[1, 2], sport="1-2")
RANGE24_D = dict(line=RANGE24, operator="range", items=[2, 4], ports=[2, 3, 4], sport="2-4")


# noinspection DuplicatedCode
class Test(Helpers):
    """Port"""

    # ========================== redefined ===========================

    def test_valid__hash__(self):
        """Port.__hash__()"""
        line = EQ1
        port_o = Port(line)
        result = port_o.__hash__()
        req = EQ1.__hash__()
        self.assertEqual(result, req, msg=f"{line=}")

    def test_valid__eq__(self):
        """Port.__eq__() __ne__()"""
        port_o = Port(EQ1)
        for other_o, req, in [
            (EQ1, True),
            (Port(EQ1), True),
            (Port(EQ2), False),
            (Port(RANGE13), False),
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
            (Port(EQ1), Port(RANGE13), True, True, False, False),
            (Port(EQ13), Port(RANGE13), True, True, False, False),
            (Port(RANGE13), Port(RANGE24), True, True, False, False),
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
        for platform, line, req_d in [
            ("ios", "", EQ0_D),
            ("ios", EQ1, EQ1_D),
            ("ios", EQ12, EQ12_D),
            ("ios", EQ13, EQ13_D),
            ("ios", EQ123, EQ123_D),
            ("ios", EQ2456, EQ2456_D),
            ("ios", NEQ1, NEQ1_D),
            ("ios", NEQ13, NEQ13_D),
            ("ios", GT, GT_D),
            ("ios", LT3, LT3_D),
            ("ios", RANGE24, RANGE24_D),

            ("cnx", "", EQ0_D),
            ("cnx", EQ1, EQ1_D),
            ("cnx", NEQ1, NEQ1_D),
            ("cnx", GT, GT_D),
            ("cnx", LT3, LT3_D),
            ("cnx", RANGE24, RANGE24_D),
        ]:
            # getter
            port_o = Port(line=line, platform=platform)
            self._test_attrs(obj=port_o, req_d=req_d, msg=f"getter {line=}")

            # setter
            port_o.line = line
            self._test_attrs(obj=port_o, req_d=req_d, msg=f"setter {line=}")

            # deleter
        port_o = Port(EQ1)
        # noinspection PyPropertyAccess
        del port_o.line
        self._test_attrs(obj=port_o, req_d=EQ0_D, msg="deleter line")

    def test_invalid__line(self):
        """Port.line"""
        for platform, line, error in [
            ("ios", 1, TypeError),
            ("ios", "eq", ValueError),
            ("ios", "typo 1", ValueError),
            ("ios", "lt 1 2", ValueError),
            ("ios", "gt 1 2", ValueError),
            ("ios", "range 1", ValueError),
            ("ios", "range 1 2 3", ValueError),

            ("cnx", EQ12, ValueError),
            ("cnx", EQ13, ValueError),
            ("cnx", EQ123, ValueError),
            ("cnx", EQ2456, ValueError),
            ("cnx", NEQ13, ValueError),
        ]:
            with self.assertRaises(error, msg=f"{line=}"):
                Port(line, platform=platform)

    def test_valid__items(self):
        """Port.items"""
        for platform, line, items, req_d in [
            ("ios", EQ2, [1, 2, 3], EQ123_D),
            ("ios", NEQ2, [1, 3], NEQ13_D),
            ("ios", GT1, [65532], GT_D),
            ("ios", LT1, [3], LT3_D),
            ("ios", RANGE13, [2, 4], RANGE24_D),

            ("cnx", EQ2, [1], EQ1_D),
            ("cnx", NEQ2, [1], NEQ1_D),
            ("cnx", GT1, [65532], GT_D),
            ("cnx", LT1, [3], LT3_D),
            ("cnx", RANGE13, [2, 4], RANGE24_D),

        ]:
            # setter
            port_o = Port(line=line, platform=platform)
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
            ("cnx", RANGE13, [1, 2, 3], ValueError),
            ("cnx", NEQ2, [1, 2], ValueError),
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
            ("ios", RANGE24, "range", RANGE24_D),

            ("cnx", EQ1, "eq", EQ1_D),
            ("cnx", EQ1, "neq", NEQ1_D),
            ("cnx", EQ1, "gt", GT1_D),
            ("cnx", EQ1, "lt", LT1_D),
            ("cnx", NEQ1, "eq", EQ1_D),
            ("cnx", NEQ1, "neq", NEQ1_D),
            ("cnx", NEQ1, "gt", GT1_D),
            ("cnx", NEQ1, "lt", LT1_D),
            ("cnx", GT1, "eq", EQ1_D),
            ("cnx", GT1, "neq", NEQ1_D),
            ("cnx", GT1, "gt", GT1_D),
            ("cnx", GT1, "lt", LT1_D),
            ("cnx", LT1, "eq", EQ1_D),
            ("cnx", LT1, "neq", NEQ1_D),
            ("cnx", LT1, "gt", GT1_D),
            ("cnx", LT1, "lt", LT1_D),
            ("cnx", RANGE24, "range", RANGE24_D),

        ]:
            # setter
            port_o = Port(line=line, platform=platform)
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
            ("ios", RANGE24, "eq", ValueError),
            ("ios", RANGE24, "neq", ValueError),
            ("ios", RANGE24, "gt", ValueError),
            ("ios", RANGE24, "lt", ValueError),
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
            ("ios", RANGE13, [2, 3, 4], RANGE24_D),

            ("cnx", EQ2, [1], EQ1_D),
            ("cnx", NEQ2, WO_1, NEQ1_D),
            ("cnx", GT1, GT_65532, GT_D),
            ("cnx", LT1, [1, 2], LT3_D),
            ("cnx", RANGE13, [2, 3, 4], RANGE24_D),

        ]:
            # setter
            port_o = Port(line=line, platform=platform)
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
            ("cnx", EQ2, [1, 2, 3], ValueError),
            ("cnx", NEQ2, WO_13, ValueError),
        ]:
            port_o = Port(EQ1, platform=platform)
            with self.assertRaises(error, msg=f"{ports=}"):
                port_o.ports = ports

    def test_valid__sport(self):
        """Port.sport"""
        for platform, line, sport, req_d in [
            ("ios", EQ2, "1-3", EQ123_D),
            ("ios", NEQ2, "2,4-65535", NEQ13_D),
            ("ios", GT1, "65533-65535", GT_D),
            ("ios", LT1, "1-2", LT3_D),
            ("ios", RANGE13, "2-4", RANGE24_D),

            ("cnx", EQ2, "1", EQ1_D),
            ("cnx", NEQ2, "2-65535", NEQ1_D),
            ("cnx", GT1, "65533-65535", GT_D),
            ("cnx", LT1, "1-2", LT3_D),
            ("cnx", RANGE13, "2-4", RANGE24_D),

        ]:
            # setter
            port_o = Port(line=line, platform=platform)
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
            ("cnx", EQ2, "1-3", ValueError),
            ("cnx", NEQ2, "2,4-65535", ValueError),
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
            ("ios", RANGE24, ["1", "3"], [1, 3]),

            ("cnx", EQ1, ["1"], [1]),
            ("cnx", NEQ1, ["1"], [1]),
            ("cnx", LT1, ["1"], [1]),
            ("cnx", GT1, ["1"], [1]),
            ("cnx", RANGE24, ["1", "3"], [1, 3]),
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
            ("ios", RANGE24, ["1"], ValueError),
            ("ios", RANGE24, ["1", "2", "3"], ValueError),

            ("cnx", EQ1, ["1", "2"], ValueError),
            ("cnx", NEQ1, ["1", "2"], ValueError),
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
