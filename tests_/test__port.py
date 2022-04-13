"""unittest port.py"""

import unittest

from cisco_acl.port import Port


# noinspection DuplicatedCode
class Test(unittest.TestCase):
    """Port"""

    # =========================== property ===========================

    def test_valid__line(self):
        """Port.line"""
        all_ports = list(range(1, 65535 + 1))
        wo_1 = [i for i in all_ports if i not in [1]]
        wo_1_2 = [i for i in all_ports if i not in [1, 2]]
        wo_1_3 = [i for i in all_ports if i not in [1, 2, 3]]
        gt_65532 = [65533, 65534, 65535]

        eq_0_d = dict(line="", operator="", sport="", ports=[])
        eq_1_d = dict(line="eq 1", operator="eq", sport="1", ports=[1])
        eq_1_3_d = dict(line="eq 1 2 3", operator="eq", sport="1-3", ports=[1, 2, 3])
        neq_1_d = dict(line="neq 1", operator="neq", sport="2-65535", ports=wo_1)
        neq_1_2_d = dict(line="neq 1 2", operator="neq", sport="3-65535", ports=wo_1_2)
        neq_1_3_d = dict(line="neq 1 2 3", operator="neq", sport="4-65535", ports=wo_1_3)
        gt_65532_d = dict(line="gt 65532", operator="gt", sport="65533-65535", ports=gt_65532)
        lt_3_d = dict(line="lt 3", operator="lt", sport="1-2", ports=[1, 2])
        range_2_4 = dict(line="range 2 4", operator="range", sport="2-4", ports=[2, 3, 4])
        for platform, line, req_d in [
            ("ios", "", eq_0_d),
            ("ios", "eq 1", eq_1_d),
            ("ios", "eq 1 2 3", eq_1_3_d),
            ("ios", "neq 1", neq_1_d),
            ("ios", "neq 1 2 3", neq_1_3_d),
            ("ios", "gt 65532", gt_65532_d),
            ("ios", "lt 3", lt_3_d),
            ("ios", "range 2 4", range_2_4),

            ("cnx", "", eq_0_d),
            ("cnx", "eq 1", eq_1_d),
            ("cnx", "neq 1", neq_1_d),
            ("cnx", "gt 65532", gt_65532_d),
            ("cnx", "lt 3", lt_3_d),
            ("cnx", "range 2 4", range_2_4),
        ]:
            port_o = Port(line, platform=platform)
            result = port_o.line
            self.assertEqual(result, req_d["line"], msg=f"{line=}")
            self.assertEqual(str(port_o), req_d["line"], msg=f"{line=}")
            for attr, req in req_d.items():
                result = getattr(port_o, attr)
                self.assertEqual(result, req, msg=f"{line=}")
        port_o.line = line
        result = port_o.line
        self.assertEqual(result, req_d["line"], msg=f"setter {line=}")
        with self.assertRaises(AttributeError, msg=f"deleter {line=}"):
            # noinspection PyPropertyAccess
            del port_o.line

    def test_invalid__line(self):
        """Port.line"""
        for platform, line, error in [
            ("", 1, TypeError),
            ("", "eq", ValueError),
            ("", "typo 1", ValueError),
            ("", "lt 1 2", ValueError),
            ("", "gt 1 2", ValueError),
            ("", "range 1", ValueError),
            ("", "range 1 2 3", ValueError),

            ("cnx", "eq 1 2", ValueError),
            ("cnx", "neq 1 2", ValueError),
        ]:
            with self.assertRaises(error, msg=f"{line=}"):
                Port(line, platform=platform)

    # =========================== helpers ============================

    def test_valid__line__operator(self):
        """Port._line__operator()"""
        port_o = Port("eq 1")
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
        port_o = Port("eq 1")
        for items, error in [
            ([], ValueError),
            (["typo", "1"], ValueError),
        ]:
            with self.assertRaises(error, msg=f"{items=}"):
                port_o._line__operator(items)

    def test_valid__line__ports(self):
        """Port._line__ports()"""
        for platform, line, items, req in [
            ("ios", "eq 1", ["1"], [1]),
            ("ios", "eq 1", ["1", "2"], [1, 2]),
            ("ios", "neq 1", ["1"], [1]),
            ("ios", "neq 1", ["1", "2"], [1, 2]),
            ("ios", "lt 1", ["1"], [1]),
            ("ios", "gt 1", ["1"], [1]),
            ("ios", "range 1 3", ["1", "3"], [1, 3]),

            ("cnx", "eq 1", ["1"], [1]),
            ("cnx", "neq 1", ["1"], [1]),
            ("cnx", "lt 1", ["1"], [1]),
            ("cnx", "gt 1", ["1"], [1]),
            ("cnx", "range 1 3", ["1", "3"], [1, 3]),
        ]:
            port_o = Port(line, platform=platform)
            result = port_o._line__ports(items)
            self.assertEqual(result, req, msg=f"{items=}")

    def test_invalid__line__ports(self):
        """Port._line__ports()"""
        for platform, line, items, error in [
            ("", "eq 1", [], ValueError),
            ("", "lt 1", ["1", "2"], ValueError),
            ("", "gt 1", ["1", "2"], ValueError),
            ("", "range 1 3", ["1"], ValueError),
            ("", "range 1 3", ["1", "2", "3"], ValueError),
            ("cnx", "eq 1", ["1", "2"], ValueError),
            ("cnx", "neq 1", ["1", "2"], ValueError),
        ]:
            port_o = Port(line, platform=platform)
            with self.assertRaises(error, msg=f"{platform=} {line=} {items=}"):
                port_o._line__ports(items)

    def test_valid__line__sport(self):
        """Port._line__sport()"""
        for items, req in [
            ([], ""),
            ([1, 2], "1-2"),
            ([2, 1], "1-2"),
            ([0, 1, 2], "0-2"),
            ([1, 3, 4, 5], "1,3-5"),
            ([5, 1, 4, 3], "1,3-5"),
            ([1, 2, 4, 6, 7], "1-2,4,6-7"),
        ]:
            port_o = Port("")
            result = port_o._line__sport(items)
            self.assertEqual(result, req, msg=f"{items=}")


if __name__ == "__main__":
    unittest.main()
