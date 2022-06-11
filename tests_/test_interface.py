"""Unittest interface.py"""

import unittest

from cisco_acl.interface import Interface
from tests_.helpers_test import ETH1, ETH2


# noinspection DuplicatedCode
class Test(unittest.TestCase):
    """Interface"""

    # =========================== property ===========================

    def test_valid__input(self):
        """Interface.input"""
        for items, req in [
            (None, []),
            ("", []),
            (ETH1, [ETH1]),
            ([], []),
            ([ETH1, ETH2], [ETH1, ETH2]),
            ([ETH2, ETH1], [ETH1, ETH2]),
            ({ETH1, ETH2}, [ETH1, ETH2]),
        ]:
            # getter
            usage_o = Interface(input=items)
            result = usage_o.input
            self.assertEqual(result, req, msg=f"{items=}")

            # setter
            usage_o.input = items
            result = usage_o.input
            self.assertEqual(result, req, msg=f"setter {items=}")

            # deleter
            del usage_o.input
            result = usage_o.input
            self.assertEqual(result, [], msg=f"setter {items=}")

    def test_invalid__input(self):
        """Interface.input"""
        for items, error in [
            (1, TypeError),
            ([1], TypeError),
        ]:
            with self.assertRaises(error, msg=f"setter {items=}"):
                Interface(input=items)
            usage_o = Interface(input=[])
            with self.assertRaises(error, msg=f"setter {items=}"):
                usage_o.input = items

    def test_valid__output(self):
        """Interface.output"""
        for items, req in [
            (None, []),
            ("", []),
            (ETH1, [ETH1]),
            ([], []),
            ([ETH1, ETH2], [ETH1, ETH2]),
            ([ETH2, ETH1], [ETH1, ETH2]),
            ({ETH1, ETH2}, [ETH1, ETH2]),
        ]:
            # getter
            usage_o = Interface(output=items)
            result = usage_o.output
            self.assertEqual(result, req, msg=f"{items=}")

            # setter
            usage_o.output = items
            result = usage_o.output
            self.assertEqual(result, req, msg=f"setter {items=}")

            # deleter
            del usage_o.output
            result = usage_o.output
            self.assertEqual(result, [], msg=f"setter {items=}")

    def test_invalid__output(self):
        """Interface.output"""
        for items, error in [
            (1, TypeError),
            ([1], TypeError),
        ]:
            with self.assertRaises(error, msg=f"setter {items=}"):
                Interface(output=items)
            usage_o = Interface(output=[])
            with self.assertRaises(error, msg=f"setter {items=}"):
                usage_o.output = items


if __name__ == "__main__":
    unittest.main()
