"""Unittest base_ace.py"""

import unittest

from cisco_acl import Ace, AceGroup, Remark
from tests.helpers_test import Helpers, PERMIT_IP, REMARK


class Test(Helpers):
    """BaseAce"""

    # =========================== property ===========================

    def test_valid__sequence(self):
        """BaseAce.sequence"""
        for sequence, req in [
            ("", 0),
            ("0", 0),
            ("1", 1),
            (0, 0),
            (1, 1),
        ]:
            for obj in [
                Remark(f"{sequence} {REMARK}"),
                Ace(f"{sequence} {PERMIT_IP}"),
                AceGroup(f"{sequence} {REMARK}\nPERMIT_IP"),
            ]:
                result = obj.sequence
                self.assertEqual(result, req, msg=f"{sequence=}")
                # setter
                obj.sequence = sequence
                result = obj.sequence
                self.assertEqual(result, req, msg=f"{sequence=}")

    def test_invalid__sequence(self):
        """BaseAce.sequence"""
        for sequence, error in [
            ({}, TypeError),
            (-1, ValueError),
            ("a", ValueError),
            ("-1", ValueError),
        ]:
            obj = Ace(PERMIT_IP)
            with self.assertRaises(error, msg=f"deleted {sequence=}"):
                obj.sequence = sequence
            with self.assertRaises(ValueError, msg=f"{sequence=}"):
                Ace(f"{sequence} {PERMIT_IP}")


if __name__ == "__main__":
    unittest.main()
