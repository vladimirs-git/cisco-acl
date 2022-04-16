"""unittest base_ace.py"""

import unittest

from cisco_acl import Ace, AceGroup, Remark
from tests_.helpers_test import Helpers, PERMIT_IP, REMARK


# noinspection DuplicatedCode
class Test(Helpers):
    """BaseAce"""

    # =========================== property ===========================

    def test_valid__sequence(self):
        """Ace.sequence"""
        for sequence, req, req_ in [
            ("", "", 0),
            ("0", "", 0),
            ("1", "1", 1),
            (0, "", 0),
            (1, "1", 1),
        ]:
            for ace_o in [
                Remark(f"{sequence} {REMARK}"),
                Ace(f"{sequence} {PERMIT_IP}"),
                AceGroup([f"{sequence} {REMARK}", PERMIT_IP]),
            ]:
                # getter
                result = str(ace_o.sequence)
                # noinspection PyUnboundLocalVariable
                self.assertEqual(result, req, msg=f"{sequence=} str")
                result_ = int(ace_o.sequence)
                self.assertEqual(result_, req_, msg=f"{sequence=} str")

                # setter
                ace_o.sequence = sequence
                result = str(ace_o.sequence)
                self.assertEqual(result, req, msg=f"{sequence=} str")
                result_ = int(ace_o.sequence)
                self.assertEqual(result_, req_, msg=f"{sequence=} str")

                # deleter
                del ace_o.sequence
                result = str(ace_o.sequence)
                # noinspection PyUnboundLocalVariable
                self.assertEqual(result, "", msg=f"{sequence=} str")
                result_ = int(ace_o.sequence)
                self.assertEqual(result_, 0, msg=f"{sequence=} str")

    def test_invalid__sequence(self):
        """Ace.sequence"""
        base_o = Ace(PERMIT_IP)
        for sequence, error in [
            ({}, ValueError),
            (-1, ValueError),
            ("a", ValueError),
            ("-1", ValueError),
        ]:
            with self.assertRaises(error, msg=f"deleted {sequence=}"):
                base_o.sequence = sequence
            with self.assertRaises(ValueError, msg=f"{sequence=}"):
                Ace(f"{sequence} {PERMIT_IP}")


if __name__ == "__main__":
    unittest.main()
