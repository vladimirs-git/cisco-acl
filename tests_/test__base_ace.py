"""unittest base_ace.py"""

import unittest

from cisco_acl import Ace, Remark
from tests_.helpers_test import PERMIT_IP, REMARK


# noinspection DuplicatedCode
class Test(unittest.TestCase):
    """BaseAce"""

    # =========================== property ===========================

    def test_valid__sequence(self):
        """Ace.sequence ssequence"""
        id_0_d = dict(sequence=0, ssequence="")
        id_10_d = dict(sequence=10, ssequence="10")
        for sequence, req_d in [
            ("", id_0_d),
            ("0", id_0_d),
            ("10", id_10_d),
            (0, id_0_d),
            (10, id_10_d),
        ]:
            for ace_o in [
                Ace(f"{sequence} {PERMIT_IP}"),
                Remark(f"{sequence} {REMARK}"),
            ]:
                # getter
                for attr, req_ in req_d.items():
                    # noinspection PyUnboundLocalVariable
                    msg = f"{sequence=} {ace_o.__class__.__name__} {attr=}"
                    result_ = getattr(ace_o, attr)
                    self.assertEqual(result_, req_, msg=msg)

                # setter
                ace_o.sequence = sequence
                for attr, req_ in req_d.items():
                    # noinspection PyUnboundLocalVariable
                    msg = f"{sequence=} {ace_o.__class__.__name__} {attr=}"
                    result_ = getattr(ace_o, attr)
                    self.assertEqual(result_, req_, msg=msg)

                # deleter
                del ace_o.sequence
                result = ace_o.sequence
                self.assertEqual(result, 0, msg="deleter sequence")
                with self.assertRaises(AttributeError, msg="deleter ssequence"):
                    # noinspection PyPropertyAccess
                    del ace_o.ssequence

    def test_invalid__sequence(self):
        """Ace.sequence"""
        base_o = Ace(PERMIT_IP)
        for sequence, error in [
            ({}, TypeError),
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
