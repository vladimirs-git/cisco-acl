"""unittest base_ace.py"""

import unittest

from cisco_acl import Ace, Remark
from tests_.helpers_test import PERMIT_IP, REMARK


# noinspection DuplicatedCode
class Test(unittest.TestCase):
    """BaseAce"""

    # =========================== property ===========================

    def test_valid__line_length(self):
        """Ace.line_length"""
        for line_length, req in [
            (50, 50),
        ]:
            acl_o = Ace(f"{PERMIT_IP}", line_length=line_length)
            result = acl_o.line_length
            self.assertEqual(result, req, msg=f"getter {line_length=}")

    def test_invalid__line_length(self):
        """Ace.line_length"""
        for class_, line, line_length, error in [
            (Ace, PERMIT_IP, 2, ValueError),
            (Remark, REMARK, 2, ValueError),
        ]:
            with self.assertRaises(error, msg=f"{line=} {line_length=}"):
                class_(line, line_length=line_length)

    def test_valid__idx(self):
        """Ace.idx sidx"""
        id_0_d = dict(idx=0, sidx="")
        id_10_d = dict(idx=10, sidx="10")
        for idx, req_d in [
            ("", id_0_d),
            ("0", id_0_d),
            ("10", id_10_d),
            (0, id_0_d),
            (10, id_10_d),
        ]:
            for ace_o in [
                Ace(f"{idx} {PERMIT_IP}"),
                Remark(f"{idx} {REMARK}"),
            ]:
                # getter
                for attr, req_ in req_d.items():
                    # noinspection PyUnboundLocalVariable
                    msg = f"{idx=} {ace_o.__class__.__name__} {attr=}"
                    result_ = getattr(ace_o, attr)
                    self.assertEqual(result_, req_, msg=msg)
                # setter
                ace_o.idx = idx
                for attr, req_ in req_d.items():
                    # noinspection PyUnboundLocalVariable
                    msg = f"{idx=} {ace_o.__class__.__name__} {attr=}"
                    result_ = getattr(ace_o, attr)
                    self.assertEqual(result_, req_, msg=msg)
                # deleter
                del ace_o.idx
                result = ace_o.idx
                self.assertEqual(result, 0, msg="deleter idx")
                with self.assertRaises(AttributeError, msg="deleter sidx"):
                    # noinspection PyPropertyAccess
                    del ace_o.sidx

    def test_invalid__idx(self):
        """Ace.idx"""
        base_o = Ace(PERMIT_IP)
        for idx, error in [
            ({}, TypeError),
            (-1, ValueError),
            ("a", ValueError),
            ("-1", ValueError),
        ]:
            with self.assertRaises(error, msg=f"deleted {idx=}"):
                base_o.idx = idx
            with self.assertRaises(ValueError, msg=f"{idx=}"):
                Ace(f"{idx} {PERMIT_IP}")

    # =========================== helpers ============================

    def test_valid__check_line_length(self):
        """AceGroup._check_line_length()"""
        for line, line_length, req in [
            (PERMIT_IP, 50, True),
        ]:
            ace_o = Ace(PERMIT_IP, line_length=line_length)
            result = ace_o._check_line_length(line)
            self.assertEqual(result, req, msg=f"{line=} {line_length=}")

    def test_invalid__check_line_length(self):
        """AceGroup._check_line_length()"""
        ace_o_ = Ace(PERMIT_IP)
        for line, line_length, error in [
            (PERMIT_IP, 2, ValueError),
        ]:
            with self.assertRaises(error, msg=f"{line=} {line_length=}"):
                ace_o_.line_length = line_length
                ace_o_._check_line_length(line)
            with self.assertRaises(error, msg=f"{line=} {line_length=}"):
                Ace(PERMIT_IP, line_length=line_length)


if __name__ == "__main__":
    unittest.main()
