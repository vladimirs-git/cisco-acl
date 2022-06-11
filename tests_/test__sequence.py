"""Unittest sequence.py"""

import unittest

from cisco_acl import Ace, Remark
from cisco_acl.sequence import Sequence
from tests_.helpers_test import Helpers, PERMIT_IP, REMARK

SEQ0_D = dict(line="", number=0)
SEQ1_D = dict(line="1", number=1)


# noinspection DuplicatedCode
class Test(Helpers):
    """Sequence"""

    # ========================== redefined ===========================

    def test_valid__hash__(self):
        """Sequence.__hash__()"""
        for line, req_ in [
            ("1", 1),
            (1, 1),
        ]:
            seq_o = Sequence(line)
            result = seq_o.__hash__()
            req = req_.__hash__()
            self.assertEqual(result, req, msg=f"{line=}")

    def test_valid__eq__(self):
        """Sequence.__eq__() __ne__()"""
        seq0_o = Sequence("0")
        seq1_o = Sequence("1")
        for seq_o, other_o, req, in [
            (seq0_o, 0, True),
            (seq0_o, "0", True),
            (seq0_o, "", True),
            (seq1_o, 1, True),
            (seq1_o, "1", True),
            (seq1_o, Sequence("1"), True),
            (seq1_o, Sequence(1), True),
            (seq1_o, Sequence("0"), False),
            (seq1_o, Remark(REMARK), False),
            (seq1_o, Ace(PERMIT_IP), False),
        ]:
            result = seq_o.__eq__(other_o)
            self.assertEqual(result, req, msg=f"{seq_o=} {other_o=}")
            result = seq_o.__ne__(other_o)
            self.assertEqual(result, not req, msg=f"{seq_o=} {other_o=}")

    def test_valid__lt__(self):
        """Sequence.__lt__() __le__() __gt__() __ge__()"""
        seq_o = Sequence("0")
        for other_o, req_lt, req_le, req_gt, req_ge in [
            (0, False, True, False, True),
            ("0", False, True, False, True),
            ("", False, True, False, True),
            (Sequence("0"), False, True, False, True),
            (1, True, True, False, False),
            ("1", True, True, False, False),
            (Sequence("1"), True, True, False, False),
            (Remark(REMARK), True, True, False, False),
            (Ace(PERMIT_IP), True, True, False, False),
        ]:
            result = seq_o.__lt__(other_o)
            self.assertEqual(result, req_lt, msg=f"{other_o=}")
            result = seq_o.__le__(other_o)
            self.assertEqual(result, req_le, msg=f"{other_o=}")
            result = seq_o.__gt__(other_o)
            self.assertEqual(result, req_gt, msg=f"{other_o=}")
            result = seq_o.__ge__(other_o)
            self.assertEqual(result, req_ge, msg=f"{other_o=}")

    # =========================== property ===========================

    def test_valid__line(self):
        """Sequence.line"""
        for line, req_d in [
            ("", SEQ0_D),
            ("0", SEQ0_D),
            (0, SEQ0_D),
            ("1", SEQ1_D),
            (1, SEQ1_D),
            ("1 permit ip any any", SEQ1_D),
        ]:
            # getter
            seq_o = Sequence(line)
            self._test_attrs(obj=seq_o, req_d=req_d, msg=f"getter {line=}")

            # setter
            seq_o.line = line
            self._test_attrs(obj=seq_o, req_d=req_d, msg=f"setter {line=}")

        # deleter
        seq_o = Sequence("1")
        del seq_o.line
        self._test_attrs(obj=seq_o, req_d=SEQ0_D, msg="deleter line")

    def test_invalid__line(self):
        """Sequence.line"""
        seq_o = Sequence("0")
        for line, error in [
            (-1, ValueError),
            ("-1", ValueError),
            ("a", ValueError),
        ]:
            with self.assertRaises(error, msg=f"setter {line=}"):
                seq_o.line = line

    def test_valid__number(self):
        """Sequence.number"""
        for number, req_d in [
            (0, SEQ0_D),
            (1, SEQ1_D),
        ]:
            # getter
            seq_o = Sequence(number)
            self._test_attrs(obj=seq_o, req_d=req_d, msg=f"getter {number=}")
            result = int(seq_o)
            req = req_d["number"]
            self.assertEqual(result, req, msg=f"{number=}")

            # setter
            seq_o.number = number
            self._test_attrs(obj=seq_o, req_d=req_d, msg=f"setter {number=}")
            result = int(seq_o)
            req = req_d["number"]
            self.assertEqual(result, req, msg=f"{number=}")

        # deleter
        seq_o = Sequence("1")
        del seq_o.line
        self._test_attrs(obj=seq_o, req_d=SEQ0_D, msg="deleter line")
        result = int(seq_o)
        self.assertEqual(result, 0, msg=f"{number=}")


if __name__ == "__main__":
    unittest.main()
