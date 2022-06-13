"""Unittest remark.py"""

import unittest

from cisco_acl import Ace, Remark
from tests.helpers_test import Helpers, PERMIT_IP, REMARK, REMARK_1, REMARK_2


# noinspection DuplicatedCode
class Test(Helpers):
    """Remark"""

    # ========================== redefined ===========================

    def test_valid__hash__(self):
        """Remark.__hash__()"""
        line = REMARK
        rem_o = Remark(line)
        result = rem_o.__hash__()
        req = line.__hash__()
        self.assertEqual(result, req, msg=f"{line=}")

    def test_valid__eq__(self):
        """Remark.__eq__() __ne__()"""
        rem_o = Remark(REMARK)
        for other_o, req, in [
            (Remark(REMARK), True),
            (REMARK, False),
            (Remark(f"{REMARK} 2"), False),
            (Remark(REMARK_1), False),
            (Ace(PERMIT_IP), False),
        ]:
            result = rem_o.__eq__(other_o)
            self.assertEqual(result, req, msg=f"{other_o=}")
            result = rem_o.__ne__(other_o)
            self.assertEqual(result, not req, msg=f"{other_o=}")

    def test_valid__lt__(self):
        """Remark.__lt__() __le__() __gt__() __ge__()"""
        for rem_o, other_o, req_lt, req_le, req_gt, req_ge in [
            (Remark(REMARK_1), Remark(REMARK_1), False, True, False, True),
            (Remark(REMARK_1), Remark(REMARK_2), True, True, False, False),
            (Remark(f"{REMARK_1} 1"), Remark(f"{REMARK_1} 2"), True, True, False, False),
        ]:
            result = rem_o.__lt__(other_o)
            self.assertEqual(result, req_lt, msg=f"{rem_o=} {other_o=}")
            result = rem_o.__le__(other_o)
            self.assertEqual(result, req_le, msg=f"{rem_o=} {other_o=}")
            result = rem_o.__gt__(other_o)
            self.assertEqual(result, req_gt, msg=f"{rem_o=} {other_o=}")
            result = rem_o.__ge__(other_o)
            self.assertEqual(result, req_ge, msg=f"{rem_o=} {other_o=}")

    # =========================== property ===========================

    def test_valid__line(self):
        """Remark.line"""
        remark_0 = "remark text1 text2"
        remark_0b = " remark\ttext1  text2\n"
        remark_0_d = dict(line=remark_0,
                          sequence="",
                          action="remark",
                          text="text1 text2")
        remark_10 = "10 remark text1 text2"
        remark_10b = " 10\tremark  text1  text2\n"
        remark_10_d = {**remark_0_d, **{"line": remark_10, "sequence": "10"}}
        for line, req_d in [
            (remark_0, remark_0_d),
            (remark_0b, remark_0_d),
            (remark_10, remark_10_d),
            (remark_10b, remark_10_d),
        ]:
            # getter
            rem_o = Remark(line)
            self._test_attrs(obj=rem_o, req_d=req_d, msg=f"getter {line=}")

            # setter
            rem_o.line = line
            self._test_attrs(obj=rem_o, req_d=req_d, msg=f"setter {line=}")

        # deleter
        rem_o = Remark(remark_0)
        with self.assertRaises(AttributeError, msg="deleter line"):
            # noinspection PyPropertyAccess
            del rem_o.line

    def test_invalid__line(self):
        """Remark.line"""
        rem_o = Remark(REMARK)
        for line, error in [
            (1, TypeError),
            ("10", ValueError),
            ("10 remark", ValueError),
            ("remark", ValueError),
            ("permit ip any any", ValueError),
            ("10 permit ip any any", ValueError),
            ("deny ip any any", ValueError),
        ]:
            with self.assertRaises(error, msg=f"setter {line=}"):
                rem_o.line = line

    def test_valid__action(self):
        """Remark.action"""
        rem_o = Remark(REMARK)
        with self.assertRaises(AttributeError, msg="setter action"):
            # noinspection PyPropertyAccess
            rem_o.action = "permit"
        with self.assertRaises(AttributeError, msg="deleter action"):
            # noinspection PyPropertyAccess
            del rem_o.action

    def test_valid__text(self):
        """Remark.text"""
        rem_d = dict(line="remark text1 text2", text="text1 text2")
        for line, req_d in [
            ("remark text1  text2", rem_d),
            ("\tremark\ttext1  text2\n", rem_d),
        ]:
            # getter
            rem_o = Remark(line)
            self._test_attrs(obj=rem_o, req_d=req_d, msg=f"getter {line=}")

            # setter
            rem_o.line = line
            self._test_attrs(obj=rem_o, req_d=req_d, msg=f"setter {line=}")

        # deleter
        rem_o = Remark(REMARK)
        with self.assertRaises(AttributeError, msg="deleter"):
            # noinspection PyPropertyAccess
            del rem_o.text

    def test_invalid__text(self):
        """Remark.text"""
        rem_o = Remark(REMARK)
        for text, error in [
            (1, TypeError),
            ("", ValueError),
            ("\n", ValueError),
        ]:
            with self.assertRaises(error, msg=f"setter {text=}"):
                rem_o.text = text


if __name__ == "__main__":
    unittest.main()
