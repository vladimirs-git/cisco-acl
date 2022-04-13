"""unittest remark.py"""

import unittest

from cisco_acl import Ace, Remark
from tests_.helpers_test import PERMIT_IP, REMARK, REMARK_1, REMARK_2


# noinspection DuplicatedCode
class Test(unittest.TestCase):
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
        for rem_o, other_o, req, in [
            (Remark(REMARK), REMARK, False),
            (Remark(REMARK), Remark(REMARK), True),
            (Remark(REMARK), Remark(f"{REMARK} 2"), False),
            (Remark(REMARK), Remark(REMARK_1), False),
            (Remark(REMARK), Ace(PERMIT_IP), False),
        ]:
            msg = f"{rem_o=} {other_o=}"
            result = rem_o.__eq__(other_o)
            self.assertEqual(result, req, msg=msg)
            result = rem_o.__ne__(other_o)
            self.assertEqual(result, not req, msg=msg)

    def test_valid__lt__(self):
        """Remark.__lt__() __le__() __gt__() __ge__()"""
        for rem_o, other_o, req_lt, req_le, req_gt, req_ge in [
            (Remark(REMARK_1), Remark(REMARK_1), False, True, False, True),
            (Remark(REMARK_1), Remark(REMARK_2), True, True, False, False),
            (Remark(f"{REMARK_1} 1"), Remark(f"{REMARK_1} 2"), True, True, False, False),
        ]:
            msg = f"{rem_o=} {other_o=}"
            result = rem_o.__lt__(other_o)
            self.assertEqual(result, req_lt, msg=msg)
            result = rem_o.__le__(other_o)
            self.assertEqual(result, req_le, msg=msg)
            result = rem_o.__gt__(other_o)
            self.assertEqual(result, req_gt, msg=msg)
            result = rem_o.__ge__(other_o)
            self.assertEqual(result, req_ge, msg=msg)

    # =========================== property ===========================

    def test_valid__line(self):
        """Remark.line"""
        remark_0 = "remark text1 text2"
        remark_0b = " remark\ttext1  text2\n"
        remark_0_d = dict(line=remark_0,
                          idx=0,
                          action="remark",
                          text="text1 text2")
        remark_10 = "10 remark text1 text2"
        remark_10b = " 10\tremark  text1  text2\n"
        remark_10_d = {**remark_0_d, **{"line": remark_10, "idx": 10}}
        for line, req, req_d in [
            (remark_0, remark_0, remark_0_d),
            (remark_0b, remark_0, remark_0_d),
            (remark_10, remark_10, remark_10_d),
            (remark_10b, remark_10, remark_10_d),
        ]:
            rem_o = Remark(line)
            result = rem_o.line
            self.assertEqual(result, req, msg=f"{line=}")
            result = str(rem_o)
            self.assertEqual(result, req, msg=f"{line=}")
            for attr, req_ in req_d.items():
                result_ = getattr(rem_o, attr)
                if not isinstance(result_, (int, str)):
                    result_ = str(result_)
                self.assertEqual(result_, req_, msg=f"{line=} {attr=}")
            rem_o.line = line
            result = str(rem_o)
            self.assertEqual(result, req, msg=f"setter {line=}")
            with self.assertRaises(AttributeError, msg=f"deleter {line=}"):
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
        text_ = "text1  text2"
        for text, req in [
            (text_, text_),
            (f"\t{text_}\n", text_),
        ]:
            rem_o = Remark(REMARK)
            rem_o.text = text
            result = rem_o.text
            self.assertEqual(result, req, msg=f"setter {text=}")
            with self.assertRaises(AttributeError, msg=f"deleter {text=}"):
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
