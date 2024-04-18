"""Unittest remark.py"""

import unittest

import dictdiffer  # type: ignore

from cisco_acl import Ace, Remark
from tests.helpers_test import Helpers, PERMIT_IP, REMARK, REMARK1, REMARK2, UUID, UUID_R


# noinspection DuplicatedCode
class Test(Helpers):
    """Remark"""

    # ========================== redefined ===========================

    def test_valid__hash__(self):
        """Remark.__hash__()"""
        line = REMARK
        obj = Remark(line)
        result = obj.__hash__()
        req = line.__hash__()
        self.assertEqual(result, req, msg=f"{line=}")

    def test_valid__eq__(self):
        """Remark.__eq__() __ne__()"""
        obj1 = Remark(REMARK)
        for obj2, req, in [
            (Remark(REMARK), True),
            (REMARK, False),
            (Remark(f"{REMARK} 2"), False),
            (Remark(REMARK1), False),
            (Ace(PERMIT_IP), False),
        ]:
            result = obj1.__eq__(obj2)
            self.assertEqual(result, req, msg=f"{obj2=}")
            result = obj1.__ne__(obj2)
            self.assertEqual(result, not req, msg=f"{obj2=}")

    def test_valid__lt__(self):
        """Remark.__lt__() __le__() __gt__() __ge__()"""
        for obj1, obj2, req_lt, req_le, req_gt, req_ge in [
            (Remark(REMARK1), Remark(REMARK1), False, True, False, True),
            (Remark(REMARK1), Remark(REMARK2), True, True, False, False),
            (Remark(f"{REMARK1} 1"), Remark(f"{REMARK1} 2"), True, True, False, False),
        ]:
            result = obj1.__lt__(obj2)
            self.assertEqual(result, req_lt, msg=f"{obj1=} {obj2=}")
            result = obj1.__le__(obj2)
            self.assertEqual(result, req_le, msg=f"{obj1=} {obj2=}")
            result = obj1.__gt__(obj2)
            self.assertEqual(result, req_gt, msg=f"{obj1=} {obj2=}")
            result = obj1.__ge__(obj2)
            self.assertEqual(result, req_ge, msg=f"{obj1=} {obj2=}")

    def test_valid__repr__(self):
        """Remark.__repr__()"""
        for kwargs, req in [
            ({"line": "remark TEXT", "platform": "ios", "note": ""}, "Remark(\"remark TEXT\")"),
            ({"line": "remark TEXT", "platform": "nxos", "note": "a"},
             "Remark(\"remark TEXT\", platform=\"nxos\", note=\"a\")"),
        ]:
            obj = Remark(**kwargs)
            result = obj.__repr__()
            result = self._quotation(result)
            self.assertEqual(result, req, msg=f"{result=}")

    # =========================== property ===========================

    def test_valid__line(self):
        """Remark.line"""
        remark_0 = "remark TEXT TEXT2"
        remark_0_dirty = " remark\tTEXT  TEXT2\n"
        remark_0_d = {
            "line": remark_0,
            "sequence": 0,
            "action": "remark",
            "text": "TEXT TEXT2",
        }
        remark_10 = "10 remark TEXT TEXT2"
        remark_10_dirty = " 10\tremark  TEXT  TEXT2\n"
        remark_10_d = {**remark_0_d, **{"line": remark_10, "sequence": 10}}
        for line, req_d in [
            (remark_0, remark_0_d),
            (remark_0_dirty, remark_0_d),
            (remark_10, remark_10_d),
            (remark_10_dirty, remark_10_d),
        ]:
            obj = Remark(line)
            self._test_attrs(obj=obj, req_d=req_d, msg=f"{line=}")
            # setter
            obj.line = line
            self._test_attrs(obj=obj, req_d=req_d, msg=f"{line=}")

    def test_invalid__line(self):
        """Remark.line"""
        for line, error in [
            (1, TypeError),
            ("10", ValueError),
            ("10 remark", ValueError),
            ("remark", ValueError),
            ("permit ip any any", ValueError),
            ("10 permit ip any any", ValueError),
            ("deny ip any any", ValueError),
        ]:
            obj = Remark(REMARK)
            with self.assertRaises(error, msg=f"{line=}"):
                obj.line = line

    def test_valid__platform(self):
        """Remark.platform"""
        remark_d = {"line": REMARK, "text": "TEXT"}
        for platform, line, req_d, platform_new, req_new_d in [
            ("ios", REMARK, remark_d, "ios", remark_d),
            ("ios", REMARK, remark_d, "nxos", remark_d),
            ("nxos", REMARK, remark_d, "ios", remark_d),
            ("nxos", REMARK, remark_d, "nxos", remark_d),
        ]:
            msg = f"{platform=} {line=} {platform_new=}"
            obj = Remark(line=line, platform=platform)
            self._test_attrs(obj=obj, req_d=req_d, msg=msg)

            obj.platform = platform_new
            self._test_attrs(obj=obj, req_d=req_new_d, msg=msg)

    def test_valid__text(self):
        """Remark.text"""
        rem_d = {"line": "remark TEXT TEXT2", "text": "TEXT TEXT2"}
        for line, req_d in [
            ("remark TEXT  TEXT2", rem_d),
            ("\tremark\tTEXT  TEXT2\n", rem_d),
        ]:
            obj = Remark(line)
            self._test_attrs(obj=obj, req_d=req_d, msg=f"{line=}")
            # setter
            obj.line = line
            self._test_attrs(obj=obj, req_d=req_d, msg=f"{line=}")

    def test_invalid__text(self):
        """Remark.text"""
        obj = Remark(REMARK)
        for text, error in [
            (1, TypeError),
            ("", ValueError),
            ("\n", ValueError),
        ]:
            with self.assertRaises(error, msg=f"{text=}"):
                obj.text = text

    # =========================== method =============================

    def test_valid__copy(self):
        """Remark.copy()"""
        obj1 = Remark(line="10 remark TEXT", platform="ios", note="a")
        obj2 = obj1.copy()

        # change obj1 to check obj1 does not depend on obj2
        new_obj1_kwargs = {"platform": "nxos", "sequence": 20, "text": "TEXT2", "note": "b"}
        for arg, value in new_obj1_kwargs.items():
            setattr(obj1, arg, value)

        req1_d = {"line": "20 remark TEXT2", "platform": "nxos", "note": "b"}
        req2_d = {"line": "10 remark TEXT", "platform": "ios", "note": "a"}
        self._test_attrs(obj1, req1_d, msg="obj1 does not depend on obj2")
        self._test_attrs(obj2, req2_d, msg="obj2 copied from obj1")

    def test_valid__data(self):
        """Remark.data()"""
        kwargs1 = {"line": "10 remark TEXT", "platform": "ios", "note": "a"}
        req1 = {"line": "10 remark TEXT",
                "platform": "ios",
                "version": "0",
                "note": "a",
                "sequence": 10,
                "action": "remark",
                "text": "TEXT"}

        for kwargs, req_d in [
            (kwargs1, req1),
        ]:
            obj = Remark(**kwargs)
            obj.uuid = UUID

            result = obj.data()
            diff = list(dictdiffer.diff(first=result, second=req_d))
            self.assertEqual(diff, [], msg=f"{kwargs=}")

            result = obj.data(uuid=True)
            diff = list(dictdiffer.diff(first=result, second=req_d))
            self.assertEqual(diff, UUID_R, msg=f"{kwargs=}")


if __name__ == "__main__":
    unittest.main()
