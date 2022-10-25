"""Unittest base.py"""

import unittest

from cisco_acl import Ace, Remark
from tests.helpers_test import Helpers, PERMIT_IP, REMARK


class Test(Helpers):
    """Base"""

    # =========================== property ===========================

    def test_valid__repr__(self):
        """Base.__repr__() __str__()"""
        for class_, line, platform, note, req_repr in [
            (Remark, REMARK, "", None, f"Remark(\"{REMARK}\")"),
            (Remark, REMARK, "", "", f"Remark(\"{REMARK}\")"),
            (Remark, REMARK, "", 0, f"Remark(\"{REMARK}\")"),
            (Remark, REMARK, "ios", None, f"Remark(\"{REMARK}\")"),
            (Remark, REMARK, "ios", "a", f"Remark(\"{REMARK}\", note=\"a\")"),
            (Remark, REMARK, "nxos", None, f"Remark(\"{REMARK}\", platform=\"nxos\")"),
            (Remark, REMARK, "nxos", "a", f"Remark(\"{REMARK}\", platform=\"nxos\", note=\"a\")"),
            (Ace, PERMIT_IP, "", None, f"Ace(\"{PERMIT_IP}\")"),
            (Ace, PERMIT_IP, "ios", None, f"Ace(\"{PERMIT_IP}\")"),
            (Ace, PERMIT_IP, "ios", "a", f"Ace(\"{PERMIT_IP}\", note=\"a\")"),
            (Ace, PERMIT_IP, "nxos", None, f"Ace(\"{PERMIT_IP}\", platform=\"nxos\")"),
            (Ace, PERMIT_IP, "nxos", "a", f"Ace(\"{PERMIT_IP}\", platform=\"nxos\", note=\"a\")"),
        ]:
            obj = class_(line, platform=platform, note=note)
            result = str(obj)
            req = line
            self.assertEqual(result, req, msg=f"{obj=} str")
            result = repr(obj)
            result = self._quotation(result)
            self.assertEqual(result, req_repr, msg=f"{obj=} repr")

    def test_invalid__repr__(self):
        """Base.__repr__() __str__()"""
        for line, error in [
            ("remark text", ValueError),
            ("10 remark text", ValueError),
            ({}, TypeError),
            ("", ValueError),
            ("typo", ValueError),
        ]:
            with self.assertRaises(error, msg=f"{line=}"):
                Ace(line)

    def test_valid__uuid(self):
        """Base.uuid"""
        obj = Ace(PERMIT_IP)
        result = len(obj.uuid.split("-"))
        self.assertEqual(result, 5, msg="uuid")
        # setter
        obj.uuid = "1"
        result = obj.uuid
        self.assertEqual(result, "1", msg="uuid")

    def test_invalid__uuid(self):
        """Base.uuid"""
        for uuid, error in [
            (1, TypeError),
        ]:
            obj = Ace(PERMIT_IP)
            with self.assertRaises(error, msg="uuid"):
                obj.uuid = uuid

    def test_valid__platform(self):
        """Base.platform"""
        for platform, req in [
            ("", "ios"),
            ("ios", "ios"),
            ("nxos", "nxos"),
        ]:
            for class_, line in [
                (Remark, REMARK),
                (Ace, PERMIT_IP),
            ]:
                obj = class_(line, platform=platform)
                result = obj.platform
                self.assertEqual(result, req, msg=f"{platform=}")
                # setter
                obj.platform = platform
                result = obj.platform
                self.assertEqual(result, req, msg=f"{platform=}")

    def test_valid__note(self):
        """Base.note"""
        for note, req in [
            (None, ""),
            ("", ""),
            ("\ttext1\n", "\ttext1\n"),
            (0, 0),
            (1, 1),
            ([], []),
            ({}, {}),
        ]:
            for class_, line in [
                (Remark, REMARK),
                (Ace, PERMIT_IP),
            ]:
                obj = class_(line, note=note)
                result = obj.note
                self.assertEqual(result, req, msg=f"{note=}")


if __name__ == "__main__":
    unittest.main()
