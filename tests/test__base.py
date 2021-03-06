"""Unittest base.py"""

import unittest

from cisco_acl import Ace, Remark
from tests.helpers_test import ACL_NAME_IOS, PERMIT_IP, REMARK

REMARK_O = Remark(REMARK)
ACE_O = Ace(PERMIT_IP)
OBJECTS = [REMARK_O, ACE_O]


class Test(unittest.TestCase):
    """Base"""

    # ============================= init =============================

    def test_valid__init_line(self):
        """Base._init_line()"""
        for child_o, line, req in [
            (REMARK_O, REMARK, REMARK),
            (REMARK_O, " \tremark\ntext\n", REMARK),
            (ACE_O, PERMIT_IP, PERMIT_IP),
            (ACE_O, " \tpermit\nip\nany\nany\n", PERMIT_IP),
        ]:
            result = child_o._init_line(line)
            self.assertEqual(result, req, msg=f"{line=}")

    def test_invalid__init_line(self):
        """Base._init_line()"""
        for line, error in [
            (1, TypeError),
            (["a"], TypeError),
        ]:
            for obj in OBJECTS:
                with self.assertRaises(error, msg=f"{line=}"):
                    obj._init_line(line)

    def test_valid__init_lines(self):
        """Base._init_lines()"""
        for line, req in [
            (f"\n{ACL_NAME_IOS}\n  {REMARK}\n \n  {PERMIT_IP}\n ",
             [ACL_NAME_IOS, REMARK, PERMIT_IP]),
        ]:
            result = ACE_O._init_lines(line)
            self.assertEqual(result, req, msg=f"{line=}")

    def test_invalid__init_lines(self):
        """Base._init_lines()"""
        for line, error in [
            (1, TypeError),
            (["a"], TypeError),
        ]:
            with self.assertRaises(error, msg=f"{line=}"):
                ACE_O._init_lines(line)

    def test_valid__init_line_int(self):
        """Base._init_line_int()"""
        for line, req in [
            ("a", "a"),
            ("\ta\n", "a"),
            (0, "0"),
            (1, "1"),
        ]:
            for obj in OBJECTS:
                result = obj._init_line_int(line)
                self.assertEqual(result, req, msg=f"{line=}")

    def test_invalid__init_line_int(self):
        """Base._init_line_int()"""
        for line, error in [
            ({}, TypeError),
            (["a"], TypeError),
        ]:
            for obj in OBJECTS:
                with self.assertRaises(error, msg=f"{line=}"):
                    obj._init_line_int(line)

    # =========================== property ===========================

    def test_valid__repr__(self):
        """Base.__repr__() __str__()"""
        for class_, line, platform, note, req_repr in [
            (Remark, REMARK, "", None, f"Remark('{REMARK}')"),
            (Remark, REMARK, "", "", f"Remark('{REMARK}')"),
            (Remark, REMARK, "", 0, f"Remark('{REMARK}')"),
            (Remark, REMARK, "ios", None, f"Remark('{REMARK}')"),
            (Remark, REMARK, "ios", "a", f"Remark('{REMARK}', note='a')"),
            (Remark, REMARK, "nxos", None, f"Remark('{REMARK}', platform='nxos')"),
            (Remark, REMARK, "nxos", "a", f"Remark('{REMARK}', platform='nxos', note='a')"),
            (Ace, PERMIT_IP, "", None, f"Ace('{PERMIT_IP}')"),
            (Ace, PERMIT_IP, "ios", None, f"Ace('{PERMIT_IP}')"),
            (Ace, PERMIT_IP, "ios", "a", f"Ace('{PERMIT_IP}', note='a')"),
            (Ace, PERMIT_IP, "nxos", None, f"Ace('{PERMIT_IP}', platform='nxos')"),
            (Ace, PERMIT_IP, "nxos", "a", f"Ace('{PERMIT_IP}', platform='nxos', note='a')"),
        ]:
            obj = class_(line, platform=platform, note=note)
            result = str(obj)
            req = line
            self.assertEqual(result, req, msg=f"{obj=} str")
            result = repr(obj)
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

        # getter
        result = len(obj.uuid.split("-"))
        self.assertEqual(result, 5, msg="getter uuid")

        # setter
        obj.uuid = "1"
        result = obj.uuid
        self.assertEqual(result, "1", msg="setter uuid")

        # deleter
        del obj.uuid
        result = obj.uuid
        # noinspection PyUnboundLocalVariable
        self.assertEqual(result, "", msg="deleter uuid")

    def test_invalid__uuid(self):
        """Base.uuid"""
        for uuid, error in [
            (1, TypeError),
        ]:
            obj = Ace(PERMIT_IP)
            with self.assertRaises(error, msg="setter uuid"):
                obj.uuid = uuid

    def test_valid__platform(self):
        """Base.platform"""
        ios, nxos = "ios", "nxos"
        for platform, req in [
            ("", ios),
            (ios, ios),
            (nxos, nxos),
        ]:
            for class_, line in [
                (Remark, REMARK),
                (Ace, PERMIT_IP),
            ]:
                # getter
                # noinspection PyUnboundLocalVariable
                obj = class_(line, platform=platform)
                result = obj.platform
                self.assertEqual(result, req, msg=f"getter {platform=}")

                # setter
                obj.platform = platform
                result = obj.platform
                self.assertEqual(result, req, msg=f"getter {platform=}")

                # deleter
                with self.assertRaises(AttributeError, msg=f"deleter {platform=}"):
                    # noinspection PyPropertyAccess
                    del obj.platform

    def test_valid__note(self):
        """Base.note"""
        for note, req in [
            ("", ""),
            ("\ttext1\n", "\ttext1\n"),
            (0, ""),
            (1, 1),
        ]:
            for class_, line in [
                (Remark, REMARK),
                (Ace, PERMIT_IP),
            ]:
                # getter
                obj = class_(line, note=note)
                result = obj.note
                self.assertEqual(result, req, msg=f"getter {note=}")


if __name__ == "__main__":
    unittest.main()
