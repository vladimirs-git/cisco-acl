"""Unittest option.py"""

import unittest

import dictdiffer  # type: ignore

from cisco_acl import Option
from cisco_acl import helpers as h
from tests.helpers_test import Helpers, UUID, UUID_R


# noinspection DuplicatedCode
class Test(Helpers):
    """Option"""

    # ========================== redefined ===========================

    def test_valid__hash__(self):
        """Option.__hash__()"""
        line = "syn log"
        obj = Option(line)
        result = obj.__hash__()
        req = ("syn",).__hash__()
        self.assertEqual(result, req, msg=f"{line=}")

    def test_valid__eq__(self):
        """Option.__eq__() __ne__()"""
        obj1 = Option("syn log")
        for obj2, req, in [
            (Option("syn log"), True),
            (Option("syn"), True),
            (Option("ack"), False),
            ("syn log", False),
        ]:
            result = obj1.__eq__(obj2)
            self.assertEqual(result, req, msg=f"{obj1=} {obj2=}")
            result = obj1.__ne__(obj2)
            self.assertEqual(result, not req, msg=f"{obj1=} {obj2=}")

    def test_valid__repr__(self):
        """Option.__repr__()"""
        for kwargs, req in [
            (dict(line="syn", platform="asa", note="a", typo="b"),
             "Option(\"syn\", platform=\"asa\", note=\"a\")"),
            (dict(line="syn", platform="ios", note=""), "Option(\"syn\")"),
            (dict(line="syn", platform="nxos", note="a", typo="b"),
             "Option(\"syn\", platform=\"nxos\", note=\"a\")"),
        ]:
            obj = Option(**kwargs)
            result = obj.__repr__()
            result = self._quotation(result)
            self.assertEqual(result, req, msg=f"{result=}")

    # =========================== property ===========================

    def test_valid__line(self):
        """Option.line()"""
        for platform in h.PLATFORMS:
            for line, req_d in [
                ("", dict(line="", flags=[], logs=[])),
                ("ack syn log", dict(line="ack syn log", flags=["ack", "syn"], logs=["log"])),
                ("typo", dict(line="typo", flags=["typo"], logs=[])),
            ]:
                obj1 = Option(line=line, platform=platform)
                self._test_attrs(obj=obj1, req_d=req_d, msg=f"{line=}")
                # setter
                obj1.line = line
                self._test_attrs(obj=obj1, req_d=req_d, msg=f"{line=}")

    def test_invalid__line(self):
        """Option.line()"""
        for platform in h.PLATFORMS:
            for line, error in [
                ("1", ValueError),
            ]:
                with self.assertRaises(error, msg=f"{line=}"):
                    Option(line=line, platform=platform)

    def test_valid__platform(self):
        """Option.platform()"""
        option_d = dict(line="syn")
        for platform, platform_new, line, req_d in [
            # asa
            ("asa", "asa", "syn", option_d),
            ("asa", "ios", "syn", option_d),
            ("asa", "nxos", "syn", option_d),
            # ios
            ("ios", "asa", "syn", option_d),
            ("ios", "ios", "syn", option_d),
            ("ios", "nxos", "syn", option_d),
            # nxos
            ("nxos", "asa", "syn", option_d),
            ("nxos", "ios", "syn", option_d),
            ("nxos", "nxos", "syn", option_d),
        ]:
            msg = f"{platform=} {platform_new=} {line=}"
            obj = Option(line, platform=platform)
            self._test_attrs(obj=obj, req_d=req_d, msg=msg)
            # setter
            obj.platform = platform_new
            self._test_attrs(obj=obj, req_d=req_d, msg=msg)

    # =========================== method =============================

    def test_valid__copy(self):
        """Option.copy()"""
        obj1 = Option(line="syn", platform="ios", note="a")
        obj2 = obj1.copy()

        # change obj1 to check obj1 does not depend on obj2
        new_obj1_kwargs = dict(line="ack log", platform="nxos", note="b")
        for arg, value in new_obj1_kwargs.items():
            setattr(obj1, arg, value)

        req1_d = dict(line="ack log", platform="nxos", note="b", flags=["ack"], logs=["log"])
        req2_d = dict(line="syn", platform="ios", note="a", flags=["syn"], logs=[])
        self._test_attrs(obj1, req1_d, msg="obj1 does not depend on obj2")
        self._test_attrs(obj2, req2_d, msg="obj2 copied from obj1")

    def test_valid__data(self):
        """Option.data()"""
        kwargs1 = dict(line="ack log", platform="ios", note="a")
        req1 = dict(line="ack log",
                    platform="ios",
                    note="a",
                    flags=["ack"],
                    logs=["log"])

        for kwargs, req_d in [
            (kwargs1, req1),
        ]:
            obj = Option(**kwargs)
            obj.uuid = UUID

            result = obj.data()
            diff = list(dictdiffer.diff(first=result, second=req_d))
            self.assertEqual(diff, [], msg=f"{kwargs=}")

            result = obj.data(uuid=True)
            diff = list(dictdiffer.diff(first=result, second=req_d))
            self.assertEqual(diff, UUID_R, msg=f"{kwargs=}")


if __name__ == "__main__":
    unittest.main()
