"""Unittest helpers.py"""

import unittest

from cisco_acl import helpers as h
from cisco_acl.types_ import LDStr
from tests.helpers_test import PERMIT_IP, DENY_IP


# noinspection DuplicatedCode
class Test(unittest.TestCase):
    """Helpers"""

    # =========================== helpers ============================

    @staticmethod
    def _generate_aces_req() -> LDStr:
        """Return all combinations of ACE, ready for parse_ace() test"""
        sequences = ["", "10"]
        actions = ["permit", "deny"]
        protocols = ["tcp"]
        srcaddrs = ["any", "host 1.1.1.1", "1.1.1.0 0.0.0.7", "1.1.0.0/16",
                    "object-group A", "addrgroup B"]
        srcports = ["", "eq ftp 22", "neq 2 ftp", "gt ftp", "lt 22", "range ftp 22", "range 22 bgp"]
        dstaddrs = ["any", "host 2.2.2.2", "2.2.2.0 0.0.0.3", "2.2.2.0/24", "object-group B"]
        dstports = ["", "eq www 443", "neq 1 www", "gt www", "lt 443", "range 1 3", "range www bgp"]
        options = ["", "log"]

        lines = [f"sequence={s}" for s in sequences]
        lines = [f"{i},action={s}" for i in lines for s in actions]
        lines = [f"{i},protocol={s}" for i in lines for s in protocols]
        lines = [f"{i},srcaddr={s}" for i in lines for s in srcaddrs]
        lines = [f"{i},srcport={s}" for i in lines for s in srcports]
        lines = [f"{i},dstaddr={s}" for i in lines for s in dstaddrs]
        lines = [f"{i},dstport={s}" for i in lines for s in dstports]
        lines = [f"{i},option={s}" for i in lines for s in options]

        lines_d = []  # return
        for line in lines:
            line_d = {}
            items = line.split(",")
            for item in items:
                key, value = item.split("=")
                line_d[key] = value
            lines_d.append(line_d)

        return lines_d

    @staticmethod
    def _generate_dstport_option_req() -> LDStr:
        """Return all combinations of ACE, ready for parse_dstport_option() test"""
        dstports = ["eq www 443", "neq 1 www", "gt www", "lt 443", "range 1 3", "range www bgp"]
        options = ["", "ack", "log", "ack log", "log ack"]

        lines = [f"dstport={s}" for s in dstports]
        lines = [f"{i},option={s}" for i in lines for s in options]
        lines.extend([f"dstport=,option={s}" for s in options])

        lines_d = []  # return
        for line in lines:
            line_d = {}
            items = line.split(",")
            for item in items:
                key, value = item.split("=")
                line_d[key] = value
            lines_d.append(line_d)

        return lines_d

    # =============================== str ================================

    def test_valid__acl_help_to_name_port(self):
        """acl_help_to_name_port()"""
        output_all = """
        <0-65535>    Port number
        cmd          Remote commands (rcmd, 514)
        syslog       Syslog (514)
        """
        for output, req in [
            ("", {}),
            ("cmd          Remote commands (rcmd, 514)", {"cmd": 514}),
            ("syslog       Syslog (514)", {"syslog": 514}),
            (output_all, {"cmd": 514, "syslog": 514}),
        ]:
            result = h.acl_help_to_name_port(output=output)
            self.assertEqual(result, req, msg=f"{output=}")

    def test_valid__findall1(self):
        """findall1()"""
        for pattern, string, req in [
            ("", "abcde", ""),
            ("typo", "abcde", ""),
            ("(typo)", "abcde", ""),
            ("(b)", "abcde", "b"),
            ("(bc)", "abcde", "bc"),
            ("(b)(c)", "abcde", "b"),
        ]:
            result = h.findall1(pattern=pattern, string=string)
            self.assertEqual(result, req, msg=f"{pattern=}")

    def test_valid__findall2(self):
        """findall2()"""
        for pattern, string, req in [
            ("", "abcde", ("", "")),
            ("typo", "abcde", ("", "")),
            ("(b)", "abcde", ("", "")),
            ("(b)(typo)", "abcde", ("", "")),
            ("(typo)(c)", "abcde", ("", "")),
            ("(b)(c)", "abcde", ("b", "c")),
            ("(b)(c)(d)", "abcde", ("b", "c")),
        ]:
            result = h.findall2(pattern=pattern, string=string)
            self.assertEqual(result, req, msg=f"{pattern=}")

    def test_valid__findall3(self):
        """findall3()"""
        for pattern, string, req in [
            ("", "abcde", ("", "", "")),
            ("typo", "abcde", ("", "", "")),
            ("(b)", "abcde", ("", "", "")),
            ("(b)(c)", "abcde", ("", "", "")),
            ("(typo)(c)(d)", "abcde", ("", "", "")),
            ("(b)(typo)(d)", "abcde", ("", "", "")),
            ("(b)(c)(typo)", "abcde", ("", "", "")),
            ("(b)(c)(d)", "abcde", ("b", "c", "d")),
            ("(b)(c)(d)(e)", "abcde", ("b", "c", "d")),
        ]:
            result = h.findall3(pattern=pattern, string=string)
            self.assertEqual(result, req, msg=f"{pattern=}")

    def test_valid__check_line_length(self):
        """check_line_length()"""
        for line, req in [
            ("", True),
            ("a" * 100, True),
        ]:
            result = h.check_line_length(line)
            self.assertEqual(result, req, msg=f"{line=}")

    def test_invalid__check_line_length(self):
        """check_line_length()"""
        for line, error in [
            (1, TypeError),
            ("a" * 101, ValueError),
        ]:
            with self.assertRaises(error, msg=f"{line=}"):
                h.check_line_length(line)

    def test_valid__check_name(self):
        """check_name()"""
        ascii_letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        digits = "0123456789"
        punctuation = r"""!"#$%&"()*+,-./:;<=>@[\]^_`{|}~"""
        valid_chars = f"{ascii_letters}{digits}{punctuation}"
        for line, req in [
            (ascii_letters, True),
            (digits, True),
            (f"a{valid_chars}", True),
        ]:
            result = h.check_name(line)
            self.assertEqual(result, req, msg=f"{line=}")

    def test_invalid__check_name(self):
        """check_name()"""
        for line, error in [
            ("", ValueError),
            ("1a", ValueError),
            ("_", ValueError),
            ("a?", ValueError),
        ]:
            with self.assertRaises(error, msg=f"{line=}"):
                h.check_name(line)

    def test_valid__line_wo_spaces(self):
        """line_wo_spaces()"""
        for line, req in [
            ("", ""),
            ("a", "a"),
            (" \ta\nb\n", "a b"),
        ]:
            result = h.line_wo_spaces(line)
            self.assertEqual(result, req, msg=f"{line=}")

    def test_invalid__line_wo_spaces(self):
        """line_wo_spaces()"""
        for line, error in [
            (1, TypeError),
            (["a"], TypeError),
        ]:
            with self.assertRaises(error, msg=f"{line=}"):
                h.line_wo_spaces(line)

    def test_valid__lines_wo_spaces(self):
        """lines_wo_spaces()"""
        for line, req in [
            ("a", ["a"]),
            ("\ta\n \nb\n", ["a", "b"]),
        ]:
            result = h.lines_wo_spaces(line)
            self.assertEqual(result, req, msg=f"{line=}")

    def test_invalid__lines_wo_spaces(self):
        """lines_wo_spaces()"""
        for line, error in [
            (1, TypeError),
            (["a"], TypeError),
        ]:
            with self.assertRaises(error, msg=f"{line=}"):
                h.lines_wo_spaces(line)

    # ============================= int ==============================

    def test_valid__str_to_positive_int(self):
        """str_to_positive_int"""
        for line, req in [
            ("", 0),
            ("0", 0),
            ("10", 10),
            (0, 0),
            (10, 10),
        ]:
            result = h.str_to_positive_int(line)
            self.assertEqual(result, req, msg=f"{line=}")

    def test_invalid__str_to_positive_int(self):
        """str_to_positive_int"""
        for line, error in [
            ({}, TypeError),
            (-1, ValueError),
            ("a", ValueError),
            ("-1", ValueError),
        ]:
            with self.assertRaises(error, msg=f"{line=}"):
                h.str_to_positive_int(line)

    # =============================== list ===============================

    def test_valid__convert_to_lstr(self):
        """convert_to_lstr"""
        for items, req in [
            (None, []),
            ("", []),
            ("a", ["a"]),
            (["a", "b"], ["a", "b"]),
            (("a", "b"), ["a", "b"]),
        ]:
            result = h.convert_to_lstr(items)
            self.assertEqual(result, req, msg=f"{items=}")

    def test_invalid__convert_to_lstr(self):
        """convert_to_lstr"""
        for items, error in [
            (1, TypeError),
            ([1], TypeError),
        ]:
            with self.assertRaises(error, msg=f"{items=}"):
                h.convert_to_lstr(items)

    # ============================= dict =============================

    def test_valid__parse_ace(self):
        """BaseAce._parse_ace()"""
        pattern = "{sequence} {action} {protocol} {srcaddr} {srcport} {dstaddr} {dstport} {option}"
        items: LDStr = self._generate_aces_req()
        for req_d in items:
            line = pattern.format(**req_d)
            line = " ".join(line.split())

            result_d = h.parse_ace(line)
            for key, result in result_d.items():
                req = req_d[key]
                self.assertEqual(result, req, msg=f"{line=} {key=}")

    def test_invalid__parse_ace(self):
        """BaseAce._parse_ace()"""
        for line, error in [
            ("permit ip", ValueError),
            ("remark permit ip any any", ValueError),
            ("10 permit ip", ValueError),
            ("10 remark permit ip any any", ValueError),
        ]:
            with self.assertRaises(error, msg=f"{line=}"):
                h.parse_ace(line)

    def test_valid__parse_dstport_option(self):
        """parse_dstport_option()"""
        items: LDStr = self._generate_dstport_option_req()
        for req_d in items:
            line = "{dstport} {option}".format(**req_d)
            line = " ".join(line.split())

            result_d = h._parse_dstport_option(line)
            for key, result in result_d.items():
                req = req_d[key]
                self.assertEqual(result, req, msg=f"{line=} {key=}")

    def test_valid__parse_action(self):
        """parse_action()"""
        for seq in ["", "10"]:
            for line, req_d in [
                (f"{seq} remark text", dict(sequence=seq, action="remark", text="text")),
                (f"{seq} {PERMIT_IP}", dict(sequence=seq, action="permit", text="ip any any")),
                (f"{seq} {DENY_IP}", dict(sequence=seq, action="deny", text="ip any any")),
            ]:
                line = " ".join(line.split())
                result_d = h.parse_action(line)
                for key, result in result_d.items():
                    req = req_d[key]
                    self.assertEqual(result, req, msg=f"{line=} {key=}")

    def test_invalid__parse_action(self):
        """parse_action()"""
        for line, error in [
            ("", ValueError),
            ("remark", ValueError),
            ("permit", ValueError),
            ("10 permit", ValueError),
            ("eq 1 log www", ValueError),
        ]:
            with self.assertRaises(error, msg=f"{line=}"):
                h.parse_action(line)

    # ============================= bool =============================

    def test_valid__is_valid_wildcard(self):
        """is_valid_wildcard()"""
        for line, req in [
            ("0.0.0.0", True),
            ("0.0.0.1", True),
            ("0.0.0.2", False),
            ("0.0.0.3", True),
            ("0.0.1.255", True),
            ("0.0.1.0", False),
            ("255.255.255.255", True),
            ("1.1.1.1 0.0.0.0", True),
            ("1.1.1.1 0.0.0.1", True),
            ("1.1.1.1 0.0.0.2", False),
        ]:
            result = h.is_valid_wildcard(line)
            self.assertEqual(result, req, msg=f"{line=}")

    def test_invalid__is_valid_wildcard(self):
        """is_valid_wildcard()"""
        for line, error in [
            ("typo", ValueError),
            ("0.0.0", ValueError),
            ("0.0.0.0.0", ValueError),
        ]:
            with self.assertRaises(error, msg=f"{line=}"):
                h.parse_action(line)

    # ========================== ip address ==========================

    def test_valid__check_subnet(self):
        """check_subnet()"""
        for subnet, req in [
            ("1.0.0.0 255.0.0.0", True),
            ("3.3.0.0 0.0.3.3", True),
        ]:
            result = h.check_subnet(subnet)
            self.assertEqual(result, req, msg=f"{subnet=}")

    def test_invalid__check_subnet(self):
        """check_subnet()"""
        for subnet, error in [
            (1, TypeError),
            ("", ValueError),
            ("1.0.0.0", ValueError),
            ("1.0.0.0/24", ValueError),
            ("1.0.0.0   255.0.0.0", ValueError),
        ]:
            with self.assertRaises(error, msg=f"{subnet=}"):
                h.check_subnet(subnet)

    def test_valid__invert_mask(self):
        """invert_mask()"""
        for subnet, req in [
            ("1.0.0.0 255.0.0.0", "1.0.0.0 0.255.255.255"),
            ("3.3.0.0 0.0.3.3", "3.3.0.0 255.255.252.252"),
        ]:
            result = h.invert_mask(subnet)
            self.assertEqual(result, req, msg=f"{subnet=}")

    def test_invalid__invert_mask(self):
        """invert_mask()"""
        for subnet, error in [
            (1, AttributeError),
            ("", ValueError),
            ("1.0.0.0", ValueError),
            ("1.0.0.0/24", ValueError),
            ("1.0.0.0   255.0.0.0", ValueError),
        ]:
            with self.assertRaises(error, msg=f"{subnet=}"):
                h.invert_mask(subnet)

    def test_valid__make_wildcard(self):
        """make_wildcard()"""
        for prefix, req in [
            ("10.0.0.0/30", "10.0.0.0 0.0.0.3"),
            ("10.0.0.1/32", "host 10.0.0.1"),
            ("0.0.0.0/0", "any"),
            ("A-B", "object-group A-B"),
        ]:
            result = h.make_wildcard(prefix=prefix)
            self.assertEqual(result, req, msg=f"{prefix=}")

    def test_invalid__make_wildcard(self):
        """make_wildcard()"""
        for prefix, error in [
            (1, TypeError),
            ("", ValueError),
            ("A B", ValueError),
        ]:
            with self.assertRaises(error, msg=f"{prefix=}"):
                h.make_wildcard(prefix=prefix)

    # ============================ ports =============================

    def test_valid__ports_to_string(self):
        """ports_to_string()"""
        for items, req in [
            ([], ""),
            ([1, 2], "1-2"),
            ([2, 1], "1-2"),
            ([0, 1, 2], "0-2"),
            ([1, 3, 4, 5], "1,3-5"),
            ([5, 1, 4, 3], "1,3-5"),
            ([1, 2, 4, 6, 7], "1-2,4,6-7"),
        ]:
            result = h.ports_to_string(items)
            self.assertEqual(result, req, msg=f"{items=}")

    def test__string_to_ports(self):
        """Port._string_to_ports()"""
        for line, req in [
            ("", []),
            ("1", [1]),
            ("1,2", [1, 2]),
            ("1-2", [1, 2]),
            ("1-3", [1, 2, 3]),
            ("1,3-5", [1, 3, 4, 5]),
            ("3-5,1", [1, 3, 4, 5]),
        ]:
            result = h.string_to_ports(line)
            self.assertEqual(result, req, msg=f"{line=}")


if __name__ == "__main__":
    unittest.main()
