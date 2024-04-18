"""Unittest helpers.py"""

import unittest
from ipaddress import IPv4Network
from logging import WARNING

from netports import SwVersion
from packaging.version import InvalidVersion

from cisco_acl import helpers as h


# noinspection DuplicatedCode
class Test(unittest.TestCase):
    """Helpers"""

    # =============================== str ================================

    def test_valid__acl_help_to_name_port(self):
        """helpers.acl_help_to_name_port()"""
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
        """helpers.findall1()"""
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
        """helpers.findall2()"""
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
        """helpers.findall3()"""
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
        """helpers.check_line_length()"""
        for line, req in [
            ("", True),
            ("a" * 100, True),
        ]:
            result = h.check_line_length(line)
            self.assertEqual(result, req, msg=f"{line=}")

    def test_invalid__check_line_length(self):
        """helpers.check_line_length()"""
        for line, error in [
            (1, TypeError),
            ("a" * 101, ValueError),
        ]:
            with self.assertRaises(error, msg=f"{line=}"):
                h.check_line_length(line)

    def test_valid__check_name(self):
        """helpers.check_name()"""
        ascii_letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        digits = "0123456789"
        punctuation = r"""!"#$%&"()*+,-./:;<=>@[\]^_`{|}~"""
        valid_chars = f"{ascii_letters}{digits}{punctuation}"
        for line, req in [
            (ascii_letters, True),
            ("15", True),
            ("0a", True),
            ("_a", True),
            ("~a", True),
            (f"a{valid_chars}", True),
        ]:
            result = h.check_name(line)
            self.assertEqual(result, req, msg=f"{line=}")

    def test_invalid__check_name(self):
        """helpers.check_name()"""
        for line, error in [
            ("", ValueError),
            ("a?", ValueError),
        ]:
            with self.assertRaises(error, msg=f"{line=}"):
                h.check_name(line)

    def test_valid__init_indent(self):
        """helpers.init_indent()"""
        for kwargs, req in [
            ({}, "  "),
            (dict(indent=""), ""),
            (dict(indent=" "), " "),
            (dict(indent="\t"), "\t"),
        ]:
            result = h.init_indent(**kwargs)
            self.assertEqual(result, req, msg=f"{kwargs=}")

    def test_invalid__init_indent(self):
        """helpers.init_indent()"""
        for kwargs, error in [
            (dict(indent=1), TypeError),
        ]:
            with self.assertRaises(error, msg=f"{kwargs=}"):
                h.init_indent(**kwargs)

    def test_valid__init_number(self):
        """helpers.init_number()"""
        for number, req in [
            (0, "0"),
            (1, "1"),
            ("0", "0"),
            ("1", "1"),
        ]:
            result = h.init_number(number)
            self.assertEqual(result, req, msg=f"{result=}")

    def test_invalid__init_number(self):
        """helpers.init_number()"""
        for number, error in [
            ("a", ValueError),
            ("1 a", ValueError),
            (-1, ValueError),
            ("-1", ValueError),
            ([1], TypeError),
        ]:
            with self.assertRaises(error, msg=f"{number=}"):
                h.init_number(number)

    def test_valid__init_platform(self):
        """helpers.init_platform()"""
        for platform, req in [
            (None, "ios"),
            ("", "ios"),
            ("ios", "ios"),
            ("nxos", "nxos"),
            ("cnx", "nxos"),
            ("cisco_ios", "ios"),
            ("cisco_nxos", "nxos"),
        ]:
            result = h.init_platform(platform=platform)
            self.assertEqual(result, req, msg=f"{platform=}")

    def test_invalid__init_platform(self):
        """helpers.init_platform()"""
        for platform, error in [
            (["ios"], TypeError),
            ("typo", ValueError),
        ]:
            with self.assertRaises(error, msg=f"{platform=}"):
                h.init_platform(platform=platform)

    def test_valid__init_protocol(self):
        """helpers.init_protocol()"""
        for kwargs, req in [
            (dict(line="", protocol="tcp"), ""),
            (dict(line="eq 1", protocol="icmp"), ""),
            # tcp
            (dict(line="eq 1", protocol="tcp"), "tcp"),
            (dict(line="eq 1", protocol="6"), "tcp"),
            (dict(line="eq 1", protocol=6), "tcp"),
            # udp
            (dict(line="eq 1", protocol="udp"), "udp"),
            (dict(line="eq 1", protocol="17"), "udp"),
            (dict(line="eq 1", protocol=17), "udp"),
        ]:
            result = h.init_protocol(**kwargs)
            self.assertEqual(result, req, msg=f"{kwargs=}")

    def test_valid__init_remark_text(self):
        """helpers.init_remark_text()"""
        for text, req in [
            ("a", "a"),
            ("\ta    b \n", "a    b"),
        ]:
            result = h.init_remark_text(text=text)
            self.assertEqual(result, req, msg=f"{text=}")

    def test_invalid__init_remark_text(self):
        """helpers.init_remark_text()"""
        for text, error in [
            ("", ValueError),
            ("    ", ValueError),
            (1, TypeError),
            (["a"], TypeError),
        ]:
            with self.assertRaises(error, msg=f"{text=}"):
                h.init_remark_text(text=text)

    def test_valid__init_type(self):
        """helpers.init_type()"""
        for kwargs, req in [
            (dict(platform="ios", type=""), "standard"),
            (dict(platform="ios", type="extended"), "extended"),
            (dict(platform="ios", type="standard"), "standard"),
            (dict(platform="ios", type="ip access-list extended NAME"), "extended"),
            (dict(platform="ios", type="ip access-list standard NAME"), "standard"),
            (dict(platform="nxos", type=""), "extended"),
            (dict(platform="nxos", type="extended"), "extended"),
            (dict(platform="nxos", type="ip access-list extended NAME"), "extended"),
        ]:
            result = h.init_type(**kwargs)
            self.assertEqual(result, req, msg=f"{kwargs=}")

    def test_invalid__init_type(self):
        """helpers.init_type()"""
        for kwargs, error in [
            (dict(platform="nxos", type="standard"), ValueError),
            (dict(platform="nxos", type="ip access-list standard NAME"), ValueError),
            (dict(platform="typo", type=""), ValueError),
            (dict(platform="typo", type="extended"), ValueError),
            (dict(platform="typo", type="standard"), ValueError),
        ]:
            with self.assertRaises(error, msg=f"{kwargs=}"):
                h.init_type(**kwargs)

    def test_valid__init_version(self):
        """helpers.init_version()"""
        for kwargs, req in [
            (dict(platform="ios"), 0),
            (dict(version=""), 0),
            (dict(version="0"), 0),
            (dict(version=0), 0),
            (dict(version="0.0"), 0),
            (dict(version="15.2(02)SY"), 15),
            (dict(version=SwVersion("0")), 0),
            (dict(version=SwVersion("15.2(02)SY")), 15),
        ]:
            version_o = h.init_version(**kwargs)
            result = version_o.major
            self.assertEqual(result, req, msg=f"{kwargs=}")

    def test_invalid__init_version(self):
        """helpers.init_version()"""
        for kwargs, error in [
            (dict(version="typo"), InvalidVersion),
        ]:
            with self.assertRaises(error, msg=f"{kwargs=}"):
                h.init_version(**kwargs)

    def test_valid__int_to_str(self):
        """helpers.int_to_str()"""
        for line, req in [
            ("a", "a"),
            ("\ta\n", "a"),
            (" 10 ", "10"),
            (0, "0"),
            (1, "1"),
        ]:
            result = h.int_to_str(line)
            self.assertEqual(result, req, msg=f"{line=}")

    def test_invalid__int_to_str(self):
        """helpers.int_to_str()"""
        for line, error in [
            ({}, TypeError),
            (["a"], TypeError),
        ]:
            with self.assertRaises(error, msg=f"{line=}"):
                h.int_to_str(line)

    def test_valid__is_line_for_acl(self):
        """helpers.is_line_for_acl()"""
        for line, req in [
            ("permit a", True),
            ("deny a", True),
            ("remark a", True),
            ("1 permit a", True),
            ("1 deny a", True),
            ("1 remark a", True),
            ("", False),
            ("statistics a", False),
            ("description a", False),
            ("ignore a", False),
        ]:
            result = h.is_line_for_acl(line)
            self.assertEqual(result, req, msg=f"{line=}")

    def test_valid__lines_wo_spaces(self):
        """helpers.lines_wo_spaces()"""
        for line, req in [
            ("a", ["a"]),
            ("\ta\n \nb\n", ["a", "b"]),
        ]:
            result = h.lines_wo_spaces(line)
            self.assertEqual(result, req, msg=f"{line=}")

    def test_invalid__lines_wo_spaces(self):
        """helpers.lines_wo_spaces()"""
        for line, error in [
            (1, TypeError),
            (["a"], TypeError),
        ]:
            with self.assertRaises(error, msg=f"{line=}"):
                h.lines_wo_spaces(line)

    # ============================= int ==============================

    def test_valid__int_(self):
        """helpers.init_int()"""
        for line, req in [
            ("", 0),
            ("0", 0),
            ("10", 10),
            (0, 0),
            (10, 10),
        ]:
            result = h.init_int(line)
            self.assertEqual(result, req, msg=f"{line=}")

    def test_invalid__int_(self):
        """helpers.init_int()"""
        for line, error in [
            ({}, TypeError),
            (-1, ValueError),
            ("a", ValueError),
            ("-1", ValueError),
        ]:
            with self.assertRaises(error, msg=f"{line=}"):
                h.init_int(line)

    # =============================== list ===============================

    def test_valid__convert_to_lstr(self):
        """helpers.convert_to_lstr()"""
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
        """helpers.convert_to_lstr()"""
        for items, error in [
            (1, TypeError),
            ([1], TypeError),
        ]:
            with self.assertRaises(error, msg=f"{items=}"):
                h.convert_to_lstr(items)

    # ============================== ipnet ===============================

    def test_valid__prefix_to_ipnet(self):
        """helpers.prefix_to_ipnet()"""
        for prefix, req, req_log in [
            ("10.0.0.0/30", "10.0.0.0/30", []),
            ("10.0.0.1/30", "10.0.0.0/30", [WARNING]),
        ]:
            if req_log:
                with self.assertLogs() as logs:
                    result = h.prefix_to_ipnet(prefix=prefix)
                    self.assertEqual(str(result), req, msg=f"{prefix=}")
                    result_log = [o.levelno for o in logs.records]
                    self.assertEqual(result_log, req_log, msg="my_function")

            result = h.prefix_to_ipnet(prefix=prefix)
            self.assertEqual(str(result), req, msg=f"{prefix=}")

    def test_valid__subnet_of(self):
        """helpers.subnet_of()"""
        for tops, bottoms, req in [
            ([], [], False),
            ([], ["10.0.0.0/30"], False),
            (["10.0.0.1/32"], [], False),
            # host
            (["10.0.0.1/32"], ["10.0.0.1/32"], True),
            (["10.0.0.1/32"], ["10.0.0.0/30"], False),
            (["10.0.0.1/32"], ["10.0.0.0/24"], False),
            (["10.0.0.1/32"], ["10.0.0.1/32", "10.0.0.0/30"], False),
            (["10.0.0.1/32"], ["10.0.0.1/32", "10.0.0.0/24"], False),
            # subnet
            (["10.0.0.0/30"], ["10.0.0.1/32"], True),
            (["10.0.0.0/30"], ["10.0.0.0/30"], True),
            (["10.0.0.0/30"], ["10.0.0.0/24"], False),
            (["10.0.0.0/30"], ["10.0.0.1/32", "10.0.0.0/30"], True),
            (["10.0.0.0/30"], ["10.0.0.1/32", "10.0.0.0/24"], False),
            # supernet
            (["10.0.0.0/24"], ["10.0.0.1/32"], True),
            (["10.0.0.0/24"], ["10.0.0.0/30"], True),
            (["10.0.0.0/24"], ["10.0.0.0/24"], True),
            (["10.0.0.0/24"], ["10.0.0.1/32", "10.0.0.0/30"], True),
            (["10.0.0.0/24"], ["10.0.0.1/32", "10.0.0.0/24"], True),
            # host subnet
            (["10.0.0.1/32", "10.0.0.0/30"], ["10.0.0.1/32"], True),
            (["10.0.0.1/32", "10.0.0.0/30"], ["10.0.0.0/30"], True),
            (["10.0.0.1/32", "10.0.0.0/30"], ["10.0.0.0/24"], False),
            (["10.0.0.1/32", "10.0.0.0/30"], ["10.0.0.1/32", "10.0.0.0/30"], True),
            (["10.0.0.1/32", "10.0.0.0/30"], ["10.0.0.1/32", "10.0.0.0/24"], False),
            # host supernet
            (["10.0.0.1/32", "10.0.0.0/24"], ["10.0.0.1/32"], True),
            (["10.0.0.1/32", "10.0.0.0/24"], ["10.0.0.0/30"], True),
            (["10.0.0.1/32", "10.0.0.0/24"], ["10.0.0.0/24"], True),
            (["10.0.0.1/32", "10.0.0.0/24"], ["10.0.0.1/32", "10.0.0.0/30"], True),
            (["10.0.0.1/32", "10.0.0.0/24"], ["10.0.0.1/32", "10.0.0.0/24"], True),
        ]:
            tops_ = [IPv4Network(s) for s in tops]
            bottoms_ = [IPv4Network(s) for s in bottoms]
            result = h.subnet_of(tops=tops_, bottoms=bottoms_)
            self.assertEqual(result, req, msg=f"{tops=}")

    # ============================ ports =============================

    def test_valid__ports_to_string(self):
        """helpers.ports_to_string()"""
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

    def test_valid__string_to_ports(self):
        """helpers.string_to_ports()"""
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

    def test_invalid__string_to_ports(self):
        """helpers.string_to_ports()"""
        for line, error in [
            (1, AttributeError),
        ]:
            with self.assertRaises(error, msg=f"{line=}"):
                # noinspection PyTypeChecker
                h.string_to_ports(ports=line)


if __name__ == "__main__":
    unittest.main()
