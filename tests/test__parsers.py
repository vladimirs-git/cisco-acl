"""Unittest parsers.py"""

import unittest

import dictdiffer  # type: ignore

from cisco_acl import parsers
from cisco_acl.types_ import LDStr
from tests import helpers_test as ht


# noinspection DuplicatedCode
class Test(unittest.TestCase):
    """Parsers"""

    # =========================== helper =============================

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

        lines_d = []  # result
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

        lines_d = []  # result
        for line in lines:
            line_d = {}
            items = line.split(",")
            for item in items:
                key, value = item.split("=")
                line_d[key] = value
            lines_d.append(line_d)

        return lines_d

    # ============================= dict =============================

    def test_valid__parse_ace_extended(self):
        """helpers.parse_ace_extended()"""
        pattern = "{sequence} {action} {protocol} {srcaddr} {srcport} {dstaddr} {dstport} {option}"
        items: LDStr = self._generate_aces_req()
        for req_d in items:
            line = pattern.format(**req_d)
            line = " ".join(line.split())

            result_d = parsers.parse_ace_extended(line)
            for key, result in result_d.items():
                req = req_d[key]
                self.assertEqual(result, req, msg=f"{line=} {key=}")

    def test_invalid__parse_ace_extended(self):
        """helpers.parse_ace_extended()"""
        for line, req in [
            ("permit host 10.0.0.1", {}),
            ("permit ip", {}),
            ("remark permit ip any any", {}),
            ("10 permit host 10.0.0.1", {}),
            ("10 permit ip", {}),
            ("10 remark permit ip any any", {}),
        ]:
            result = parsers.parse_ace_extended(line)
            self.assertEqual(result, req, msg=f"{line=}")

    def test_valid__parse_ace_standard(self):
        """helpers.parse_ace_standard()"""
        base = dict(sequence="", action="permit", protocol="ip", srcaddr="",
                    srcport="", dstaddr="any", dstport="", option="")
        for line, req_d in [
            (f"permit {ht.HOST}", dict(srcaddr=ht.HOST)),
            (f"permit {ht.WILD30} log", dict(srcaddr=ht.WILD30, option="log")),
            (f"10 permit {ht.HOST}", dict(sequence="10", srcaddr=ht.HOST)),
            (f"10 permit {ht.WILD30} log", dict(sequence="10", srcaddr=ht.WILD30, option="log")),
        ]:
            req_d = {**base, **req_d}
            result = parsers.parse_ace_standard(line)
            diff = list(dictdiffer.diff(first=result, second=req_d))
            self.assertEqual(diff, [], msg=f"{line=}")

    def test_invalid__parse_ace_standard(self):
        """helpers.parse_ace_standard()"""
        for line, req in [
            ("permit ip", {}),
            ("remark permit ip any any", {}),
            ("10 permit ip", {}),
            ("10 remark permit ip any any", {}),
        ]:
            result = parsers.parse_ace_standard(line)
            self.assertEqual(result, req, msg=f"{line=}")

    def test_valid__parse_dstport_option(self):
        """helpers.parse_dstport_option()"""
        items: LDStr = self._generate_dstport_option_req()
        for req_d in items:
            line = "{dstport} {option}".format(**req_d)
            line = " ".join(line.split())

            result_d = parsers._parse_dstport_option(line)
            for key, result in result_d.items():
                req = req_d[key]
                self.assertEqual(result, req, msg=f"{line=} {key=}")

    def test_valid__parse_action(self):
        """helpers.parse_action()"""
        for line, req_d in [
            (ht.REMARK, dict(sequence="", action="remark", text="TEXT")),
            (ht.PERMIT_IP, dict(sequence="", action="permit", text="ip any any")),
            (ht.DENY_IP, dict(sequence="", action="deny", text="ip any any")),

            (f"1 {ht.REMARK}", dict(sequence="1", action="remark", text="TEXT")),
            (f"1 {ht.PERMIT_IP}", dict(sequence="1", action="permit", text="ip any any")),
            (f"1 {ht.DENY_IP}", dict(sequence="1", action="deny", text="ip any any")),
        ]:
            result = parsers.parse_action(line)
            diff = list(dictdiffer.diff(first=result, second=req_d))
            self.assertEqual(diff, [], msg=f"{line=}")

    def test_invalid__parse_action(self):
        """helpers.parse_action()"""
        for line, error in [
            ("", ValueError),
            ("remark", ValueError),
            ("permit", ValueError),
            ("10 permit", ValueError),
            ("eq 1 log www", ValueError),
        ]:
            with self.assertRaises(error, msg=f"{line=}"):
                parsers.parse_action(line)

    def test_valid__parse_address(self):
        """helpers.parse_address()"""
        for line, req_d in [
            (ht.HOST, dict(sequence="", address=ht.HOST)),
            (ht.PREFIX30, dict(sequence="", address=ht.PREFIX30)),
            (ht.SUBNET30, dict(sequence="", address=ht.SUBNET30)),
            (ht.WILD30, dict(sequence="", address=ht.WILD30)),
            (ht.GROUPOBJ, dict(sequence="", address=ht.GROUPOBJ)),

            (f"1 {ht.HOST}", dict(sequence="1", address=ht.HOST)),
            (f"1 {ht.PREFIX30}", dict(sequence="1", address=ht.PREFIX30)),
            (f"1 {ht.SUBNET30}", dict(sequence="1", address=ht.SUBNET30)),
            (f"1 {ht.WILD30}", dict(sequence="1", address=ht.WILD30)),
            (f"1 {ht.GROUPOBJ}", dict(sequence="1", address=ht.GROUPOBJ)),

        ]:
            result = parsers.parse_address(line)
            diff = list(dictdiffer.diff(first=result, second=req_d))
            self.assertEqual(diff, [], msg=f"{line=}")


if __name__ == "__main__":
    unittest.main()
