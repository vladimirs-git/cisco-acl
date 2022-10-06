"""unittest config_parser.py"""

import unittest

import dictdiffer  # type: ignore

from cisco_acl.config_parser import ConfigParser
from cisco_acl.types_ import LDAny

VERSION = """Cisco Nexus Operating System (NX-OS) Software
Software
 NXOS: version 9.3(8)
Hardware
  cisco Nexus9000 C93180YC-EX chassis
"""
SHOW = {"show version": VERSION}
ADDGR = """
hostname HOSTNAME
object-group ip address AG_NAME
  10 host 1.1.1.1
  20 2.2.2.0/24
  30 3.3.3.0 0.0.0.3
object-group ip port PORT
  10 eq 17
  20 range 1000 2000
  30 lt 10
"""
POL1 = """
hostname HOSTNAME
interface Ethernet1/54
  ip access-group ACL_NAME in
ip access-list ACL_NAME
  statistics per-entry
  10 remark === C-1, text
  20 permit tcp 10.0.0.1/32 eq 1 10.0.0.0/8 range 3 5 log
  30 remark === C-2
  40 deny ip 10.0.0.2/32 any
interface Ethernet1/55
  description unused
ip access-list UNUSED
  10 remark unused
  20 permit ip 10.0.0.253/32 any
"""
POL2 = """
hostname HOSTNAME
interface Ethernet1/54
  ip access-group ACL_NAME in
ip access-list ACL_NAME
  statistics per-entry
  10 remark === C-1, text
  20 permit tcp 10.0.0.1/32 eq 1 10.0.0.0/8 range 3 5 log
  30 deny ip 10.0.0.1/32 any
  40 remark === C-2
  50 deny ip 10.0.0.2/32 any
"""


class Test(unittest.TestCase):
    """ConfigParser"""

    def test_valid__addgrs(self):
        """ConfigParser.addgrs()"""
        addgrs1 = [dict(name="AG_NAME",
                        items=["10 host 1.1.1.1", "20 2.2.2.0/24", "30 3.3.3.0 0.0.0.3"],
                        platform="nxos")]
        for kwargs, req_d in [
            (dict(platform="nxos", config=""), []),
            (dict(platform="nxos", config=ADDGR), addgrs1),
        ]:
            parser = ConfigParser(**kwargs)
            parser.parse_config()
            result = parser.addgrs()
            diff = list(dictdiffer.diff(first=result, second=req_d))
            self.assertEqual(diff, [], msg=f"{kwargs=}")

    def test_valid__acls(self):
        """ConfigParser.acls()"""
        acl1 = dict(name="ACL_NAME",
                    line="ip access-list ACL_NAME\n"
                         "statistics per-entry\n"
                         "10 remark === C-1, text\n"
                         "20 permit tcp 10.0.0.1/32 eq 1 10.0.0.0/8 range 3 5 log\n"
                         "30 remark === C-2\n"
                         "40 deny ip 10.0.0.2/32 any",
                    input=["interface Ethernet1/54"],
                    output=[],
                    platform="nxos",
                    type="extended")
        acl2 = dict(name="UNUSED",
                    line="ip access-list UNUSED\n"
                         "10 remark unused\n"
                         "20 permit ip 10.0.0.253/32 any",
                    input=[],
                    output=[],
                    platform="nxos",
                    type="extended")
        for config, req in [
            ("", []),
            (POL1, [acl1, acl2]),
        ]:
            parser = ConfigParser(config=config, platform="nxos")
            parser.parse_config()
            result: LDAny = parser.acls()
            diff = list(dictdiffer.diff(first=result, second=req))
            self.assertEqual(diff, [], msg=f"{config=}")


if __name__ == "__main__":
    unittest.main()
