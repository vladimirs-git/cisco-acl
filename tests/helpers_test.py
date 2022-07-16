"""Unittest helpers"""

import unittest

ACL_IOS = "ip access-list extended "
ACL_NAME_IOS = "ip access-list extended A"
ACL_NAME_RP_IOS = "ip access-list extended A\n  remark text\n  permit ip any any"
ACL_RP_IOS = "ip access-list extended \n  remark text\n  permit ip any any"

ACL_CNX = "ip access-list "
ACL_NAME_CNX = "ip access-list A"
ACL_NAME_RP_CNX = "ip access-list A\n  remark text\n  permit ip any any"
ACL_RP_CNX = "ip access-list \n  remark text\n  permit ip any any"

DENY_ICMP = "deny icmp any any"
DENY_IP = "deny ip any any"
DENY_IP_1 = "1 deny ip any any"
DENY_IP_2 = "2 deny ip any any"

PERMIT_ADDR_GR = "permit ip addrgroup NAME any"
PERMIT_ICMP = "permit icmp any any"
PERMIT_IP = "permit ip any any"
PERMIT_IP_1 = "1 permit ip any any"
PERMIT_IP_2 = "2 permit ip any any"
PERMIT_OBJ_GR = "permit ip object-group NAME any"

REMARK = "remark text"
REMARK_1 = "1 remark text"
REMARK_2 = "2 remark text"
REMARK_3 = "3 remark text"

ETH1 = "interface Ethernet1"
ETH2 = "interface Ethernet2"


class Helpers(unittest.TestCase):
    """Unittest Helpers"""

    def _test_attrs(self, obj, req_d, msg: str):
        """Test obj.line and attributes in req_d
        :param obj: Tested object
        :param req_d: Valid attributes and values
        :param msg: Message
        """
        result = obj.line
        req = req_d["line"]
        self.assertEqual(result, req, msg=f"{msg} line")
        result = str(obj)
        self.assertEqual(result, req, msg=f"{msg} str")
        for attr, req in req_d.items():
            result = getattr(obj, attr)
            if hasattr(result, "line"):
                result = str(result)
            self.assertEqual(result, req, msg=f"{msg} {attr=}")

    def _test_keys(self, data: dict, req_d: dict, msg: str):
        """Test values of data in req_d
        :param data: Tested dict
        :param req_d: Valid keys and values
        :param msg: Message
        """
        for key, req in req_d.items():
            result = data[key]
            self.assertEqual(result, req, msg=f"{msg} {key=}")

    def _test_no_keys(self, data: dict, absent: list, msg: str):
        """Test `absent_d` keys absent in `data`
        :param data: Tested dict
        :param absent: Valid keys and values
        :param msg: Message
        """
        for key in absent:
            result = data.get(key)
            self.assertIsNone(result, msg=f"{msg} {key=}")
