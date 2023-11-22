"""Unittest helpers."""

import unittest
from ipaddress import IPv4Network

import cisco_acl
from cisco_acl import Acl, AceGroup
from cisco_acl.helpers import DEF_INDENT
from cisco_acl.types_ import DAny

UUID = "ID1"
UUID_R = [("remove", "", [("uuid", "ID1")])]
UUID_R2 = [("remove", ["items", 0], [("uuid", "ID1")]), ("remove", "", [("uuid", "ID1")])]

ACL_NAME_IOS = "ip access-list extended NAME"
ACL_NAME_RP_IOS = "ip access-list extended NAME\n  remark text\n  permit ip any any"
ACL_NAME_CNX = "ip access-list NAME"
ACL_NAME_RP_CNX = "ip access-list NAME\n  remark text\n  permit ip any any"
ACL_NAME_IOS_STD = "ip access-list standard NAME"

DENY_ICMP = "deny icmp any any"
DENY_IP = "deny ip any any"
DENY_IP1 = "1 deny ip any any"
DENY_IP2 = "2 deny ip any any"

PERMIT_ADDR_GR = "permit ip addrgroup NAME any"
PERMIT_ICMP = "permit icmp any any"
PERMIT_IP = "permit ip any any"
PERMIT_0 = "permit 0 any any"
PERMIT_IP1 = "1 permit ip any any"
PERMIT_IP2 = "2 permit ip any any"
PERMIT_OBJ_GR = "permit ip object-group NAME any"
PERMIT_NUM = "permit tcp any eq 21 any eq 80"
PERMIT_NAM = "permit tcp any eq ftp any eq www"
PERMIT_TCP = "permit tcp any any"
PERMIT_UDP = "permit udp any any"
PERMIT_TCP1 = "permit tcp any any eq 1"
PERMIT_TCP2 = "permit tcp any any eq 2"
PERMIT_UDP1 = "permit udp any any eq 1"
PERMIT_WILD_252 = "permit ip 0.0.0.0 255.255.255.252 0.0.0.0 255.255.255.252"

REMARK = "remark TEXT"
REMARK1 = "1 remark TEXT"
REMARK2 = "2 remark TEXT"
REMARK3 = "3 remark TEXT"

ETH1 = "interface Ethernet1"
ETH2 = "interface Ethernet2"

NAME_IOS = "object-group network NAME"
NAME_IOS_ = "object-group network "
NAME_CNX = "object-group ip address NAME"
GROUPOBJ = "group-object NAME"

ANY = "any"
HOST = "host 10.0.0.1"
PREFIX00 = "0.0.0.0/0"
PREFIX00_32 = "0.0.0.0/32"
PREFIX24 = "10.0.0.0/24"
PREFIX30 = "10.0.0.0/30"
PREFIX31 = "10.0.0.0/31"
PREFIX32 = "10.0.0.1/32"
SUBNET00 = "0.0.0.0 0.0.0.0"
SUBNET30 = "10.0.0.0 255.255.255.252"
SUBNET32 = "10.0.0.1 255.255.255.255"
WILD00 = "0.0.0.0 255.255.255.255"
WILD30 = "10.0.0.0 0.0.0.3"
WILD32 = "10.0.0.1 0.0.0.0"
WILD_NC3 = "10.0.0.0 0.0.3.3"
WILD_NC252 = "10.0.0.0 255.255.255.252"
CNX_ADDGR = "addrgroup NAME"
IOS_ADDGR = "object-group NAME"
IPNET00 = IPv4Network("0.0.0.0/0")
IPNET00_32 = IPv4Network("0.0.0.0/32")
IPNET22 = IPv4Network("10.0.0.0/22")
IPNET30 = IPv4Network("10.0.0.0/30")
IPNET32 = IPv4Network("10.0.0.1/32")

PREFIX00_D = dict(
    line="0.0.0.0/0",
    type="prefix",
    addrgroup="",
    subnet="0.0.0.0 0.0.0.0",
    ipnet=IPNET00,
    prefix="0.0.0.0/0",
    wildcard="0.0.0.0 255.255.255.255",
)
PREFIX00_32_D = dict(
    line="0.0.0.0/32",
    type="prefix",
    addrgroup="",
    subnet="0.0.0.0 255.255.255.255",
    ipnet=IPNET00_32,
    prefix="0.0.0.0/32",
    wildcard="0.0.0.0 0.0.0.0",
)
PREFIX30_D = dict(
    line="10.0.0.0/30",
    type="prefix",
    addrgroup="",
    subnet="10.0.0.0 255.255.255.252",
    ipnet=IPNET30,
    prefix="10.0.0.0/30",
    wildcard="10.0.0.0 0.0.0.3",
)
PREFIX32_D = dict(
    line="10.0.0.1/32",
    type="prefix",
    addrgroup="",
    subnet="10.0.0.1 255.255.255.255",
    ipnet=IPNET32,
    prefix="10.0.0.1/32",
    wildcard="10.0.0.1 0.0.0.0",
)
SUBNET00_D = dict(
    line="0.0.0.0 0.0.0.0",
    type="subnet",
    addrgroup="",
    subnet="0.0.0.0 0.0.0.0",
    ipnet=IPNET00,
    prefix="0.0.0.0/0",
    wildcard="0.0.0.0 255.255.255.255",
)
SUBNET00_32_D = dict(
    line="0.0.0.0 255.255.255.255",
    type="subnet",
    addrgroup="",
    subnet="0.0.0.0 255.255.255.255",
    ipnet=IPNET00_32,
    prefix="0.0.0.0/32",
    wildcard="0.0.0.0 0.0.0.0",
)
SUBNET30_D = dict(
    line="10.0.0.0 255.255.255.252",
    type="subnet",
    addrgroup="",
    subnet="10.0.0.0 255.255.255.252",
    ipnet=IPNET30,
    prefix="10.0.0.0/30",
    wildcard="10.0.0.0 0.0.0.3",
)
SUBNET32_D = dict(
    line="10.0.0.1 255.255.255.255",
    type="subnet",
    addrgroup="",
    subnet="10.0.0.1 255.255.255.255",
    ipnet=IPNET32,
    prefix="10.0.0.1/32",
    wildcard="10.0.0.1 0.0.0.0",
)
WILD_ANY_D = dict(
    line="0.0.0.0 255.255.255.255",
    type="wildcard",
    addrgroup="",
    subnet="0.0.0.0 0.0.0.0",
    ipnet=IPNET00,
    prefix="0.0.0.0/0",
    wildcard="0.0.0.0 255.255.255.255",
)
WILD00_32_D = dict(
    line="0.0.0.0 0.0.0.0",
    type="wildcard",
    addrgroup="",
    subnet="0.0.0.0 255.255.255.255",
    ipnet=IPNET00_32,
    prefix="0.0.0.0/32",
    wildcard="0.0.0.0 0.0.0.0",
)
WILD30_D = dict(
    line="10.0.0.0 0.0.0.3",
    type="wildcard",
    addrgroup="",
    subnet="10.0.0.0 255.255.255.252",
    ipnet=IPNET30,
    prefix="10.0.0.0/30",
    wildcard="10.0.0.0 0.0.0.3",
)
WILD32_D = dict(
    line="10.0.0.1 0.0.0.0",
    type="wildcard",
    addrgroup="",
    subnet="10.0.0.1 255.255.255.255",
    ipnet=IPNET32,
    prefix="10.0.0.1/32",
    wildcard="10.0.0.1 0.0.0.0",
)
WILD_NC3_D = dict(
    line="10.0.0.0 0.0.3.3",
    type="wildcard",
    addrgroup="",
    subnet="",
    ipnet=None,
    prefix="",
    wildcard="10.0.0.0 0.0.3.3",
)
WILD_NC252_D = dict(
    line="0.0.0.0 255.255.255.252",
    type="wildcard",
    addrgroup="",
    subnet="",
    ipnet=None,
    prefix="",
    wildcard="0.0.0.0 255.255.255.252",
)
ANY_D = dict(
    line="any",
    type="any",
    addrgroup="",
    subnet="0.0.0.0 0.0.0.0",
    ipnet=IPNET00,
    prefix="0.0.0.0/0",
    wildcard="0.0.0.0 255.255.255.255",
)
HOST_D = dict(
    line="host 10.0.0.1",
    type="host",
    addrgroup="",
    subnet="10.0.0.1 255.255.255.255",
    ipnet=IPNET32,
    prefix="10.0.0.1/32",
    wildcard="10.0.0.1 0.0.0.0",
)
HOST_0_D = dict(
    line="host 0.0.0.0",
    type="host",
    addrgroup="",
    subnet="0.0.0.0 255.255.255.255",
    ipnet=IPNET00_32,
    prefix="0.0.0.0/32",
    wildcard="0.0.0.0 0.0.0.0",
)
GROUPOBJ_D = dict(
    line="group-object NAME",
    type="addrgroup",
    addrgroup="NAME",
    subnet="",
    ipnet=None,
    prefix="",
    wildcard="",
)
IOS_ADDGR_D = dict(
    line="object-group NAME",
    type="addrgroup",
    addrgroup="NAME",
    subnet="",
    ipnet=None,
    prefix="",
    wildcard="",
)
CNX_ADDGR_D = dict(
    line="addrgroup NAME",
    type="addrgroup",
    addrgroup="NAME",
    subnet="",
    ipnet=None,
    prefix="",
    wildcard="",
)


class Helpers(unittest.TestCase):
    """Unittest Helpers."""

    # =========================== helper =============================

    @staticmethod
    def _quotation(line: str) -> str:
        """Replace quotation sign."""
        return line.replace(chr(39), "\"")

    # ============================ tests =============================

    def _test_attrs(self, obj, req_d, msg: str):
        """Test obj.line and attributes in req_d.

        :param obj: Tested object.
        :param req_d: Valid attributes and values.
        :param msg: Message.
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
        """Test values of data in req_d.

        :param data: Tested dict.
        :param req_d: Valid keys and values.
        :param msg: Message.
        """
        for key, req in req_d.items():
            result = data[key]
            self.assertEqual(result, req, msg=f"{msg} {key=}")

    def _test_no_keys(self, data: dict, absent: list, msg: str):
        """Test `absent_d` keys absent in `data`.

        :param data: Tested dict.
        :param absent: Valid keys and values.
        :param msg: Message.
        """
        for key in absent:
            result = data.get(key)
            self.assertIsNone(result, msg=f"{msg} {key=}")


def make_acl(line: str, **kwargs) -> Acl:
    """Create Acl, add "ip access-list" if absent."""
    platform = kwargs.get("platform") or "nxos"
    if not line.startswith("ip access-list "):
        acl_name = "ACL_NAME"
        lines = [s.strip() for s in line.split("\n")]
        lines = [s for s in lines if s]
        lines = [f"{DEF_INDENT}{s}" for s in lines]
        cmd_acl_name = f"ip access-list extended {acl_name}"
        if platform == "nxos":
            cmd_acl_name = f"ip access-list {acl_name}"
        lines.insert(0, cmd_acl_name)
        line = "\n".join(lines)

    acl_o: Acl = cisco_acl.acls(config=line, platform=platform, group_by="=== ")[0]
    for aceg_o in acl_o.items:
        if isinstance(aceg_o, AceGroup):
            name = aceg_o.name.lstrip("=== ")
            aceg_o.name = name.split(",")[0]
    return acl_o


def make_aceg(line: str) -> DAny:
    """Create AceGroup based on ACL line, add "ip access-list" if absent."""
    acl_o = make_acl(line)
    aceg_o = acl_o.items[0]
    data = aceg_o.data()
    return data


def remove_acl_name(line: str) -> str:
    """Remove multiple spaces and "ip access-list ACL_NAME" from line."""
    items = [s.strip() for s in line.split("\n")]
    items = [s for s in items if s]
    items = [s for s in items if not s.startswith("ip access-list ")]
    return "\n".join(items)
