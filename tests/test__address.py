"""Unittest address.py"""

import unittest
from ipaddress import ip_network

from cisco_acl import Address
from tests.helpers_test import Helpers

OBJGROUP = "object-group NAME"
ADDRGROUP = "addrgroup NAME"
PREFIX0 = "0.0.0.0/0"
PREFIX30 = "10.0.0.0/30"
PREFIX32 = "10.0.0.1/32"
IPNET0 = ip_network("0.0.0.0/0")
IPNET30 = ip_network("10.0.0.0/30")
IPNET32 = ip_network("10.0.0.1/32")
ANY_D = dict(
    line="any",
    addrgroup="",
    subnet="0.0.0.0 0.0.0.0",
    ipnet=IPNET0,
    prefix="0.0.0.0/0",
    wildcard="0.0.0.0 255.255.255.255",
)
WILD_D = dict(
    line="10.0.0.0 0.0.0.3",
    addrgroup="",
    subnet="10.0.0.0 255.255.255.252",
    ipnet=IPNET30,
    prefix="10.0.0.0/30",
    wildcard="10.0.0.0 0.0.0.3",
)
WILD2_D = dict(
    line="10.0.0.0 0.0.3.3",
    addrgroup="",
    subnet="",
    ipnet=None,
    prefix="",
    wildcard="10.0.0.0 0.0.3.3",
)
NXOS_PREFIX_D = dict(
    line="10.0.0.0/30",
    addrgroup="",
    subnet="10.0.0.0 255.255.255.252",
    ipnet=IPNET30,
    prefix="10.0.0.0/30",
    wildcard="10.0.0.0 0.0.0.3",
)
IOS_HOST_D = dict(
    line="host 10.0.0.1",
    addrgroup="",
    subnet="10.0.0.1 255.255.255.255",
    ipnet=IPNET32,
    prefix="10.0.0.1/32",
    wildcard="10.0.0.1 0.0.0.0",
)
NXOS_HOST_D = dict(
    line="10.0.0.1/32",
    addrgroup="",
    subnet="10.0.0.1 255.255.255.255",
    ipnet=IPNET32,
    prefix="10.0.0.1/32",
    wildcard="10.0.0.1 0.0.0.0",
)
IOS_ADDRGROUP_D = dict(
    line="object-group NAME",
    addrgroup="NAME",
    subnet="",
    ipnet=None,
    prefix="",
    wildcard="",
)
NXOS_ADDRGROUP_D = dict(
    line="addrgroup NAME",
    addrgroup="NAME",
    subnet="",
    ipnet=None,
    prefix="",
    wildcard="",
)


# noinspection DuplicatedCode
class Test(Helpers):
    """Address"""

    # ========================== redefined ===========================

    def test_valid__hash__(self):
        """Address.__hash__()"""
        line = PREFIX30
        addr_o = Address(line, platform="nxos")
        result = addr_o.__hash__()
        req = PREFIX30.__hash__()
        self.assertEqual(result, req, msg=f"{line=}")

        addr_o.platform = "ios"
        result = addr_o.__hash__()
        self.assertNotEqual(result, req, msg=f"{line=}")

    def test_valid__eq__(self):
        """Address.__eq__() __ne__()"""
        addr_o = Address(PREFIX30, platform="nxos")
        for other_o, req, in [
            (PREFIX30, True),
            (Address(PREFIX30, platform="nxos"), True),
            (Address(PREFIX30, platform="ios"), False),
            (Address(OBJGROUP), False),
        ]:
            result = addr_o.__eq__(other_o)
            self.assertEqual(result, req, msg=f"{addr_o=} {other_o=}")
            result = addr_o.__ne__(other_o)
            self.assertEqual(result, not req, msg=f"{addr_o=} {other_o=}")

    def test_valid__lt__(self):
        """Address.__lt__() __le__() __gt__() __ge__()"""
        for ace_o, other_o, req_lt, req_le, req_gt, req_ge in [
            (Address(PREFIX30), Address(PREFIX30), False, True, False, True),
            (Address(PREFIX30), Address(PREFIX32), True, True, False, False),
            (Address(PREFIX30), Address(OBJGROUP), True, True, False, False),
        ]:
            result = ace_o.__lt__(other_o)
            self.assertEqual(result, req_lt, msg=f"{ace_o=} {other_o=}")
            result = ace_o.__le__(other_o)
            self.assertEqual(result, req_le, msg=f"{ace_o=} {other_o=}")
            result = ace_o.__gt__(other_o)
            self.assertEqual(result, req_gt, msg=f"{ace_o=} {other_o=}")
            result = ace_o.__ge__(other_o)
            self.assertEqual(result, req_ge, msg=f"{ace_o=} {other_o=}")

    def test_valid__lt__sort(self):
        """Address.__lt__(), Address.__le__()"""
        for items in [
            [Address(PREFIX30), Address(PREFIX30)],
            [Address(PREFIX30), Address(PREFIX32)],
            [Address(PREFIX30), Address(OBJGROUP)],
            [Address(ADDRGROUP), Address(OBJGROUP)],
        ]:
            req = items.copy()
            result = sorted(items)
            self.assertEqual(result, req, msg=f"{items=}")
            items[0], items[1] = items[1], items[0]
            result = sorted(items)
            self.assertEqual(result, req, msg=f"{items=}")

    # =========================== property ===========================

    def test_valid__line(self):
        """Address.line"""
        for platform, line, req_d in [
            ("ios", "any", ANY_D),
            ("ios", "10.0.0.0 0.0.0.3", WILD_D),
            ("ios", "10.0.0.0 0.0.3.3", WILD2_D),
            ("ios", "10.0.0.0/30", WILD_D),
            ("ios", "10.0.0.1/32", IOS_HOST_D),
            ("ios", "host 10.0.0.1", IOS_HOST_D),
            ("ios", "object-group NAME", IOS_ADDRGROUP_D),
            ("ios", "addrgroup NAME", IOS_ADDRGROUP_D),

            ("nxos", "any", ANY_D),
            ("nxos", "10.0.0.0 0.0.0.3", NXOS_PREFIX_D),
            ("nxos", "10.0.0.0 0.0.3.3", WILD2_D),
            ("nxos", "10.0.0.0/30", NXOS_PREFIX_D),
            ("nxos", "10.0.0.1/32", NXOS_HOST_D),
            ("nxos", "host 10.0.0.1", NXOS_HOST_D),
            ("nxos", "object-group NAME", NXOS_ADDRGROUP_D),
            ("nxos", "addrgroup NAME", NXOS_ADDRGROUP_D),
        ]:
            # getter
            addr_o = Address(line=line, platform=platform)
            self._test_attrs(obj=addr_o, req_d=req_d, msg=f"getter {line=}")

            # setter
            addr_o.line = line
            self._test_attrs(obj=addr_o, req_d=req_d, msg=f"setter {line=}")

        # deleter
        addr_o = Address(line="10.0.0.0 0.0.0.3")
        # noinspection PyPropertyAccess
        del addr_o.line
        self._test_attrs(obj=addr_o, req_d=ANY_D, msg="deleter line")

    def test_invalid__line(self):
        """Address.line"""
        for address, error in [
            (1, TypeError),
            ("", ValueError),
            ("typo", ValueError),
            (["any"], TypeError),
        ]:
            with self.assertRaises(error, msg=f"{address=}"):
                Address(address)

    def test_valid__addrgroup(self):
        """Address.addrgroup()"""
        for platform, line, req_d in [
            ("ios", "object-group NAME", IOS_ADDRGROUP_D),
            ("ios", "addrgroup NAME", IOS_ADDRGROUP_D),
            ("nxos", "object-group NAME", NXOS_ADDRGROUP_D),
            ("nxos", "addrgroup NAME", NXOS_ADDRGROUP_D),
        ]:
            # getter
            addr_o = Address(line, platform=platform)
            self._test_attrs(obj=addr_o, req_d=req_d, msg=f"getter addrgroup {platform=}")

            # setter
            addr_o.addrgroup = "NAME"
            self._test_attrs(obj=addr_o, req_d=req_d, msg=f"setter addrgroup {platform=}")

            # deleter
            with self.assertRaises(AttributeError, msg="deleter addrgroup"):
                # noinspection PyPropertyAccess
                del addr_o.addrgroup

    def test_invalid__addrgroup(self):
        """Address.addrgroup()"""
        proto_o = Address("object-group NAME")
        for name, error in [
            ("with space", ValueError),
            ("1a", ValueError),
            ("_a", ValueError),
            ("a?", ValueError),
        ]:
            with self.assertRaises(error, msg=f"{name=}"):
                proto_o.addrgroup = name
            with self.assertRaises(error, msg=f"{name=}"):
                Address(name)

    def test_valid__ipnet(self):
        """Address.ipnet()"""
        for platform, ipnet, req_d in [
            ("ios", IPNET30, WILD_D),
            ("nxos", IPNET30, NXOS_PREFIX_D),
        ]:
            # getter
            addr_o = Address(str(ipnet), platform=platform)
            self._test_attrs(obj=addr_o, req_d=req_d, msg=f"getter ipnet {platform=}")

            # setter
            addr_o.ipnet = ipnet
            self._test_attrs(obj=addr_o, req_d=req_d, msg=f"setter ipnet {platform=}")

            # deleter
            with self.assertRaises(AttributeError, msg="deleter ipnet"):
                # noinspection PyPropertyAccess
                del addr_o.ipnet

    def test_invalid__ipnet(self):
        """Address.ipnet()"""
        proto_o = Address(PREFIX30)
        for ipnet, error in [
            (PREFIX30, TypeError),
        ]:
            with self.assertRaises(error, msg=f"{ipnet=}"):
                proto_o.ipnet = ipnet

    def test_valid__prefix(self):
        """Address.prefix()"""
        for prefix, platform, req_d in [
            ("any", "ios", ANY_D),
            ("any", "nxos", ANY_D),
            ("0.0.0.0 255.255.255.255", "ios", ANY_D),
            ("0.0.0.0 255.255.255.255", "nxos", ANY_D),
            ("10.0.0.0 0.0.3.3", "ios", WILD2_D),
            ("10.0.0.0 0.0.3.3", "nxos", WILD2_D),
            (PREFIX0, "ios", ANY_D),
            (PREFIX0, "nxos", ANY_D),
            (PREFIX30, "ios", WILD_D),
            (PREFIX30, "nxos", NXOS_PREFIX_D),
            (PREFIX32, "ios", IOS_HOST_D),
            (PREFIX32, "nxos", NXOS_HOST_D),
        ]:
            # getter
            addr_o = Address(prefix, platform=platform)
            self._test_attrs(obj=addr_o, req_d=req_d, msg=f"getter prefix {platform=}")

            # setter
            addr_o.prefix = prefix
            self._test_attrs(obj=addr_o, req_d=req_d, msg=f"setter prefix {platform=}")

            # deleter
            with self.assertRaises(AttributeError, msg="deleter prefix"):
                # noinspection PyPropertyAccess
                del addr_o.prefix

    def test_invalid__prefix(self):
        """Address.prefix()"""
        proto_o = Address(PREFIX30)
        for prefix, error in [
            ("", ValueError),
            ("1.1.1", ValueError),
        ]:
            with self.assertRaises(error, msg=f"{prefix=}"):
                proto_o.prefix = prefix

    def test_valid__subnet(self):
        """Address.subnet()"""
        subnet30 = "10.0.0.0 255.255.255.252"
        for platform, subnet, req_d in [
            ("ios", subnet30, WILD_D),
            ("nxos", subnet30, NXOS_PREFIX_D),
        ]:
            # setter
            addr_o = Address(PREFIX30, platform=platform)
            addr_o.subnet = subnet
            self._test_attrs(obj=addr_o, req_d=req_d, msg=f"setter subnet {platform=}")

            # deleter
            with self.assertRaises(AttributeError, msg="deleter subnet"):
                # noinspection PyPropertyAccess
                del addr_o.subnet

    def test_invalid__subnet(self):
        """Address.subnet()"""
        proto_o = Address(PREFIX30)
        for subnet, error in [
            ("", ValueError),
            ("1.1.1.1", ValueError),
            (PREFIX30, ValueError),
        ]:
            with self.assertRaises(error, msg=f"{subnet=}"):
                proto_o.subnet = subnet

    def test_valid__wildcard(self):
        """Address.wildcard()"""
        wildcard30 = "10.0.0.0 0.0.0.3"
        for platform, wildcard, req_d in [
            ("ios", wildcard30, WILD_D),
            ("nxos", wildcard30, NXOS_PREFIX_D),
        ]:
            # setter
            addr_o = Address(PREFIX30, platform=platform)
            addr_o.wildcard = wildcard
            self._test_attrs(obj=addr_o, req_d=req_d, msg=f"setter wildcard {platform=}")

            # deleter
            with self.assertRaises(AttributeError, msg="deleter wildcard"):
                # noinspection PyPropertyAccess
                del addr_o.wildcard

    def test_invalid__wildcard(self):
        """Address.wildcard()"""
        proto_o = Address(PREFIX30)
        for wildcard, error in [
            ("", ValueError),
            ("1.1.1.1", ValueError),
            (PREFIX30, ValueError),
        ]:
            with self.assertRaises(error, msg=f"{wildcard=}"):
                proto_o.wildcard = wildcard


if __name__ == "__main__":
    unittest.main()
