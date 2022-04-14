"""unittest address.py"""

import unittest

from netaddr import IPNetwork  # type: ignore

from cisco_acl.address import Address


# noinspection DuplicatedCode
class Test(unittest.TestCase):
    """Address"""

    # =========================== property ===========================

    def test_valid__line(self):
        """Address.line"""
        ipnet0 = IPNetwork("0.0.0.0/0")
        ipnet30 = IPNetwork("10.0.0.0/30")
        ipnet32 = IPNetwork("10.0.0.1/32")
        any_d = dict(
            line="any",
            addrgroup="",
            subnet="0.0.0.0 0.0.0.0",
            ipnet=ipnet0,
            prefix="0.0.0.0/0",
            wildcard="0.0.0.0 255.255.255.255",
        )
        wild_d = dict(
            line="10.0.0.0 0.0.0.3",
            addrgroup="",
            subnet="10.0.0.0 255.255.255.252",
            ipnet=ipnet30,
            prefix="10.0.0.0/30",
            wildcard="10.0.0.0 0.0.0.3",
        )
        wild_2_d = dict(
            line="10.0.0.0 0.0.3.3",
            addrgroup="",
            subnet="",
            ipnet=None,
            prefix="",
            wildcard="10.0.0.0 0.0.3.3",
        )
        cnx_prefix_d = dict(
            line="10.0.0.0/30",
            addrgroup="",
            subnet="10.0.0.0 255.255.255.252",
            ipnet=ipnet30,
            prefix="10.0.0.0/30",
            wildcard="10.0.0.0 0.0.0.3",
        )
        ios_host_d = dict(
            line="host 10.0.0.1",
            addrgroup="",
            subnet="10.0.0.1 255.255.255.255",
            ipnet=ipnet32,
            prefix="10.0.0.1/32",
            wildcard="10.0.0.1 0.0.0.0",
        )
        cnx__host_d = dict(
            line="10.0.0.1/32",
            addrgroup="",
            subnet="10.0.0.1 255.255.255.255",
            ipnet=ipnet32,
            prefix="10.0.0.1/32",
            wildcard="10.0.0.1 0.0.0.0",
        )
        ios_addrgroup_d = dict(
            line="object-group NAME",
            addrgroup="NAME",
            subnet="",
            ipnet=None,
            prefix="",
            wildcard="",
        )
        cnx_addrgroup_d = dict(
            line="addrgroup NAME",
            addrgroup="NAME",
            subnet="",
            ipnet=None,
            prefix="",
            wildcard="",
        )
        for platform, line, req_d in [
            ("ios", "any", any_d),
            ("ios", "10.0.0.0 0.0.0.3", wild_d),
            ("ios", "10.0.0.0 0.0.3.3", wild_2_d),
            ("ios", "10.0.0.0/30", wild_d),
            ("ios", "10.0.0.1/32", ios_host_d),
            ("ios", "host 10.0.0.1", ios_host_d),
            ("ios", "object-group NAME", ios_addrgroup_d),
            ("ios", "addrgroup NAME", ios_addrgroup_d),

            ("cnx", "any", any_d),
            ("cnx", "10.0.0.0 0.0.0.3", cnx_prefix_d),
            ("cnx", "10.0.0.0 0.0.3.3", wild_2_d),
            ("cnx", "10.0.0.0/30", cnx_prefix_d),
            ("cnx", "10.0.0.1/32", cnx__host_d),
            ("cnx", "host 10.0.0.1", cnx__host_d),
            ("cnx", "object-group NAME", cnx_addrgroup_d),
            ("cnx", "addrgroup NAME", cnx_addrgroup_d),
        ]:
            # getter
            addr_o = Address(line=line, platform=platform)
            result = addr_o.line
            req = req_d["line"]
            self.assertEqual(result, req, msg=f"{line=}")
            result = str(addr_o)
            self.assertEqual(result, req, msg=f"{line=}")
            for attr, req in req_d.items():
                result = getattr(addr_o, attr)
                self.assertEqual(result, req, msg=f"{line=}")

            # setter
            addr_o.line = line
            result = addr_o.line
            req = req_d["line"]
            self.assertEqual(result, req, msg=f"setter {line=}")

            # deleter
            with self.assertRaises(AttributeError, msg=f"deleter {line=}"):
                # noinspection PyPropertyAccess
                del addr_o.line

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


if __name__ == "__main__":
    unittest.main()
