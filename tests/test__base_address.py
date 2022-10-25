"""Unittest base_address.py"""

import unittest

from cisco_acl import Address, AddressAg
from tests.helpers_test import (
    ANY,
    CNX_ADDGR,
    GROUPOBJ,
    HOST,
    Helpers,
    IOS_ADDGR,
    PREFIX00,
    PREFIX30,
    PREFIX32,
    SUBNET30,
    WILD00,
    WILD30,
    WILD32,
    WILD_NC252,
    WILD_NC3,
)


# noinspection DuplicatedCode
class Test(Helpers):
    """BaseAddress"""

    # ========================== redefined ===========================

    def test_valid__hash__(self):
        """BaseAddress.__hash__()"""
        for line, hash_ in [
            (WILD30, ("", WILD30)),
            (PREFIX30, ("", WILD30)),
            (HOST, ("", "10.0.0.1 0.0.0.0")),
            (ANY, ("", "0.0.0.0 255.255.255.255")),
            (IOS_ADDGR, ("NAME", "")),
        ]:
            obj = Address(line=line, platform="ios")
            result = obj.__hash__()
            req = hash_.__hash__()
            self.assertEqual(result, req, msg=f"{line=}")

    def test_valid__eq__(self):
        """BaseAddress.__eq__() __ne__()"""
        prefix00 = Address(PREFIX00, platform="nxos")
        prefix30 = Address(PREFIX30, platform="nxos")
        prefix30_2 = Address(PREFIX30, platform="nxos")
        prefix30_3 = Address(PREFIX30, platform="nxos")
        prefix32 = Address(PREFIX32, platform="nxos")
        wild00 = Address(WILD00, platform="nxos")
        wild30 = Address(WILD30, platform="nxos")
        wild32 = Address(WILD32, platform="nxos")
        wild_3_3 = Address(WILD_NC3, platform="nxos")
        subnet30 = Address(SUBNET30, platform="ios", max_ncwb=30)
        addgr_ios = Address(IOS_ADDGR, platform="ios")
        addgr_cnx = Address(CNX_ADDGR, platform="nxos")

        for obj1, obj2, req, in [
            # prefix
            (prefix30, prefix00, False),
            (prefix30, prefix30, True),
            (prefix30, prefix30_2, True),
            (prefix30, prefix30_3, True),
            (prefix30, prefix32, False),
            (prefix30, wild00, False),
            (prefix30, wild30, True),
            (prefix30, wild32, False),
            (prefix30, wild_3_3, False),
            (prefix30, subnet30, False),
            (prefix30, addgr_ios, False),
            (prefix30, addgr_cnx, False),
            (prefix30, PREFIX30, False),
            # wildcard
            (wild30, prefix00, False),
            (wild30, prefix30, True),
            (wild30, prefix30_2, True),
            (wild30, prefix30_3, True),
            (wild30, prefix32, False),
            (wild30, wild00, False),
            (wild30, wild30, True),
            (wild30, wild32, False),
            (wild30, wild_3_3, False),
            (wild30, subnet30, False),
            (wild30, addgr_ios, False),
            (wild30, addgr_cnx, False),
            (wild30, PREFIX30, False),
        ]:
            result = obj1.__eq__(obj2)
            self.assertEqual(result, req, msg=f"{obj1=} {obj2=}")
            result = obj1.__ne__(obj2)
            self.assertEqual(result, not req, msg=f"{obj1=} {obj2=}")

    def test_valid__lt__(self):
        """BaseAddress.__lt__() __le__() __gt__() __ge__()"""
        for line1, line2, req_lt, req_le, req_gt, req_ge in [
            # wildcard="0.0.0.0 255.255.255.255", ipnet="0.0.0.0/0"
            (WILD00, WILD00, False, True, False, True),
            (WILD00, WILD30, True, True, False, False),
            (WILD00, WILD32, True, True, False, False),
            (WILD00, WILD_NC3, True, True, False, False),
            (WILD00, WILD_NC252, True, True, False, False),
            (WILD00, IOS_ADDGR, True, True, False, False),
            # wildcard="10.0.0.0 0.0.0.3", ipnet="10.0.0.0/30"
            (WILD30, WILD30, False, True, False, True),
            (WILD30, WILD32, True, True, False, False),
            (WILD30, WILD_NC3, True, True, False, False),
            (WILD30, WILD_NC252, True, True, False, False),
            (WILD30, IOS_ADDGR, True, True, False, False),
            # wildcard="10.0.0.1 0.0.0.0", ipnet="10.0.0.1/32"
            (WILD32, WILD32, False, True, False, True),
            (WILD32, WILD_NC3, True, True, False, False),
            (WILD32, WILD_NC252, True, True, False, False),
            (WILD32, IOS_ADDGR, True, True, False, False),
            # wildcard="10.0.0.0 0.0.3.3", ipnet=None
            (WILD_NC3, WILD_NC3, False, True, False, True),
            (WILD_NC3, WILD_NC252, False, False, True, True),
            (WILD_NC3, IOS_ADDGR, False, False, True, True),
            # wildcard="10.0.0.0 255.255.255.252", ipnet=None
            (WILD_NC252, WILD_NC252, False, True, False, True),
            (WILD_NC252, IOS_ADDGR, False, False, True, True),
            # line="group-object NAME", ipnet=None
            (IOS_ADDGR, IOS_ADDGR, False, True, False, True),
        ]:
            obj1 = Address(line1, max_ncwb=30)
            obj2 = Address(line2, max_ncwb=30)
            result = obj1.__lt__(obj2)
            self.assertEqual(result, req_lt, msg=f"{line1=} {line2=}")
            result = obj1.__le__(obj2)
            self.assertEqual(result, req_le, msg=f"{line1=} {line2=}")
            result = obj1.__gt__(obj2)
            self.assertEqual(result, req_gt, msg=f"{line1=} {line2=}")
            result = obj1.__ge__(obj2)
            self.assertEqual(result, req_ge, msg=f"{line1=} {line2=}")

    def test_valid__lt__sort(self):
        """BaseAddress.__lt__(), Address.__le__()"""
        for items in [
            # wildcard="0.0.0.0 255.255.255.255", ipnet="0.0.0.0/0"
            [Address(WILD00), Address(WILD00)],
            [Address(WILD00), Address(WILD30)],
            [Address(WILD00), Address(WILD32)],
            [Address(WILD00), Address(WILD_NC3)],
            [Address(WILD00), Address(WILD_NC252, max_ncwb=30)],
            [Address(WILD00), Address(IOS_ADDGR)],
            # wildcard="10.0.0.0 0.0.0.3", ipnet="10.0.0.0/30"
            [Address(WILD30), Address(WILD30)],
            [Address(WILD30), Address(WILD32)],
            [Address(WILD30), Address(WILD_NC3)],
            [Address(WILD30), Address(WILD_NC252, max_ncwb=30)],
            [Address(WILD30), Address(IOS_ADDGR)],
            # wildcard="10.0.0.1 0.0.0.0", ipnet="10.0.0.1/32"
            [Address(WILD32), Address(WILD32)],
            [Address(WILD32), Address(WILD_NC3)],
            [Address(WILD32), Address(WILD_NC252, max_ncwb=30)],
            [Address(WILD32), Address(IOS_ADDGR)],
            # line="group-object NAME", ipnet=None
            [Address(IOS_ADDGR), Address(IOS_ADDGR)],
            [Address(IOS_ADDGR), Address(WILD_NC252, max_ncwb=30)],
            [Address(IOS_ADDGR), Address(WILD_NC3)],
            [Address(IOS_ADDGR), Address("object-group NAME2")],
            # wildcard="10.0.0.0 255.255.255.252", ipnet=None
            [Address(WILD_NC252, max_ncwb=30), Address(WILD_NC252, max_ncwb=30)],
            [Address(WILD_NC252, max_ncwb=30), Address(WILD_NC3)],
            # wildcard="10.0.0.0 0.0.3.3", ipnet=None
            [Address(WILD_NC3), Address(WILD_NC3)],
        ]:
            req = items.copy()
            result = sorted(items)
            self.assertEqual(result, req, msg=f"{items=}")
            items[0], items[1] = items[1], items[0]
            result = sorted(items)
            self.assertEqual(result, req, msg=f"{items=}")

    def test_valid__repr__(self):
        """Port.__repr__()"""
        for obj, req in [
            # Address
            (Address(line=HOST, platform="ios", note=""), f"Address(\"{HOST}\")"),
            (Address(line=HOST, platform="nxos", note="a"),
             f"Address(\"{HOST}\", platform=\"nxos\", note=\"a\")"),
            (Address(line=CNX_ADDGR, platform="nxos", items=HOST),
             f"Address(\"{CNX_ADDGR}\", platform=\"nxos\", "
             f"items=[Address(\"{HOST}\", platform=\"nxos\")])"),
            # AddressAg
            (AddressAg(HOST, platform="ios", note=""), f"AddressAg(\"{HOST}\")"),
            (AddressAg(HOST, platform="nxos", note="a"),
             f"AddressAg(\"{HOST}\", platform=\"nxos\", note=\"a\")"),
            (AddressAg(GROUPOBJ, platform="ios", items=HOST),
             f"AddressAg(\"{GROUPOBJ}\", items=[AddressAg(\"{HOST}\")])"),
        ]:
            result = obj.__repr__()
            result = self._quotation(result)
            self.assertEqual(result, req, msg=f"{result=}")


if __name__ == "__main__":
    unittest.main()
