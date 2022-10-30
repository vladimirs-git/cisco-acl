"""Address - Source or destination address in ACE"""
from __future__ import annotations

from functools import total_ordering
from typing import Dict, Iterable, List, Optional, Union

from cisco_acl import base_address
from cisco_acl.base_address import BaseAddress
from cisco_acl.types_ import LStr, DAny, LDAny


@total_ordering
class Address(BaseAddress):
    """Address - Source or destination address in ACE"""

    def __init__(self, line: str, **kwargs):
        """Address
        :param line: Address line
            Line pattern        Platform    Description
            ==================  ==========  ===========================
            A.B.C.D A.B.C.D     ios, nxos   Address and wildcard bits
            A.B.C.D/LEN         nxos        Network prefix
            any                 ios, nxos   Any host
            host A.B.C.D        ios         A single host
            object-group NAME   ios         Network object group
            addrgroup NAME      nxos        Network object group
        :type line: str

        :param platform: Platform: "ios" (default), "nxos"
        :type platform: str

        Helpers
        :param note: Object description
        :type note: Any

        :param items: List of *Address* objects for address group
        :type items: str, List[str], dict, List[dict], Address, List[Address]

        :param max_ncwb: Max count of non-contiguous wildcard bits
        :type max_ncwb: int

        :example: wildcard
            address = Address("10.0.0.0 0.0.0.3", platform="ios")
            result:
                address.line == "10.0.0.0 0.0.0.3"
                address.addrgroup == ""
                address.ipnet == IPv4Network("10.0.0.0/30")
                address.prefix == "10.0.0.0/30"
                address.subnet == "10.0.0.0 255.255.255.252"
                address.wildcard == "10.0.0.0 0.0.0.3"

        :example: host
            address = Address("host 10.0.0.1", platform=="nxos")
            result:
                address.line == "10.0.0.1/32"
                address.addrgroup == ""
                address.ipnet == IPv4Network("10.0.0.1/32")
                address.prefix == "10.0.0.1/32"
                address.subnet == "10.0.0.1 255.255.255.255"
                address.wildcard == "10.0.0.1 0.0.0.0"

        :example: address group
            address = Address("object-group NAME", platform="ios")
            result:
                address.line == "object-group network NAME"
                address.addrgroup == "NAME"
                address.ipnet == None
                address.prefix == ""
                address.subnet == ""
                address.wildcard == ""
        """
        super().__init__(**kwargs)  # addrgroup, wildcard, items, max_ncwb, etc
        self._items: LAddress = []
        self.line = line
        if self._type == "addrgroup":
            self.items = kwargs.get("items") or []

    # =========================== property ===========================

    @property
    def items(self) -> LAddress:
        """List of *Address* objects for address group (type="addrgroup")"""
        return self._items

    @items.setter
    def items(self, items: LUAddress) -> None:
        items_ = self._init_items(items)
        self._items = [o for o in items_ if isinstance(o, Address)]

    # =========================== methods ============================


IAddress = Iterable[Address]
LAddress = List[Address]
OAddress = Optional[Address]
UAddress = Union[str, LStr, DAny, LDAny, Address, LAddress]
LUAddress = List[UAddress]
DLAddress = Dict[str, LAddress]
DDLAddress = Dict[str, DLAddress]


# ============================ functions =============================

def collapse(addresses: IAddress) -> LAddress:
    """Collapses a list of *Address* objects and deletes subnets in the shadow
        :param addresses: Iterable *Address* objects
        :return: List of collapsed *Address* objects

        :raises TypeError: Passed addresses not match conditions:
            - Item of `addresses` is not *Address*
            - Address is non-contiguous wildcard

        :example:
            wildcard = Address("10.0.0.0 0.0.0.1")
            host2 = Address("host 10.0.0.2")
            host3 = Address("host 10.0.0.3")
            collapse([wildcard, host2, host3]) -> [Address("10.0.0.0 0.0.0.3")]
    """
    addresses = list(addresses)
    for address in addresses:
        if not isinstance(address, Address):
            raise TypeError(f"{address=} {Address} expected")
    # noinspection PyProtectedMember
    collapsed = base_address.collapse_(addresses)
    collapsed_: LAddress = [o for o in collapsed if isinstance(o, Address)]
    return collapsed_
