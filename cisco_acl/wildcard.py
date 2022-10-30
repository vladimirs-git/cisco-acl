"""Wildcard network that of Cisco ACL"""

from __future__ import annotations

from functools import lru_cache
from ipaddress import NetmaskValueError, IPv4Address, IPv4Network
from itertools import product

from cisco_acl import helpers as h
from cisco_acl.base import Base
from cisco_acl.types_ import LIpNet, LInt, DAny, OIpNet, T2IpAddr, TLintInt

PREFIX_LEN = 32  # IPv4 prefix length
ALL_ONES = (2 ** PREFIX_LEN) - 1
DEF_NCWB = 16  # Default count of non-contiguous wildcard bits
MAX_NCWB = 30  # Maximum allowed count of non-contiguous wildcard bits


class Wildcard(Base):
    """Wildcard network that of Cisco ACL"""

    def __init__(self, line: str, **kwargs):
        """Wildcard
        :param line: Network with wildcard mask
        :param max_ncwb: Max count of non-contiguous wildcard bits. Allowed in range 0..30
            0  - contiguous wildcard, 1 prefix
            30 - max allowed, 1073741824 prefixes
            16 - default, 65536 prefixes
        :type max_ncwb: int

        Helpers
        :param uuid: Unique identifier
        :type uuid: str

        :param note: Object description
        :type note: Any

        :raises NetmaskValueError: If non-contiguous wildcard increase max_ncwb
        """
        self.ipnet: OIpNet = None  # IPv4Network of contiguous wildcard
        self._ncwb: LInt = []  # non-contiguous wildcard bits
        self._prefixlen: int = 0  # Prefix length of contiguous wildcard
        super().__init__(**kwargs)  # platform, note
        self.max_ncwb: int = init_max_ncwb(**kwargs)
        self.line = line

    def __repr__(self):
        params = self._repr__params()

        max_ncwb = self.max_ncwb
        if max_ncwb != DEF_NCWB:
            params.append(f"{max_ncwb=!r}")

        name = self.__class__.__name__
        kwargs = ", ".join(params)
        return f"{name}({kwargs})"

    def __str__(self):
        return self.line

    # =========================== property ===========================

    @property
    def line(self) -> str:
        """Line of network with wildcard mask"""
        return f"{self._prefix} {self._wildmask}"

    @line.setter
    def line(self, line: str) -> None:
        line = h.init_line(line)
        prefix_o, wildmask_o = self._create_prefix(line)
        self._prefix = prefix_o
        self._wildmask = wildmask_o
        self.ipnet = self._create_ipnet()
        ncwb, prefixlen = self._create_ncwb()
        self._ncwb = ncwb
        self._prefixlen = prefixlen

    @property
    def max_ncwb(self) -> int:
        """Max count of non-contiguous wildcard bits"""
        return self._max_ncwb

    @max_ncwb.setter
    def max_ncwb(self, max_ncwb: int) -> None:
        """Max count of non-contiguous wildcard bits
        :param max_ncwb: Max count of non-contiguous wildcard bits. Allowed in range 0..30
            0  - contiguous wildcard, 1 prefix
            30 - max allowed, 1073741824 prefixes
            16 - default, 65536 prefixes
        """
        self._max_ncwb = init_max_ncwb(max_ncwb=max_ncwb)

    @property
    def prefix(self) -> str:
        """Wildcard network"""
        return str(self._prefix)

    @property
    def wildmask(self) -> str:
        """Wildcard mask"""
        return str(self._wildmask)

    # =========================== classmethod ============================

    # noinspection PyIncorrectDocstring
    @classmethod
    def fprefix(cls, prefix: str, **kwargs) -> Wildcard:
        """Converts prefix to *Wildcard* object
        :param prefix: Prefix "A.B.C.D/LEN"
        :type prefix: str

        :param max_ncwb: Max count of non-contiguous wildcard bits
        :type max_ncwb: int

        :return: *Wildcard* object
        """
        ipnet: IPv4Network = h.prefix_to_ipnet(prefix)
        line: str = ipnet.with_hostmask.replace("/", " ")
        return Wildcard(line, **kwargs)

    # noinspection PyIncorrectDocstring
    @classmethod
    def fsubnet(cls, subnet: str, **kwargs) -> Wildcard:
        """Converts subnet to *Wildcard* object
        :param subnet: Subnet with mask "A.B.C.D A.B.C.D"
        :type subnet: str

        :param max_ncwb: Max count of non-contiguous wildcard bits
        :type max_ncwb: int

        :return: *Wildcard* object
        :rtype: Wildcard
        """
        items = subnet.split()
        if len(items) != 2:
            raise ValueError(f"invalid {subnet=}")
        subnet_, mask = items
        if mask == "0.0.0.0":
            wildmask = invert_mask(mask)
            wildcard = f"{subnet_} {wildmask}"
            return Wildcard(wildcard, **kwargs)

        subnet = subnet.replace(" ", "/")
        ipnet = IPv4Network(subnet)
        if subnet != ipnet.with_netmask:
            raise ValueError(f"{subnet=} not equal ipnet={str(ipnet)!r}")
        wildcard = ipnet.with_hostmask.replace("/", " ")
        return Wildcard(wildcard, **kwargs)

    # =========================== methods ============================

    def data(self, uuid: bool = False) -> DAny:
        """Converts *Wildcard* object to *dict*
        :param uuid: Returns self.uuid in data
        :type uuid: bool

        :return: data in *dict* format
        """
        data = dict(
            # init
            line=self.line,
            max_ncwb=self.max_ncwb,
            platform=self._platform,
            note=self.note,
            # property
            ipnet=self.ipnet,
            prefix=self.prefix,
            wildmask=self.wildmask,
        )
        if uuid:
            data["uuid"] = self.uuid
        return data

    @lru_cache
    def ipnets(self) -> LIpNet:
        """List of *IPv4Network* that match this wildcard
        :return: List of *IPv4Network*
        :example:
            wildcard = Wildcard("10.0.0.0 0.0.1.3")
            wildcard.ipnets() -> [IPv4Network("10.0.0.0/30"),
                                  IPv4Network("10.0.1.0/30")]
        """
        ipnets: LIpNet = []
        prefix_i = int(self._prefix)
        repeat = len(self._ncwb)
        for bits_values in product((0, 1), repeat=repeat):
            prefix_i_ = prefix_i
            for idx, value in zip(self._ncwb, bits_values):
                mask = 1 << idx
                if value:
                    prefix_i_ |= mask
                else:
                    prefix_i_ &= ~mask
            ipnet = IPv4Network((prefix_i_, self._prefixlen))
            ipnets.append(ipnet)
        return ipnets

    # =========================== helpers ============================

    def _create_ipnet(self) -> OIpNet:
        """Init ipnet"""
        prefix = str(self._prefix)
        wildmask = str(self._wildmask)
        try:
            if str(wildmask) == "255.255.255.255":
                subnet = f"{prefix}/0"
            elif str(wildmask) == "0.0.0.0":
                subnet = f"{prefix}/{PREFIX_LEN}"
            else:
                mask = invert_mask(wildmask)
                if not is_mask(mask):
                    mask = ""
                subnet = f"{prefix}/{mask}"
            ipnet = IPv4Network(subnet)
        except NetmaskValueError:
            ipnet = None
        return ipnet

    def _create_ncwb(self) -> TLintInt:
        """Init non-contiguous wildcard bits and prefix length
        :return: List of non-contiguous wildcard bits, prefixlen
        :example:
            _init_prefix("10.0.0.0 0.0.0.3") -> IPv4Address("10.0.0.0"), IPv4Address("0.0.0.3")
        """
        wild_bits: LInt = [int(b) for b in format(int(self._wildmask), f"0{PREFIX_LEN}b")]
        wb_idxs: LInt = [i for i, e in enumerate(reversed(wild_bits)) if e == 1]
        prefixlen_idx: int = self._prefixlen_idx(wb_idxs)
        ncwb: LInt = self._ncw_bits(wb_idxs, prefixlen_idx)
        prefixlen: int = PREFIX_LEN - prefixlen_idx
        return ncwb, prefixlen

    @staticmethod
    def _create_prefix(line: str) -> T2IpAddr:
        """Converts line to prefix, wildmask as *IPv4Address*
        :return: prefix, wildmask
        :example:
            _init_prefix("10.0.0.0 0.0.0.3") -> IPv4Address("10.0.0.0"), IPv4Address("0.0.0.3")
        """
        items = line.split()
        if len(items) != 2:
            raise ValueError(f"invalid {line=}")
        prefix_i = int(IPv4Address(items[0]))
        wildmask_o = IPv4Address(items[1])
        wildmask_i = int(wildmask_o)
        inverted_i = ALL_ONES ^ wildmask_i
        prefix_i = prefix_i & inverted_i
        prefix_o = IPv4Address(prefix_i)
        return prefix_o, wildmask_o

    def _ncw_bits(self, wb_idxs: LInt, prefixlen_idx: int) -> LInt:
        """Returns non-contiguous wildcard mask bits
        :param wb_idxs: Wildcard mask bit indexes
        :param prefixlen_idx: Index to get indexes of IPv4Network prefix length
        :raise NetmaskValueError: If non-contiguous wildcard mask bits count increase allowed
        """
        ncwb: LInt = wb_idxs[prefixlen_idx:]
        ncwb.reverse()

        count = len(ncwb)
        if count > self.max_ncwb:
            wild_mask = str(self._wildmask)
            max_ncwb = self.max_ncwb
            msg = f"non-contiguous wildcard bits {count=} increases {max_ncwb=} in {wild_mask=}"
            raise NetmaskValueError(msg)

        return ncwb

    @staticmethod
    def _prefixlen_idx(mask_bit_idxs: LInt) -> int:
        """Gets last bits in wildcard mask amd returns index to get prefix length
        :return: Index to get indexes of IPv4Network prefix length
        """
        prefixlen_idx = 0
        for idx, mask_bit_idx in enumerate(mask_bit_idxs):
            if idx != mask_bit_idx:
                break
            prefixlen_idx += 1
        return prefixlen_idx


# ============================ functions =============================

# noinspection PyIncorrectDocstring
def init_max_ncwb(**kwargs) -> int:
    """Init max non-contiguous wildcard bits count
    :param max_ncwb: Max count of non-contiguous wildcard bits. Allowed in range 0..30
        0  - contiguous wildcard, 1 prefix
        30 - max allowed, 1073741824 prefixes
        16 - default, 65536 prefixes
    """
    max_ncwb = kwargs.get("max_ncwb")
    if max_ncwb is None:
        max_ncwb = DEF_NCWB
    if not isinstance(max_ncwb, int):
        raise TypeError(f"{max_ncwb=} {int} expected")
    if not 0 <= max_ncwb <= MAX_NCWB:
        raise ValueError(f"invalid {max_ncwb=}, allowed in range 0..{MAX_NCWB}")
    return max_ncwb


def invert_mask(mask: str) -> str:
    """Inverts mask to wildcard and vice versa
    :param mask: Mask or wildmask "0.0.0.3"
    :return: Inverted mask or wildmask
    :example: wildmask to mask
        invert_mask("0.0.0.3") -> "0.0.0.252"
    :example: mask to wildmask
        invert_mask("0.0.0.252") -> "0.0.0.3"
    """
    return ".".join([str(255 - int(s)) for s in mask.split(".")])


def is_contiguous_wildmask(mask: str) -> bool:
    """Checks mask.
      True  - if contiguous wildcard mask
      False - if non-contiguous wildcard mask or generic mask
    :example:
        is_contiguous_wildmask("0.0.0.3") -> True
        is_contiguous_wildmask("0.0.3.3") -> False
        is_contiguous_wildmask("255.255.255.252") -> False
    """
    if mask_i := sum_octets(mask):
        bits = "{0:b}".format(mask_i)
        return "0" not in set(bits)
    return True


def is_mask(mask: str) -> bool:
    """Checks mask.
      True  - if generic mask
      False - if wildcard mask
    :example:
    is_mask("255.255.255.252") -> True
        is_mask("0.0.0.3") -> False
        is_mask("0.0.3.3") -> False
    """
    if mask_i := sum_octets(mask):
        bits = "".join([str(b) for b in format(int(mask_i), f"0{PREFIX_LEN}b")])
        bits = bits.lstrip("1")
        return "1" not in set(bits)
    return True


def sum_octets(mask: str) -> int:
    """Returns sum of "A.B.C.D" octets"""
    octets: LInt = [int(s) for s in mask.split(".")]
    if len(octets) != 4:
        raise ValueError(f"invalid {mask=}, expected 4 octets")
    return sum([octets[0] * 256 ** 3, octets[1] * 256 ** 2, octets[2] * 256, octets[3]])
