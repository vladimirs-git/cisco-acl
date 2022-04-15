"""ACE helper functions"""

import re
from string import ascii_letters, digits, punctuation
from typing import Any, List, NamedTuple

from netaddr import IPNetwork  # type: ignore

from cisco_acl.static import ACTIONS, OPERATORS, PORTS, MAX_LINE_LENGTH
from cisco_acl.types_ import DStr, LStr, StrInt, LInt, OInt, SInt


# =============================== str ================================


def check_line_length(line: str) -> bool:
    """True if line length <= 100 chars, else raise ERROR"""
    length = len(line)
    expected = MAX_LINE_LENGTH
    if length > expected:
        raise ValueError(f"invalid line {length=}, {expected=}")
    return True


def check_name(name: str) -> bool:
    """True if first char is ascii_letters, other chars can be punctuation, else raise ERROR"""
    if not name:
        raise ValueError(f"absent {name=}")
    first_char = name[0]
    if first_char not in ascii_letters:
        raise ValueError(f"acl name {first_char=}, expected={ascii_letters}")
    skip_chas = {"?"}
    valid_chars = set(ascii_letters + digits + punctuation).difference(skip_chas)
    if invalid_chars := set(name).difference(valid_chars):
        raise ValueError(f"{invalid_chars=} in name")
    return True


def replace_spaces(line: str) -> str:
    """Replace multiple white spaces with single space."""
    return " ".join(line.split())


def line_wo_spaces(line: str) -> str:
    """Return <str>. Replace multiple white spaces with single space."""
    if not isinstance(line, str):
        raise TypeError(f"{line=} {str} expected")
    return replace_spaces(line)


def lines_wo_spaces(line: str) -> LStr:
    """Return List[str]. Replace multiple white spaces with single space."""
    if not isinstance(line, str):
        raise TypeError(f"{line=} {str} expected")
    lines = line.split("\n")
    lines = [line_wo_spaces(s) for s in lines]
    return [s for s in lines if s]


def re_find_s(regex: str, line: str) -> str:
    """Find interested line.
    :param regex: Regex pattern, should contain one group.
    :param line: String body.
    :return: Interested text or empty line.
    """
    return (re.findall(regex, line) or [""])[0]


def re_find_t(regex: str, line: str) -> tuple:
    """Find interested tuple.
    :param regex: Regex pattern, should contain groups.
    :param line: String body.
    :return: Tuple with interested values or empty tuple
    """
    return (re.findall(regex, line) or [tuple()])[0]


# =============================== int ================================

def str_to_positive_int(line: StrInt) -> int:
    """Convert str to positive int"""
    if not isinstance(line, (int, str)):
        raise TypeError(f"{line=} {int} or {str} expected")
    if isinstance(line, str):
        line = line.strip()
        line = line.split()[0] if line else "0"
        if not line.isdigit():
            raise ValueError(f"{line=}, {int} expected")
    sequence = int(line)
    if sequence < 0:
        raise ValueError(f"invalid {sequence=}, positive expected")
    return sequence


# =============================== list ===============================

def convert_to_lstr(items: Any, name: str = "") -> LStr:
    """Convert items to List[str]. If items has other type, raise ERROR."""
    if not items:
        items = []
    if isinstance(items, str):
        items = [items]
    items = list(items)
    items_: LStr = []
    for item in items:
        if isinstance(item, str):
            items_.append(item)
        else:
            raise TypeError(f"{name} {item=} {str} expected")
    return items_


# =============================== dict ===============================

def parse_ace(line: str) -> DStr:
    """Parse ACE line to elements.
    Example:
        :param line: "10 permit tcp host 1.1.1.1 eq 1025 10.0.0.0 255.0.0.0 eq web log"
        :return: {"sequence": 10,
                  "action": "permit",
                  "protocol": "tcp",
                  "srcaddr": "host 1.1.1.1",
                  "srcport": "eq 1025",
                  "dstaddr": "10.0.0.0 255.0.0.0",
                  "dstport": "eq web",
                 "option": "log"}
    """
    space = r"(?: )"
    text = r"\S+"
    octets = r"\d+\.\d+\.\d+\.\d+"
    addr = "|".join([
        "any",  # "any"
        f"host {octets}",  # "host A.B.C.D"
        f"(?:object-group|addrgroup) {text}",  # ios: "object-group NAME", cnx: "addrgroup NAME"
        octets + r"/\d+",  # "A.B.C.D/LEN"
        f"{octets} {octets}",  # "A.B.C.D A.B.C.D"
    ])

    re_sequence = r"(\d+)?"
    re_action = f"{space}?(permit|deny)"
    re_proto = f"({space}{text})?"
    re_srcaddr = f"{space}({addr})"
    re_srcport = "( .+)?"
    re_dstaddr = f"{space}({addr})"
    re_dstport = "( .+)?"

    regex = f"^{re_sequence}{re_action}{re_proto}{re_srcaddr}{re_srcport}{re_dstaddr}{re_dstport}"
    items_ = re_find_t(regex, line)
    if not items_:
        raise ValueError(f"invalid {line=}")
    items = [s.strip() for s in items_]
    dstport_option = items[-1]
    result: DStr = _parse_dstport_option(dstport_option)
    data = dict(
        sequence=items[0],
        action=items[1],
        protocol=items[2],
        srcaddr=items[3],
        srcport=items[4],
        dstaddr=items[5],
        dstport=result["dstport"],
        option=result["option"],
    )
    return data


def _parse_dstport_option(line: str) -> DStr:
    """Parse destination-ports and options from last part of ACE line.
    Example:
        :param line: "eq bgp www ack log"
        :return: {"dstport": "eq bgp www", "option": "ack log"}
    """
    dstports: LStr = []  # return
    options: LStr = []  # return
    if items := line.split():
        operator = items[0]
        if operator in OPERATORS:
            dstports.append(operator)
            items = items[1:]
            for id_, item in enumerate(items):
                if item in PORTS or item.isdigit():
                    dstports.append(item)
                    continue
                options = items[id_:]
                break
        else:
            options.extend(items)

    invalid_options: LStr = []
    for item in options:
        if item in OPERATORS or item in PORTS or item.isdigit():
            invalid_options.append(item)
    if invalid_options:
        raise ValueError(f"{invalid_options=} in {line=}")

    result = dict(dstport=" ".join(dstports), option=" ".join(options))
    return result


def parse_action(line: str) -> DStr:
    """Parse action from ACE line.

    Example1:
        line: "10 remark text"
        return: "remark"

    Example2:
        line: "permit ip any any"
        return: "permit"
    """
    space = r"(?: )"
    actions = "|".join(ACTIONS)

    re_sequence = r"(\d+)?"
    re_action = f"{space}?({actions})"
    re_text = r"( .+)"
    regex = f"^{re_sequence}{re_action}{re_text}"
    items_ = re_find_t(regex, line)
    if not items_:
        raise ValueError(f"invalid {line=}")
    items = [s.strip() for s in items_]
    data = dict(
        sequence=items[0],
        action=items[1],
        text=items[2],
    )
    return data


# =============================== bool ===============================

def is_valid_wildcard(wildcard: str) -> bool:
    """True if wildcard is ready for prefix.
    Example1:
        :wildcard: "0.0.0.3"
        :return: True

    Example2:
        :wildcard: "0.0.3.3"
        :return: False
    """
    wildcard = wildcard.split()[-1]
    items = wildcard.split(".")
    if len(items) != 4:
        raise ValueError(f"invalid {wildcard}, expected 4 octets")
    octets = [int(s) for s in items]
    int_ = sum([octets[0] * 256 ** 3,
                octets[1] * 256 ** 2,
                octets[2] * 256,
                octets[3]])
    if not int_:
        return True
    str_ = "{0:b}".format(int_)
    bits = set(str_)
    if "0" in bits:
        return False
    return True


# ============================ ip address ============================

def check_subnet(subnet: str) -> bool:
    """True if subnet has format A.B.C.D A.B.C.D, else raise ERROR"""
    octets = r"\d+\.\d+\.\d+\.\d+"
    regex = f"{octets} {octets}$"
    if not re.match(regex, subnet):
        raise ValueError(f"{subnet=} expected A.B.C.D A.B.C.D")
    return True


def invert_mask(subnet: str) -> str:
    """Invert mask to wildcard and vice versa. Example:
    :param subnet: "10.0.0.0 0.0.0.3"
    :return: "10.0.0.0 0.0.0.252"
    """
    net, mask = subnet.split(" ")[:2]
    inverted = ".".join([str(255 - int(s)) for s in mask.split(".")])
    return f"{net} {inverted}"


def make_wildcard(prefix: str) -> str:
    """Convert prefix to wildcard. Ready for ACL.
    :param prefix: prefix A.B.C.D/E
    :return:  ACE line with inverted mask.

    Example1:
        prefix: "10.0.0.0/30"
        return: "10.0.0.0 0.0.0.3"

    Example2:
        prefix: "10.0.0.1/32"
        return: "host 10.0.0.1"

    Example3:
        prefix: "0.0.0.0/0"
        return: "any"

    Example4:
        prefix: "NAME"
        return: "object-group NAME"
    """
    if not isinstance(prefix, str):
        raise TypeError(f"port {prefix=} {str} expected")

    # "any"
    if prefix == "0.0.0.0/0":
        return "any"

    # "host 1.1.1.1"
    if re.match(r"\d+\.\d+\.\d+\.\d+$", prefix):
        prefix = f"{prefix}/32"

    # "1.1.1.0 0.0.0.255"
    if re.match(r"\d+\.\d+\.\d+\.\d+/\d+$", prefix):
        ipnet = IPNetwork(prefix)
        if ipnet.prefixlen == 32:
            return f"host {ipnet.ip}"
        subnet = f"{ipnet.ip} {ipnet.netmask}"
        inverted = invert_mask(subnet=subnet)
        return inverted

    # "object-group NAME"
    if re.match(r"\S+$", prefix):
        return f"object-group {prefix}"

    raise ValueError(f"invalid {prefix=}")


# ============================== ports ===============================

class PortRange(NamedTuple):
    """helper, tcp/udp ports range"""
    string: str
    range: range
    min: int
    max: int


def ports_to_string(items: LInt) -> str:
    """Convert list of ports to string.
    Example:
        :param items: [1,3,4,5]
        :return: "1,3-5"
    """
    if not items:
        return ""
    # if self.operator in ["eq", "neq"]:
    #     return ",".join([str(i) for i in items])

    items = sorted(items)
    ranges: LStr = []  # return
    item_1st: OInt = None
    for idx, item in enumerate(items, start=1):
        # not last iteration
        if idx < len(items):
            item_next = items[idx]
            if item_next - item <= 1:  # range
                if item_1st is None:  # start new range
                    item_1st = item
            else:  # int or end of range
                ranges.append(str(item) if item_1st is None else f"{item_1st}-{item}")
                item_1st = None
        # last iteration
        else:
            item_ = str(item) if item_1st is None else f"{item_1st}-{item}"
            ranges.append(item_)
    return ",".join(ranges)


def string_to_ports(ports: str) -> LInt:
    """Convert string to list of ports
    Example:
        :param ports: "1,3-5"
        :return: [1, 3, 4, 5]
    """
    values = [s for s in ports.split(",") if s]
    ints: SInt = {int(s) for s in values if re.match(r"\d+$", s)}
    ranges = {s for s in values if re.match(r"\d+-\d+$", s)}
    ranges_t = _port_range_min_max(ranges)
    ports_calc = {i for o in ranges_t for i in o.range}  # ports in all ranges
    ports_calc.update(ints)
    ports_ = [i for i in ports_calc if 1 <= i <= 65535]
    return ports_


def _port_range_min_max(ranges) -> List[PortRange]:
    """Return named tuple of range_sting, range_int, port_min, port_max"""
    ranges_tup = []
    for range_string in ranges:
        port_min, port_max = map(int, range_string.split("-"))
        range_int = range(port_min, port_max + 1)
        ranges_tup.append(PortRange(range_string, range_int, port_min, port_max))
    ranges_tup = sorted(ranges_tup, key=lambda o: o.min)
    return ranges_tup
