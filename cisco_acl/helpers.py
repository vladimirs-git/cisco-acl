"""ACE helper functions"""

import re
from typing import Any

from netaddr import IPNetwork  # type: ignore

from cisco_acl.static_ import ACTIONS, OPERATORS, PORTS
from cisco_acl.types_ import DStr, LStr, StrInt


# =============================== str ================================

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
    idx = int(line)
    if idx < 0:
        raise ValueError(f"invalid {idx=}, positive expected")
    return idx


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
        :return: {"idx": 10,
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

    re_idx = r"(\d+)?"
    re_action = f"{space}?(permit|deny)"
    re_proto = f"({space}{text})?"
    re_srcaddr = f"{space}({addr})"
    re_srcport = "( .+)?"
    re_dstaddr = f"{space}({addr})"
    re_dstport = "( .+)?"

    regex = f"^{re_idx}{re_action}{re_proto}{re_srcaddr}{re_srcport}{re_dstaddr}{re_dstport}"
    items_ = re_find_t(regex, line)
    if not items_:
        raise ValueError(f"invalid {line=}")
    items = [s.strip() for s in items_]
    dstport_option = items[-1]
    result: DStr = _parse_dstport_option(dstport_option)
    data = dict(
        idx=items[0],
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

    re_idx = r"(\d+)?"
    re_action = f"{space}?({actions})"
    re_text = r"( .+)"
    regex = f"^{re_idx}{re_action}{re_text}"
    items_ = re_find_t(regex, line)
    if not items_:
        raise ValueError(f"invalid {line=}")
    items = [s.strip() for s in items_]
    data = dict(
        idx=items[0],
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


def invert_mask(subnet: str) -> str:
    """Invert mask to wildcard and vice versa. Example:
    :param subnet: "10.0.0.0 0.0.0.3"
    :return: "10.0.0.0 0.0.0.252"
    """
    net, mask = subnet.split(" ")[:2]
    inverted = ".".join([str(255 - int(s)) for s in mask.split(".")])
    return f"{net} {inverted}"
