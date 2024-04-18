"""ACE helper functions."""

import logging
import re
from functools import wraps
from ipaddress import IPv4Network
from string import ascii_letters, digits, punctuation
from time import time
from typing import Any, List, NamedTuple

from netports import SwVersion

from cisco_acl.types_ import LStr, StrInt, LInt, OInt, SInt, T2Str, T3Str, DInt, SStr, LIpNet

IOS = "ios"
MAX_LINE_LENGTH = 100
SEQUENCE_MAX = 4294967295
PLATFORMS = ("asa", "ios", "nxos")
ACTIONS = ("remark", "permit", "deny")
OPERATORS = ("eq", "gt", "lt", "neq", "range")

DEF_INDENT = "  "
OCTETS = r"\d+\.\d+\.\d+\.\d+"


# =============================== str ================================


def acl_help_to_name_port(output: str) -> DInt:
    """Transform `output` of ACL help to the dictionary where key is name, value is port.

    :param output: ACL help.
    :return: names and ports.
    :example:
        output: "bgp          Border Gateway Protocol (179)"
        return: {"bgp": 179}
    """
    data: DInt = {}
    lines = [s.strip().replace("(", " ") for s in output.split("\n")]
    for line in lines:
        name, port = findall2(r"(\S+).+\s(\d+)\)$", line)
        if name and port:
            data[name] = int(port)
    return data


def findall1(pattern: str, string: str, flags=0) -> str:
    """Parse 1st item of re.findall(). If nothing is found, returns an empty string.

    Group with parentheses in pattern is required.
    :return: Interested substring.
    :example:
        pattern: "a(b)cde"
        string: "abcde"
        return: "b"
    """
    result = (re.findall(pattern=pattern, string=string, flags=flags) or [""])[0]
    if isinstance(result, str):
        return result
    if isinstance(result, tuple):
        return result[0]
    return ""


def findall2(pattern: str, string: str, flags=0) -> T2Str:
    """Parse 2 items of re.findall(). If nothing is found, returns 2 empty strings.

    Group with parentheses in pattern is required.
    :return: Two interested substrings.
    :example:
        pattern: "a(b)(c)de"
        string: "abcde"
        return: "b", "c"
    """
    result = (re.findall(pattern=pattern, string=string, flags=flags) or [("", "")])[0]
    if isinstance(result, tuple) and len(result) >= 2:
        return result[0], result[1]
    return "", ""


def findall3(pattern: str, string: str, flags=0) -> T3Str:
    """Parse 3 items of re.findall(). If nothing is found, returns 3 empty strings.

    Group with parentheses in pattern is required.
    :return: Three interested substrings.
    :example:
        pattern: "a(b)(c)(d)e"
        string: "abcde"
        return: "b", "c", "d"
    """
    result = (re.findall(pattern=pattern, string=string, flags=flags) or [("", "", "")])[0]
    if isinstance(result, tuple) and len(result) >= 3:
        return result[0], result[1], result[2]
    return "", "", ""


def check_line_length(line: str) -> bool:
    """Return True if line length <= 100 chars, else raise ERROR."""
    length = len(line)
    expected = MAX_LINE_LENGTH
    if length > expected:
        raise ValueError(f"invalid {line=} {length=}, {expected=}")
    return True


def check_name(name: str) -> bool:
    """Check name.

    :return: True  - if first char is ascii_letters,
             False - chars can be punctuation, else raise ERROR.
    """
    if not name:
        raise ValueError(f"absent {name=}")
    skip_chas = {"?"}
    valid_chars: SStr = set(ascii_letters + digits + punctuation).difference(skip_chas)
    if invalid_chars := list(set(name).difference(valid_chars)):
        raise ValueError(f"{invalid_chars=} in {name=}")
    return True


def init_ace_action(action: str = "permit") -> str:
    """Init ACE action: "permit", "deny"."""
    action = str(action)
    expected = ["permit", "deny"]
    if action not in expected:
        raise ValueError(f"invalid {action=}, {expected=}")
    return action


def init_indent(**kwargs) -> str:
    """Init ACE lines indentation (default "  ")."""
    indent = kwargs.get("indent")
    if indent is None:
        indent = DEF_INDENT
    if not isinstance(indent, str):
        raise TypeError(f"{indent=} {str} expected")
    return indent


def init_line(line: str) -> str:
    """Init line, replace spaces to one space, checks length <= 100 chars."""
    if not isinstance(line, str):
        raise TypeError(f"{line=} {str} expected")
    line = replace_spaces(line)
    return line


def init_name(name: str) -> str:
    """ACL or address group name, without "ip access-list ".

    Requirements:
    - length <= 100 chars.
    - all chars are digits.
    - first char is ascii_letters, other chars are ascii_letters and punctuation.
    """
    if not name:
        name = ""
    if not isinstance(name, str):
        raise TypeError(f"{name=} {str} expected")
    name = name.strip()
    check_line_length(name)
    return name


def init_number(number: StrInt) -> str:
    """Init number, convert int to string."""
    while True:
        if isinstance(number, int):
            if number < 0:
                raise ValueError(f"{number=} positive expected")
            break
        if isinstance(number, str):
            if number.isdigit():
                number = int(number)
                break
            raise ValueError(f"{number=} digit expected")
        raise TypeError(f"{number=} {str} {int} expected")
    return str(number)


# noinspection PyIncorrectDocstring
def init_platform(**kwargs) -> str:
    """Init device platform.

    :param platform: Not checked platform: "cisco_ios", "cisco_nxos", "cnx", "ios", "nxos".
    :return: Valid platform: "ios", "nxos".
    """
    platform = kwargs.get("platform") or ""
    if not platform:
        platform = IOS
    if not isinstance(platform, str):
        raise TypeError(f"{platform=} {str} expected")
    expected = sorted(["cisco_asa", "cisco_ios", "cisco_nxos", "cnx", *PLATFORMS])
    if platform not in expected:
        raise ValueError(f"Invalid {platform=}, {expected=}.")
    if platform in ["cisco_asa", "asa"]:
        return "asa"
    if platform in ["cisco_nxos", "cnx", "nxos"]:
        return "nxos"
    return IOS


# noinspection PyIncorrectDocstring
def init_protocol(line: str, **kwargs) -> str:
    """Init protocol, converts tcp, udp numbers to name.

    :param line: Protocol line. Example "eq www".
    :param protocol: Protocol name or number. Example: "tcp".
    """
    if line:
        protocol = str(kwargs.get("protocol") or "")
        if protocol == "6":
            protocol = "tcp"
        if protocol == "17":
            protocol = "udp"
        expected = ["", "tcp", "udp"]
        if protocol in expected:
            return protocol
    return ""


def init_remark_text(text: str) -> str:
    """Init Remark.text.

    :param text: text for remark.
    """
    if not isinstance(text, str):
        raise TypeError(f"{text=} {str} expected")
    text = text.strip()
    if not text:
        raise ValueError(f"{text=} value required")
    return text


# noinspection PyIncorrectDocstring
def init_type(**kwargs) -> str:
    """Init ACL type: "extended", "standard".

    :param platform: Platform: "asa", "ios", "nxos". Default "ios".
    :param type: Not checked ACL type: "extended", "standard", "ip access-list extended", etc.
    """
    platform = init_platform(**kwargs)
    _type = str(kwargs.get("type") or "").strip()
    if _type.startswith("ip access-list extended "):
        _type = "extended"
    if _type.startswith("ip access-list standard "):
        _type = "standard"
    if _type not in ["extended", "standard"]:
        _type = "standard"
        if platform == "nxos":
            _type = "extended"
    if platform == "nxos" and _type == "standard":
        expected = "extended"
        raise ValueError(f"invalid type={_type!r}, {expected=}")
    return _type


# noinspection PyIncorrectDocstring
def init_version(**kwargs) -> SwVersion:
    """Init version.

    Convert software version string to SwVersion object.
    :param version: software version string.
    :return: SwVersion object.
    """
    version = str(kwargs.get("version") or "")
    if not version:
        version = "0"
    return SwVersion(version)


def int_to_str(line: StrInt) -> str:
    """Init line, int or string convert to string, replace spaces."""
    if isinstance(line, int):
        if line < 0:
            raise ValueError(f"{line=} positive expected")
        line = str(line)
    if not isinstance(line, str):
        raise TypeError(f"{line=} {str} expected")
    line = replace_spaces(line)
    return line


def is_line_for_acl(line: str) -> bool:
    """Return True if line ready for ACL.

    If Starts with "allow", "deny", "remark" startswith` + `split` faster than `re`.
    """
    if line.startswith("permit "):
        return True
    if line.startswith("remark "):
        return True
    if line.startswith("deny "):
        return True

    digit, *items = line.split(" ", 1)
    if digit.isdigit() and items:
        return is_line_for_acl(items[0])
    return False


def lines_wo_spaces(line: str) -> LStr:
    r"""Split line by newline, replaces multiple white spaces with single space.

    :line: Text joined by "\n".
    :return: Lines with single spaces and split by "\n".
    :example:
        line: "  10 deny icmp any any  \n  20 permit ip any any  "
        return: ["10 deny icmp any any", "20 permit ip any any"]
    """
    if not isinstance(line, str):
        raise TypeError(f"{line=} {str} expected")
    lines = [replace_spaces(s) for s in line.split("\n")]
    return [s for s in lines if s]


def parse_remark_name(text: str, group_by: str) -> str:
    """Parse Rule name from Remark.text.

    :param text: Remark.text.
    :param group_by: Acl.group_by.
    :return: Rule name.
    :example:
        self.group_by = "= "
        parse_aceg_name("= C-1, text", "= ") -> "C-1"
    """
    name = text.split(",")[0]
    name = name.strip().replace(group_by, "")
    return name


def re_find_t(regex: str, line: str) -> tuple:
    """Find interested tuple.

    :param regex: Regex pattern, should contain groups.
    :param line: String body.
    :return: Tuple with interested values or empty tuple.
    """
    return (re.findall(regex, line) or [tuple()])[0]


def replace_spaces(line: str) -> str:
    """Replace multiple white spaces with single space."""
    return " ".join(line.split())


# =============================== int ================================


def init_int(line: StrInt) -> int:
    """Convert string to positive int."""
    if not isinstance(line, (int, str)):
        raise TypeError(f"{line=} {int} or {str} expected")
    if isinstance(line, str):
        line = line.strip()
        line = line.split()[0] if line else "0"
        if not line.isdigit():
            raise ValueError(f"{line=}, digit expected")
    line_: int = int(line)
    if line_ < 0:
        raise ValueError(f"{line_=}, positive expected")
    return line_


# =============================== list ===============================


def convert_to_lstr(items: Any) -> LStr:
    """Convert items to List[str].

    If items has other type, raise ERROR.
    """
    if not items:
        items = []
    if isinstance(items, str):
        items = [items]
    items = list(items)
    _items: LStr = []
    for item in items:
        if not isinstance(item, str):
            raise TypeError(f"{item=} {str} expected")
        _items.append(item)
    return _items


# ============================== ipnet ===============================


def prefix_to_ipnet(prefix: str) -> IPv4Network:
    """Convert prefix to ipnet, logging WARNING if invalid prefixlen.

    :param prefix: Prefix "A.B.C.D/LEN".
    :return: ipnet IPv4Network.
    """
    try:
        ipnet = IPv4Network(address=prefix)
    except ValueError as ex:
        if "has host bits set" not in str(ex):
            raise type(ex)(*ex.args)
        ipnet = IPv4Network(address=prefix, strict=False)
        msg = f"ValueError: {ex}, fixed to prefix {ipnet}"
        logging.warning(msg)
    return ipnet


def subnet_of(tops: LIpNet, bottoms: LIpNet) -> bool:
    """Check all IPv4Network  in`bottoms` ara subnets of any IPv4Network in `tops`.

    :param tops: List of IPv4Network in the top.
    :type bottoms: List of IPv4Network in the bottom.
    :return: True - if all `bottoms` atr subnets of `tops`.
    """
    if not (tops and bottoms):
        return False
    for bottom in bottoms:
        for top in tops:
            if bottom.subnet_of(top):
                break
        else:
            return False
    return True


# ============================== ports ===============================


class PortRange(NamedTuple):
    """TCP/UDP ports range."""

    string: str
    range: range
    min: int
    max: int


def ports_to_string(items: LInt) -> str:
    """Convert list of ports to string.

    :example:
        items: [1,3,4,5]
        return: "1,3-5"
    """
    if not items:
        return ""
    # if self.operator in ["eq", "neq"]:
    #     return ",".join([str(i) for i in items])

    items = sorted(items)
    ranges: LStr = []  # result
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
    """Convert string to list of ports.

    :example:
        ports: "1,3-5"
        return: [1, 3, 4, 5]
    """
    values = [s for s in ports.split(",") if s]
    ints: SInt = {int(s) for s in values if s.isdigit()}

    ranges = set()
    for value in values:
        items = value.split("-")
        if len(items) == 2 and items[0].isdigit() and items[1].isdigit():
            ranges.add(value)

    ranges_t = _port_range_min_max(ranges)
    ports_calc = {i for o in ranges_t for i in o.range}  # ports in all ranges
    ports_calc.update(ints)
    ports_ = [i for i in ports_calc if 1 <= i <= 65535]
    return ports_


def _port_range_min_max(ranges) -> List[PortRange]:
    """Return named tuple of range_sting, range_int, port_min, port_max."""
    ranges_tup = []
    for range_string in ranges:
        port_min, port_max = map(int, range_string.split("-"))
        range_int = range(port_min, port_max + 1)
        ranges_tup.append(PortRange(range_string, range_int, port_min, port_max))
    ranges_tup = sorted(ranges_tup, key=lambda o: o.min)
    return ranges_tup


# ============================= wrapper ==============================


def check_start_step_sequence(method):
    """Wrap and check sequence numbers."""

    @wraps(method)
    def _wrapper(ace_o, start: int = 10, step: int = 10, **kwargs) -> int:
        """Check sequence numbers, max/min value for `start` and `step`.

        :param start: Starting sequence number. start=0 - delete all sequence numbers.
        :param step: Step to increment the sequence number.
        :param items: List of Ace objects (default self.items).
        :return: Last sequence number.
        :raises: ValueError if `start` or `step` does not match conditions.
        """
        if not 0 <= start <= SEQUENCE_MAX:
            raise ValueError(f"{start=} expected=0..{SEQUENCE_MAX}")
        if start and step < 1:
            raise ValueError(f"{step=} expected >= 1")
        if not start:
            step = 0

        sequence = method(ace_o, start, step, **kwargs)

        if sequence > SEQUENCE_MAX:
            raise ValueError(f"last {sequence=} expected=1..{SEQUENCE_MAX}")

        return sequence

    return _wrapper


def time_spent(func):
    """Wrap measure function execution time."""

    def wrap(*args, **kwargs):
        """Wrap."""
        started = time()
        _return = func(*args, **kwargs)
        elapsed = time() - started
        print(f"====== {func.__name__}, spent {elapsed:.3f}s ======")
        return _return

    return wrap
