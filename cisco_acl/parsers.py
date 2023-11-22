"""Parsing helpers."""

from cisco_acl import helpers as h
from cisco_acl.port_name import all_known_names
from cisco_acl.types_ import DStr, LStr


def parse_ace_extended(line: str) -> DStr:
    """Parse extended ACE line to the dictionary.

    :param line: ACE string.
    :return: ACE dict.

    :example:
    parse_ace_extended("10 permit tcp host 1.1.1.1 eq 1025 10.0.0.0 255.0.0.0 eq web log") -> {
        "sequence": "10",
        "action": "permit",
        "protocol": "tcp",
        "srcaddr": "host 1.1.1.1",
        "srcport": "eq 1025",
        "dstaddr": "10.0.0.0 255.0.0.0",
        "dstport": "eq web",
        "option": "log",
     }
    """
    space = r"(?: )"
    text = r"\S+"
    addr = "|".join([
        "any",  # "any"
        f"host {h.OCTETS}",  # "host A.B.C.D"
        f"(?:object-group|addrgroup) {text}",  # ios: "object-group NAME", nxos: "addrgroup NAME"
        h.OCTETS + r"/\d+",  # "A.B.C.D/LEN"
        f"{h.OCTETS} {h.OCTETS}",  # "A.B.C.D A.B.C.D"
    ])

    re_sequence = r"(\d+)?"
    re_action = f"{space}?(permit|deny)"
    re_proto = f"({space}{text})?"
    re_srcaddr = f"{space}({addr})"
    re_srcport = "( .+)?"
    re_dstaddr = f"{space}({addr})"
    re_dstport = "( .+)?"

    regex = f"^{re_sequence}{re_action}{re_proto}{re_srcaddr}{re_srcport}{re_dstaddr}{re_dstport}"
    _items = h.re_find_t(regex, line)
    if not _items:
        return {}

    items = [s.strip() for s in _items]
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


def parse_ace_standard(line: str) -> DStr:
    """Parse standard ACE line to the dictionary.

    :param line: ACE string.
    :return: ACE dict.

    :example:
        line: "10 permit host 1.1.1.1 log"
        return: {"sequence": "10",
                 "action": "permit",
                 "protocol": "ip",
                 "srcaddr": "host 1.1.1.1",
                 "srcport": "",
                 "dstaddr": "any",
                 "dstport": "",
                 "option": "log"}
    """
    space = r"(?: )"
    text = r"\S+"
    addr = "|".join([
        "any",  # "any"
        f"host {h.OCTETS}",  # "host A.B.C.D"
        f"(?:object-group|addrgroup) {text}",  # ios: "object-group NAME", nxos: "addrgroup NAME"
        h.OCTETS + r"/\d+",  # "A.B.C.D/LEN"
        f"{h.OCTETS} {h.OCTETS}",  # "A.B.C.D A.B.C.D"
    ])

    re_sequence = r"(\d+)?"
    re_action = f"{space}?(permit|deny)"
    re_srcaddr = f"{space}({addr})"
    re_log = "( .+)?"

    regex = f"^{re_sequence}{re_action}{re_srcaddr}{re_log}"
    _items = h.re_find_t(regex, line)
    if not _items:
        return {}

    items = [s.strip() for s in _items]
    data = dict(
        sequence=items[0],
        action=items[1],
        protocol="ip",
        srcaddr=items[2],
        srcport="",
        dstaddr="any",
        dstport="",
        option=items[3],
    )
    return data


def _parse_dstport_option(line: str) -> DStr:
    """Split destination-ports and options based on end of ACE line.

    :param line: ACE string.
    :return: ACE dict.
    :example:
        line: "eq bgp www ack log"
        return: {"dstport": "eq bgp www", "option": "ack log"}
    """
    dstports: LStr = []  # result
    options: LStr = []  # result
    known_names = all_known_names()

    if items := line.split():
        operator = items[0]
        if operator in h.OPERATORS:
            dstports.append(operator)
            items = items[1:]
            for id_, item in enumerate(items):
                if item.isdigit() or item in known_names:
                    dstports.append(item)
                    continue
                options = items[id_:]
                break
        else:
            options.extend(items)
    return dict(dstport=" ".join(dstports), option=" ".join(options))


def parse_action(line: str) -> DStr:
    """Parse action from ACE line.

    :example:
        line: "10 remark TEXT"
        return: {"sequence": "10", "action": "remark", "text": "TEXT"}

    :example:
        line: "permit ip any any"
        return: "permit"
    """
    space = r"(?: )"
    actions = "|".join(h.ACTIONS)

    re_sequence = r"(\d+)?"
    re_action = f"{space}?({actions})"
    re_text = r"( .+)"
    regex = f"^{re_sequence}{re_action}{re_text}"
    _items = h.re_find_t(regex, line)
    if not _items:
        raise ValueError(f"invalid {line=}")
    items = [s.strip() for s in _items]
    data = dict(
        sequence=items[0],
        action=items[1],
        text=items[2],
    )
    return data


def parse_address(line: str) -> DStr:
    """Parse address item from address group.

    :example:
        line: "10 host 10.0.0.1"
        return: {"sequence": 10, "address": "host 10.0.0.1"}
    """
    re_sequence = r"(\d+\s+)?"
    re_address = "(.+)"
    regex = f"^{re_sequence}{re_address}"
    _items = h.re_find_t(regex, line)
    if not _items:
        raise ValueError(f"invalid {line=}")
    items = [s.strip() for s in _items]
    data = dict(
        sequence=items[0],
        address=items[1],
    )
    return data
