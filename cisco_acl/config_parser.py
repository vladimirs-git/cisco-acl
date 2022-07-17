"""CISCO config parser"""

import re
from abc import ABC
from copy import deepcopy

from cisco_acl.types_ import DAny, DLStr, DStr, LDAny, LStr, LDStr


class ConfigParser(ABC):
    """CISCO config parser"""

    def __init__(self, **kwargs):
        """CISCO config parser
        :param platform: Platform: "ios", "nxos"
        :param version: Software version (not implemented, planned for compatability)
        """
        self.platform: str = kwargs.get("platform") or "ios"
        self.version: str = kwargs.get("version") or ""
        self.config: str = kwargs.get("config") or ""

        self.dic_text: DStr = {}  # config in *dict* format, commands as *str*
        self.mdic_text: DAny = {}  # config in multidimensional *dict* format, commands as *str*

    def parse_config(self) -> None:
        """Parses all data. Gets data structure described in class"""
        self._parse_rows()

    def acls(self) -> LDAny:
        """Parses ACLs from config
        :return: Parsed ACLs

        :example:
            self.config: "ip access-list ACL_NAME
                            10 remark ACE_NAME_1
                            20 permit icmp any any
                            30 remark ACE_NAME_2
                            40 deny ip any any
                          interface Ethernet1/1/1
                            ip access-group ACL_NAME in
                          "
            return: [{"acl_name": "ACL_NAME",
                      "aces": "10 remark ACE_NAME_1
                               20 permit icmp any any
                               30 remark ACE_NAME_2
                               40 deny ip any any",
                      "input": ["interface Ethernet1/1/1"],
                      "output": []}]
        """
        result: LDAny = []
        acls_d: DStr = self._extended_acls()
        for name, acl_s in acls_d.items():
            acl_d: DAny = dict(name=name, line=acl_s, input=[], output=[])
            result.append(acl_d)
        self._add_acl_interfaces(result)
        return result

    def acls_by_remark(self) -> LDAny:
        """Parses ACLs from config. ACEs grouped by remarks
        :return: Parsed ACLs

        :example:
            self.config: "ip access-list ACL_NAME
                            10 remark ACE_NAME_1
                            20 permit icmp any any
                            30 remark ACE_NAME_2
                            40 deny ip any any
                          interface Ethernet1/1/1
                            ip access-group ACL_NAME in
                          "
            return: [{"acl_name": "ACL_NAME",
                      "ace_group": [{"note": "ACE_NAME_1",
                                     "line": "10 remark ACE_NAME_1\n20 permit icmp any any"},
                                    {"note": "ACE_NAME_2",
                                     "line": "30 remark ACE_NAME_2\40 deny ip any any"}],
                      "input": ["interface Ethernet1/1/1"],
                      "output": []}]
        """
        result: LDAny = []
        acls: DStr = self._extended_acls_d()
        for name, acl_cfg in acls.items():
            ace_group: LDStr = self._make_ace_group(acl=acl_cfg)
            acl_d: DAny = dict(name=name, ace_group=ace_group, input=[], output=[])
            result.append(acl_d)
        self._add_acl_interfaces(result)
        return result

    # ========================== parse rows ==========================

    def _parse_rows(self) -> None:
        """Parses config rows to specific format: list, dict, multidimensional dict
        # make rows, main_rows, dic, mdic, etc.
        self.dic_text - config in *dict* format, commands as *str*
        self.mdic_text - config in multidimensional *dict* format, commands as *str*
        """
        config_l = [i for i in self.config.splitlines() if not re.match(r"!|$", i.strip())]
        for line in config_l:
            while True:
                if re.match(r"\s", line):
                    break
                break
        dic = self._parse_dic(config_l)
        mdic = self._parse_mdic(config_l)
        self.dic_text = {k: "\n".join(v) for k, v in dic.items()}
        self.mdic_text = self._join_mdic_text(mdic)

    @staticmethod
    def _parse_dic(config_l: LStr) -> DLStr:
        """Config in dictionary format (indented strings in dictionary)
        :example:
            data = {"interface Ethernet1/1": ["ip address 1.1.1.1/24",
                                              "no shutdown",
                                              "hsrp 5",
                                              "ip 1.1.1.2"]}
        """
        data: DLStr = {}
        key = ""
        for line in config_l:
            # not indented lines (main config) used as dictionary keys
            if re.match(r"\S", line):
                if re.match("interface .+", key) and not data.get(key):
                    data[key] = []  # empty dict for interface without settings
                key = line.strip()
            # indented lines used as dictionary values
            elif re.match(r"\s", line):
                # save line as dictionary value | init
                line_ = line.strip()
                data[key] = data[key] + [line_] if data.get(key) else [line_]
        return data

    def _parse_mdic(self, config_l: LStr) -> DAny:
        """Parses config in multidimensional dict format
        :example:
            data = {"interface Ethernet1/1": {"_config_": ["ip address 1.1.1.1/24",
                                                           "no shutdown"],
                                              "hsrp 5" : {"_config_": ["ip 1.1.1.2"]}}
                   }
        """
        data: DAny = {"_config_": []}  # return
        # validation
        if not config_l:  # exit if config is empty
            return data
        if re.match(r"\s", config_l[0]):  # error if first line is incorrect
            raise ValueError("first line in config should not be indented")
        config_l.append("END_OF_CONFIG")  # add last line, to detect end of config

        # Foreach config, indented lines add to dictionary as value.
        # More indented line add to more embedded dictionary (dictionary of dictionary)
        i_max = len(config_l)
        i_next = 0
        indent_i = ""  # no indentation
        for i in range(i_max):
            # last line, END_OF_CONFIG
            if i_max - i <= 1:
                break
            # skip already processed lines
            if i_next and i <= i_next:
                continue

            indent_next = re.sub(r"(^\s*).*", r"\1", config_l[i + 1])  # indentation in next line
            line_i = config_l[i]

            # not indented lines, main config
            if indent_i == indent_next:
                data["_config_"].append(line_i.strip())  # add not indented line to config section

            # next line is indented, make more deep indentation parsing
            elif indent_i < indent_next:
                # indented config parser
                (i_next, indent_next, mdic) = self._get_indented_dic(i, config_l)
                data.update(mdic)  # save

        # Interface can be without indented configuration, but should be in "mdic" as key
        for line in config_l:
            # Skip not Interface lines
            if not re.match("interface .+", line, re.I):
                continue
            line = line.strip()
            # Skip already created keys
            if data.get(line):
                continue
            # make key with empty config
            data.update({line: {"_config_": []}})

        return data

    def _get_indented_dic(self, i, config_l) -> tuple:
        """Config in multidimensional dict format,
        multi indented strings as dictionary in dictionary"""
        # init
        key = config_l[i].strip()
        i += 1
        i_next = 0
        data: DLStr = {"_config_": []}
        indent_i = re.sub(r"(^\s*)(.*)", r"\1", config_l[i])  # indentation in first line
        indent_next = ""

        # Foreach config, indented lines add to dictionary as value.
        # More indented line add to more embedded dictionary (dictionary of dictionary)
        i_max = len(config_l)

        # pylint: disable=redefined-argument-from-local
        for i in range(i, i_max):
            # skip already processed lines
            if i_next and i <= i_next:
                continue

            # end of config_l
            if i_max == i + 1:
                break

            # indentation in next line
            indent_next = re.sub(r"(^\s*).*", r"\1", config_l[i + 1])
            line_i = config_l[i]

            # not indented lines, main config
            if indent_i == indent_next:
                data["_config_"].append(line_i.strip())  # add not indented line to config section

            # next line is indented, make more deep indentation parsing
            elif len(indent_i) < len(indent_next):
                # indented config parser
                (i_next, indent_next, mdic) = self._get_indented_dic(i, config_l)
                data.update(mdic)  # save
                if len(indent_i) > len(indent_next):
                    i = i_next
                    break

            # end of indentation
            elif len(indent_i) > len(indent_next):
                data["_config_"].append(line_i.strip())  # add not indented line to config section
                break

        return i, indent_next, {key: data}

    @staticmethod
    def _join_mdic_text(mdic: DAny) -> DAny:
        """Joins self.mdic[key]["_config_"] from List[str] to str"""

        def join_config(mdic_text_: DAny) -> None:
            """join self.mdic[key]["_config_"] from List[str] to str"""
            for key, values in mdic_text_.items():
                if key == "_config_" and isinstance(values, list):
                    mdic_text_[key] = "\n".join(values)
                else:
                    join_config(values)

        mdic_text: DAny = deepcopy(mdic)
        join_config(mdic_text)
        return mdic_text

    # =========================== helpers ============================

    def _add_acl_interfaces(self, acls: LDAny) -> None:
        """Adds input/output interfaces to parsed `acls`
        :result: Side effect `acls`
        """
        intf_acls_all: LDAny = self._acls_on_interfaces()
        for acl_d in acls:
            intf_acls = [d for d in intf_acls_all if d["name"] == acl_d["name"]]
            for intf_acl in intf_acls:
                if intf_acl["input"]:
                    acl_d["input"].append(intf_acl["input"])
                if intf_acl["output"]:
                    acl_d["output"].append(intf_acl["output"])
        for acl_d in acls:
            acl_d["input"] = sorted(set(acl_d["input"]))
            acl_d["output"] = sorted(set(acl_d["output"]))

    def _extended_acls(self) -> DStr:
        """Returns *str* of extended ACLs, skips standard ACLs
        :example:
            self.config: "ip access-list extended ACL_NAME
                            permit ip any any
                          ip access-list standard acl_standard
                            permit ip any any"
            return: ["ip access-list extended ACL_NAME\npermit ip any any"]
        """
        acls: DStr = {}
        pattern = self._extended_acl__pattern()
        for acl_name, acl_cfg in self.dic_text.items():
            if acl_name.startswith(pattern):
                name = acl_name.replace(pattern, "", 1).strip()
                acls[name] = f"{acl_name}\n{acl_cfg}"
        return acls

    def _extended_acls_d(self) -> DStr:
        """Returns *dict* of extended ACLs, skips standard ACLs
        :example:
            self.config: "ip access-list extended ACL_NAME
                            permit ip any any
                          ip access-list standard acl_standard
                            permit ip any any"
            return:
                {"ACL_NAME": "permit ip any any"}
        """
        acls: DStr = {}
        pattern = self._extended_acl__pattern()
        for acl_name, acl_cfg in self.dic_text.items():
            if acl_name.startswith(pattern):
                name = acl_name.replace(pattern, "", 1).strip()
                acls[name] = acl_cfg
        return acls

    def _extended_acl__pattern(self):
        """Pattern for extended ACL for, platform depended"""
        if self.platform == "nxos":
            return "ip access-list "
        return "ip access-list extended "

    @staticmethod
    def _make_ace_group(acl: str) -> LDStr:
        """Returns ACE groups, grouped by 1st remark, without lines not related to ACE
        :param acl: ACL config (ACEs)
        :return: ACE groups, grouped by 1st remark
        :example:
            acl: "remark ACE_NAME1
                  permit icmp any any
                  remark ACE_NAME2
                  deny ip any any"
            return: [{"note": "ACE_NAME1", "line": "remark ACE_NAME1\npermit icmp any any"},
                     {"note": "ACE_NAME2", "line": "remark ACE_NAME2\ndeny ip any any"}]
        """
        groups: LDStr = []

        skip = ["statistics per-entry"]
        aces_all = [s.strip() for s in acl.split("\n")]
        aces_all = [s for s in aces_all if s]
        aces_all = [s for s in aces_all if s not in skip]
        if not aces_all:
            return []

        note = ""
        ace1 = aces_all[0]

        re_remark = r"(\d+ )?remark "
        if re.match(re_remark, ace1):
            note = re.sub(re_remark, "", ace1)

        lines: LStr = [ace1]
        for idx, line in enumerate(aces_all[1:], start=1):
            # rule
            if not re.match(re_remark, line):
                lines.append(line)
                continue
            # 2nd remark
            line_prev = aces_all[idx - 1]
            if re.match(re_remark, line_prev):
                lines.append(line)
                continue
            # 1st remark
            groups.append(dict(note=note, line="\n".join(lines)))
            note = re.sub(re_remark, "", line)
            lines = [line]
        groups.append(dict(note=note, line="\n".join(lines)))
        return groups

    def _interfaces_w_acl(self) -> DStr:
        """Returns dict of interfaces with access-group, skips interfaces without ACLs
        :example:
            self.config: "interface GigabitEthernet1/1/1
                            ip address 10.0.1.1 255.255.255.0
                            ip access-group ACL_NAME in
                          interface GigabitEthernet1/1/2
                            ip address 10.0.2.1 255.255.255.0"
            return: {"interface GigabitEthernet1/1/1":
                     "ip address 10.0.1.1 255.255.255.0\nip access-group ACL_NAME in"}
        """
        return {k: s for k, s in self.dic_text.items() if re.search("ip access-group", s, re.M)}

    def _acls_on_interfaces(self) -> LDAny:
        """Returns data of ACLs applied to the interfaces
        :example:
            self.config: "interface GigabitEthernet1/1/1
                            ip address 10.0.2.1 255.255.255.0
                            ip access-group ACL_NAME in"
            return: [{"acl": "ACL_NAME",
                      "input": "interface GigabitEthernet1/1/1",
                      "output": ""}]
        """
        access_groups: LDAny = []
        intfs_cfg: DStr = self._interfaces_w_acl()
        for intf_name, intf_cfg in intfs_cfg.items():
            if not intf_name.startswith("interface "):
                raise ValueError("invalid interface")
            if access_group := re.findall(r"ip access-group (\S+) (\S+)", intf_cfg):
                if len(access_group) != 1:
                    raise ValueError("invalid count of access-groups")
                acl_name, direction = access_group[0]
                if not acl_name:
                    raise ValueError("absent access-group")
                if direction not in ["in", "out"]:
                    raise ValueError("invalid access-group direction")
                data: DAny = dict(
                    name=acl_name,
                    input=intf_name if direction == "in" else "",
                    output=intf_name if direction == "out" else "",
                )
                access_groups.append(data)
        return access_groups
