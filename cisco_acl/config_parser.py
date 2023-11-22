"""CISCO config parser."""

import re
from abc import ABC
from copy import deepcopy

from cisco_acl import helpers as h
from cisco_acl.types_ import DAny, DLStr, DStr, LDAny, LStr, OLStr


class ConfigParser(ABC):
    """CISCO config parser."""

    def __init__(self, config: str = "", **kwargs):
        """Init ConfigParser.

        :param config: Cisco config, "show running-config" output.
        :type config: str

        :param platform: Platform: "asa", "ios", "nxos". Default "ios".
        :type platform: str

        :param version: Software version (not implemented, planned for compatability).
        """
        self.config: str = str(config)  # raw config
        self.platform: str = h.init_platform(**kwargs)
        self.version: str = str(kwargs.get("version") or "")

        self.lines: LStr = []  # config in list format
        self.dic: DLStr = {}  # config in dict format, commands as LStr
        self.mdic: DAny = {}  # config in multidimensional dict format, commands as LStr
        self.dic_text: DStr = {}  # config in dict format, commands as string
        self.mdic_text: DAny = {}  # config in multidimensional dict format, commands as string

    def __repr__(self):
        """__repr__."""
        name = self.__class__.__name__
        platform = self.platform
        version = self.version
        return f"<{name}: {platform=} {version=}>"

    # =========================== method =============================

    def addgrs(self) -> LDAny:
        """Parse address groups from config.

        :return: data ready for AddrGroup.

        :example:
            config: "object-group ip address NAME
                       10 host 10.0.0.1
                       20 10.0.0.0/24"
            self.platform: "nxos"
            return: [{"name": "NAME",
                      "items": ["10 host 10.0.0.1", "20 10.0.0.0/24"],
                      "platform": "nxos"}]
        """
        addgrs: LDAny = []
        for objgr_key, objgr_cfg in self.dic_text.items():
            regex = "object-group (network |ip address )?(.+)"
            type_, name = h.findall2(regex, objgr_key)
            if type_ and name:
                items = h.lines_wo_spaces(objgr_cfg)
                addgr_d: DAny = dict(name=name, items=items, platform=self.platform)
                addgrs.append(addgr_d)
        return addgrs

    # noinspection PyShadowingBuiltins,PyIncorrectDocstring
    def acls(self, type: str = "", **kwargs) -> LDAny:  # pylint: disable=redefined-builtin
        """Parse ACLs from config.

        :param type: ACL type: "extended", "standard", "any" (default "any").
        :type type: str

        :param names: Parse only ACLs with specified names.
        :type names: List[str]

        :return: Parsed ACLs.
        :rtype: List[dict]

        :example:
            self.config: "ip access-list ACL_NAME
                            10 remark ACE_NAME1
                            20 permit icmp any any
                            30 remark ACEG_NAME2
                            40 deny ip any any
                          interface Ethernet1/1/1
                            ip access-group ACL_NAME in
                          "
            self.platform: "nxos"
            return: [{"acl_name": "ACL_NAME",
                      "aces": "10 remark ACE_NAME1
                               20 permit icmp any any
                               30 remark ACEG_NAME2
                               40 deny ip any any",
                      "input": ["interface Ethernet1/1/1"],
                      "output": [],
                      "platform": "nxos"}]
        """
        names: OLStr = kwargs.get("names")
        if names is not None:
            names = [str(s) for s in names]

        acls: LDAny = []  # result
        for acl_key, acl_cfg in self.dic_text.items():
            regex = "ip access-list (extended |standard )?(.+)"
            acl_type, name = h.findall2(regex, acl_key)
            if not name:
                continue
            if names is None or name in names:
                acl_type = h.init_type(type=acl_type, platform=self.platform)
                acl_d: DAny = dict(line=f"{acl_key}\n{acl_cfg}",
                                   platform=self.platform,
                                   name=name,
                                   type=acl_type,
                                   input=[],
                                   output=[])
                if not type or type == acl_type:
                    acls.append(acl_d)
        self._add_acl_interfaces(acls)
        return acls

    def pattern__cfg_acl(self) -> str:
        """Pattern for extended ACL, by platform."""
        if self.platform == "nxos":
            return "ip access-list "
        return "ip access-list extended "

    def pattern__object_group(self) -> str:
        """Pattern for object-group, by platform."""
        if self.platform == "nxos":
            return "object-group network "
        return "object-group ip address "

    # ========================= parse_config =========================

    def parse_config(self) -> None:
        """Parse config rows to specific format: list, dict, multidimensional dict.

        # make rows, main_rows, dic, mdic, etc.
        self.dic_text - config in dict format, commands as string,
        self.mdic_text - config in multidimensional dict format, commands as string.
        """
        config_l = [s.rstrip() for s in self.config.splitlines()]
        config_l = [s for s in config_l if s and not s.startswith("!")]
        if config_l:
            config_l[0] = config_l[0].strip()
        self.lines = self._parse_lines(config_l)
        self.dic = self._parse_dic(config_l)
        self.mdic = self._parse_mdic(config_l)
        self.dic_text = {k: "\n".join(v) for k, v in self.dic.items()}
        self.mdic_text = self._join_mdic_text(self.mdic)

    @staticmethod
    def _parse_lines(config_l: LStr) -> LStr:
        """Return command lines without indentation."""
        lines = [s.strip() for s in config_l]
        lines = [s for s in lines if s]
        return lines

    @staticmethod
    def _join_mdic_text(mdic: DAny) -> DAny:
        """Join self.mdic[key]["_config_"] from List[str] to str."""

        def join_config(mdic_text_: DAny) -> None:
            """Join self.mdic[key]["_config_"] from List[str] to str."""
            for key, values in mdic_text_.items():
                if key == "_config_" and isinstance(values, list):
                    mdic_text_[key] = "\n".join(values)
                else:
                    join_config(values)

        mdic_text: DAny = deepcopy(mdic)
        join_config(mdic_text)
        return mdic_text

    @staticmethod
    def _parse_dic(config_l: LStr) -> DLStr:
        """Config in dictionary format (indented strings in dictionary).

        :example:
            data: {"interface Ethernet1/1": ["ip address 1.1.1.1/24",
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
        """Parse config in multidimensional dict format.

        :example:
            data: {"interface Ethernet1/1": {"_config_": ["ip address 1.1.1.1/24",
                                                           "no shutdown"],
                                              "hsrp 5" : {"_config_": ["ip 1.1.1.2"]}}
                   }
        """
        data: DAny = {"_config_": []}  # result
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

    # =========================== helper =============================

    def _add_acl_interfaces(self, acls: LDAny) -> None:
        """Add input/output interfaces to parsed `acls`.

        :result: Side effect `acls`.
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

    def _acls_on_interfaces(self) -> LDAny:
        """Return data of ACLs applied to the interfaces.

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
            if access_group_t := re.findall(r"ip access-group (\S+) (\S+)", intf_cfg):
                acl_name = access_group_t[0][0]
                data: DAny = dict(name=acl_name, input="", output="")
                for acl_name, direction in access_group_t:
                    if not acl_name:
                        raise ValueError(f"absent access-group {acl_name=}")
                    if direction not in ["in", "out"]:
                        raise ValueError(f"invalid access-group {direction=}")
                    if direction == "in":
                        data.update(dict(input=intf_name))
                    elif direction == "out":
                        data.update(dict(output=intf_name))
                access_groups.append(data)
        return access_groups

    def _get_indented_dic(self, i, config_l) -> tuple:
        """Config in multidimensional dict format.

        Multi indented strings as dictionary in dictionary.
        """
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

    def _interfaces_w_acl(self) -> DStr:
        r"""Return dict of interfaces with access-group, skip interfaces without ACLs.

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
