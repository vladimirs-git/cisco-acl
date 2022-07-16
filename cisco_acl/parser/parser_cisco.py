"""CISCO config parser"""

import re
from abc import ABC
from copy import deepcopy

from cisco_acl.types_ import DAny, DLStr, DStr, LDAny, LStr


class ParserCISCO(ABC):
    """CISCO config parser"""

    def __init__(self, **kwargs):
        self.config = str(kwargs.get("config") or "")
        self.platform = str(kwargs.get("platform") or "ios")
        self.dic_text: DStr = {}  # Config in dict format, commands as string
        self.mdic_text: DAny = {}  # Config in multidimensional dictionary, commands as string

    def parse_config(self) -> None:
        """Parse all data. Get data structure described in Class"""
        self._parse_rows()  # make rows, main_rows, dic, mdic, etc.

    # ========================== parse rows ==========================

    def _parse_rows(self) -> None:
        """CISCO. Parsing config rows to specific format: list, dic, mdic."""
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
        Example:
            data = {
                "interface Ethernet1/1": ["ip address 1.1.1.1/24",
                                          "no shutdown",
                                          "hsrp 5",
                                          "ip 1.1.1.2"]
            }
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
        """Parsing config in multidimensional dictionary format.
        Example:
            data = {
            "interface Ethernet1/1": {
                "_config_": ["ip address 1.1.1.1/24", "no shutdown"],
                "hsrp 5" : {
                    "_config_": ["ip 1.1.1.2"]
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
        """Config in multidimensional dictionary format,
        multi indented strings as dictionary in dictionary """
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
        """join self.mdic[key]["_config_"] from List[str] to str"""

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

    def _acls_extended(self) -> DStr:
        """Return dict of extended ACLs (skip standard ACLs).
        Example:
        self.config: "ip access-list extended acl_extended
                        permit ip any any
                      ip access-list standard acl_standard
                        permit any"
        :return:
            {"acl_extended": "permit ip any any"}
        """
        acls: DStr = {}
        pattern = "ip access-list extended "
        for name, acl in self.dic_text.items():
            if name.startswith(pattern):
                name = name.replace(pattern, "", 1).strip()
                acls[name] = acl
        return acls

    def _acls_cnx(self) -> DStr:
        """Return dict of CNX ACLs.
        Example:
        self.config: "ip access-list acl_extended
                        permit ip any any
                      ip access-list acl_standard
                        permit any"
        :return:
            {"acl_extended": "permit ip any any",
            "acl_standard": "permit any"}
        """
        acls: DStr = {}
        pattern = "ip access-list "
        for name, acl in self.dic_text.items():
            if name.startswith(pattern):
                name = name.replace(pattern, "", 1).strip()
                acls[name] = acl
        return acls

    def _interfaces_w_acl(self) -> DStr:
        """Return dict of interfaces with access-group (skip interfaces without ACLs).
        Example:
        self.config: "interface GigabitEthernet0/0/1.2
                        ip address 10.0.2.1 255.255.255.0
                        ip access-group acl_extended in
                      interface GigabitEthernet0/0/1.3
                        ip address 10.0.3.1 255.255.255.0"
        :return: {"interface GigabitEthernet0/0/1.2":
                    "ip address 10.0.2.1 255.255.255.0" \
                    "ip access-group acl_extended in"}
        """
        return {k: s for k, s in self.dic_text.items() if re.search("ip access-group", s, re.M)}

    def _make_acls_on_interfaces(self) -> LDAny:
        """Return/parse access-groups in/out under interfaces.
        Example:
        self.config: "interface GigabitEthernet0/0/1.2
                        ip address 10.0.2.1 255.255.255.0
                        ip access-group acl_extended in"
        :return: [{"acl": "acl_extended",
                   "srcintf": "interface GigabitEthernet0/0/1.2",
                   "dstintf": ""}]
        """
        access_groups: LDAny = []  # return
        intfs_cfg = self._interfaces_w_acl()
        for interface, intf_cfg in intfs_cfg.items():
            if not interface.startswith("interface "):
                raise ValueError("invalid interface")
            if access_group := re.findall(r"ip access-group (\S+) (\S+)", intf_cfg):
                if len(access_group) != 1:
                    raise ValueError("multiple access-groups")
                acl_name, direction = access_group[0]
                if not acl_name:
                    raise ValueError("absent access-group")
                if direction not in ["in", "out"]:
                    raise ValueError("invalid access-group direction")
                data: DAny = dict(
                    acl_name=acl_name,
                    input=interface if direction == "in" else "",
                    output=interface if direction == "out" else "",
                )
                access_groups.append(data)
        return access_groups
