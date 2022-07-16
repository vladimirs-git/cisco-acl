"""IOS config parser"""

from cisco_acl.parser.parser_cisco import ParserCISCO
from cisco_acl.types_ import DDAny, DStr, LDAny, LStr, LDStr, DAny


class ParserIOS(ParserCISCO):
    """IOS config parser"""

    def parse_acls_by_remark(self) -> DDAny:
        """IOS. Parse access-lists from config
        :return: Parsed ACLs
        :example:
        self.config: "ip access-list extended ACL_NAME
                        remark RULE_NAME
                        permit ip any any
                      interface GigabitEthernet0/0/1.2
                        ip access-group ACL_NAME in"

        return: {"ACL_NAME": {
                    "acl_name": "ACL_NAME",
                    "name": "RULE_NAME",
                    "ace": ["remark RULE_NAME", "permit ip any any"],
                    "input": ["interface GigabitEthernet0/0/1.2"],
                    "output": []}
               }
        """
        result: DDAny = {}

        # make ace groups
        acls: DStr = self._acls_extended()
        for acl_name, acl_cfg in acls.items():
            ace_group: LDStr = self._make_ace_group(acl_cfg=acl_cfg)
            acl_d: DAny = dict(acl_name=acl_name, ace_group=ace_group, input=[], output=[])
            result[acl_name] = acl_d

        # add input/output interfaces
        intf_acls_all: LDAny = self._make_acls_on_interfaces()
        for acl_name, acl_d in result.items():
            intf_acls = [d for d in intf_acls_all if d["acl_name"] == acl_name]
            for intf_acl in intf_acls:
                if intf_acl["input"]:
                    acl_d["input"].append(intf_acl["input"])
                if intf_acl["output"]:
                    acl_d["output"].append(intf_acl["output"])
        for acl_d in result.values():
            acl_d["input"] = sorted(set(acl_d["input"]))
            acl_d["output"] = sorted(set(acl_d["output"]))

        return result

    @staticmethod
    def _make_ace_group(acl_cfg: str) -> LDStr:
        """Returns ACE groups split by remarks"""
        groups: LDStr = []
        if aces_all := [s.strip() for s in acl_cfg.split("\n") if s.strip()]:
            note = ""
            ace1 = aces_all[0]
            if ace1.startswith("remark "):
                note = ace1.replace("remark ", "", 1)

            lines: LStr = [ace1]
            for idx, line in enumerate(aces_all[1:], start=1):
                # rule
                if not line.startswith("remark "):
                    lines.append(line)
                    continue
                # 2nd remark
                line_prev = aces_all[idx - 1]
                if line_prev.startswith("remark "):
                    lines.append(line)
                    continue
                # 1st remark
                groups.append(dict(note=note, line="\n".join(lines)))
                note = line.replace("remark ", "", 1)
                lines = [line]
            groups.append(dict(note=note, line="\n".join(lines)))
        return groups
