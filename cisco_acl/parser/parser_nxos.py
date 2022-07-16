"""NXOS config parser"""

import re

from cisco_acl.parser.parser_cisco import ParserCISCO
from cisco_acl.types_ import DDAny, DLStr, DStr, LDAny, LStr


class ParserNXOS(ParserCISCO):
    """NXOS config parser"""

    def parse_policy(self) -> DDAny:
        """NXOS. Parse policies (access-list and access-group) from config.
        Example:
        self.config: "
        ip access-list ACL_NAME
          10 remark RULE_NAME
          20 permit ip any any
        interface Ethernet1/54
          ip access-group ACL_NAME in
        "
        :return: {"RULE_NAME": {
                    "acl": "ACL_NAME",
                    "name": "RULE_NAME",
                    "ace": ["remark RULE_NAME", "permit ip any any"],
                    "srcintf": {"interface Ethernet1/54"},
                    "dstintf": set(),}
                  }
        """
        policies: DDAny = {}  # return
        access_groups: LDAny = self._make_acls_on_interfaces()
        vdom = ""
        acls: DStr = self._acls_cnx()
        acls = {k: v for k, v in acls.items() if k in vdom}
        for acl_name, acl_cfg in acls.items():
            ace_groups: DLStr = {}
            aces = [s.strip() for s in acl_cfg.split("\n") if s.strip()]
            name = ""
            remarks: LStr = []
            for ace in aces:
                if 'statistics per-entry' in ace:
                    ace = ace.replace("statistics per-entry", "")
                elif re.match("[0-9]+ remark ", ace):
                    remark = re.sub("[0-9]+ remark ", "", ace)
                    if set(remark) == {"="}:
                        continue
                    if not remarks:
                        name = remark
                    remarks.append(remark)
                    ace_groups.setdefault(name, [])
                    ace_groups[name].append(ace)
                    continue
                if not name:
                    continue
                remarks = []
                ace_groups[name].append(ace)

            acgs = [d for d in access_groups if d["acl"] == acl_name]
            for acg in acgs:
                for name, aces_ in ace_groups.items():
                    if not policies.get(name):
                        policy = dict(acl=acl_name,
                                      name=name,
                                      ace=aces_,
                                      srcintf=set(),
                                      dstintf=set())
                        policies[name] = policy
                    if acg["srcintf"]:
                        policies[name]["srcintf"].add(acg["srcintf"])
                    if acg["dstintf"]:
                        policies[name]["dstintf"].add(acg["dstintf"])
        return policies
