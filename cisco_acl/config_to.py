"""From the "show running-config" output - Creates *Acl* objects"""

from cisco_acl.ace_group import AceGroup
from cisco_acl.acl import Acl, LAcl
from cisco_acl.config_parser import ConfigParser


def config_to_ace(config: str, platform: str = "ios", version: str = "") -> LAcl:
    """Creates *Acl* objects based on the "show running-config" output.
    *Acl* contains *Ace* items, where each ACE line is treated as an independent element
    :param config: Config file, output of "show running-config" command
    :param platform: Platform: "ios", "nxos" (default "ios")
    :param version: Software version (not implemented, planned for compatability)
    :return: *Acl* objects
    """
    parser = ConfigParser(config=config, platform=platform, version=version)
    parser.parse_config()
    parsed_acls = parser.acls()

    acls: LAcl = []
    for acl_d in parsed_acls:
        acl_o = Acl(platform=platform, **acl_d)
        acls.append(acl_o)
    return acls


def config_to_aceg(config: str, platform: str = "ios", version: str = "") -> LAcl:
    """Creates *Acl* objects based on the "show running-config" output.
    *Acl* contains *AceGroup* items, where ACE lines grouped by remarks
    :param config: Config file, output of "show running-config" command
    :param platform: Platform: "ios", "nxos" (default "ios")
    :param version: Software version (not implemented, planned for compatability)
    """
    parser = ConfigParser(config=config, platform=platform, version=version)
    parser.parse_config()
    parsed_acls = parser.acls_by_remark()

    acls: LAcl = []
    for acl_d in parsed_acls:
        name = acl_d["name"]
        items = []
        for ace_group_d in acl_d["ace_group"]:
            ace_group_o = AceGroup(platform=platform, **ace_group_d)
            items.append(ace_group_o)
        acl_o = Acl(name=name, platform=platform, items=items,
                    input=acl_d["input"], output=acl_d["output"])
        acls.append(acl_o)
    return acls
