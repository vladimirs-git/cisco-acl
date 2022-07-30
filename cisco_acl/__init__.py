"""cisco-acl"""

from cisco_acl.ace import Ace
from cisco_acl.ace_group import AceGroup
from cisco_acl.acl import Acl
from cisco_acl.address import Address
from cisco_acl.config_to import config_to_ace, config_to_aceg
from cisco_acl.port import Port
from cisco_acl.protocol import Protocol
from cisco_acl.remark import Remark

__all__ = [
    "Ace",
    "AceGroup",
    "Acl",
    "Address",
    "Port",
    "Protocol",
    "Remark",
    "config_to_ace",
    "config_to_aceg",
]

__version__ = "1.2.0"
__date__ = "2022-07-30"
__title__ = "cisco-acl"

__summary__ = "Python package to parse and manage Cisco ACL (Access Control List)"
__author__ = "Vladimir Prusakov"
__email__ = "vladimir.prusakovs@gmail.com"
__url__ = "https://github.com/vladimirs-git/cisco-acl"
__download_url__ = f"{__url__}/archive/refs/tags/{__version__}.tar.gz"
__license__ = "MIT"
