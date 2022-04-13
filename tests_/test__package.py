"""unittests package"""

import os
import re
import unittest
from datetime import datetime

from cisco_acl import __title__
from setup import PACKAGE, PACKAGE_, ROOT

IMPORTS = [
    "from cisco_acl.ace import Ace",
    "from cisco_acl.ace_group import AceGroup",
    "from cisco_acl.acl import Acl",
    "from cisco_acl.remark import Remark",
]


class Test(unittest.TestCase):
    """unittests package"""

    # =========================== helpers ============================

    @staticmethod
    def paths_dates():
        """path to .py files with last modified dates"""
        paths = []
        for root_i, _, files_i in os.walk(ROOT):
            for file_ in files_i:
                if file_.endswith(".py"):
                    path = os.path.join(root_i, file_)
                    stat = os.stat(path)
                    date_ = datetime.fromtimestamp(stat.st_mtime).date()
                    paths.append((path, date_))
        return paths

    # ============================ tests =============================

    def test_valid__package(self):
        """package"""
        name, var = f"{__title__=!s}".split("=")
        path = os.path.join(ROOT, PACKAGE, "__init__.py")
        self.assertEqual(var, PACKAGE, msg=f"invalid variable {name} in {path=}")

        name, var = f"{ROOT=!s}".split("=")
        var = os.path.split(var)[1]
        path = os.path.join(ROOT, "static_.py")
        self.assertEqual(var, PACKAGE, msg=f"invalid variable {name} in {path=}")

    @unittest.skip("solve pylint conflict")
    def test_valid__init__(self):
        """__init__.py"""
        req_lines = set(IMPORTS)
        path = os.path.join(ROOT, "__init__.py")
        with open(path) as fh:
            text = fh.read()
            lines = {s.strip() for s in text.split("\n")}
            result = req_lines.difference(lines)
            self.assertEqual(len(result), 0, msg=f"mandatory lines in {path=}")

    def test_valid__init(self):
        """__init__.py"""
        req_imports = IMPORTS.copy()
        req_imports.extend([
            "__all__ = .+",
            "__version__ = .+",
            "__date__ = .+",
            "__title__ = .+",
            "__summary__ = .+",
            "__author__ = .+",
            "__email__ = .+",
            "__url__ = .+",
            "__download_url__ = .+",
        ])
        path = os.path.join(ROOT, PACKAGE_, "__init__.py")
        with open(path) as fh:
            text = fh.read()
            lines = {s.strip() for s in text.split("\n")}
            mandatory = list()
            for req in req_imports:
                for line in lines:
                    if re.search(req, line):
                        break
                else:
                    mandatory.append(req)
                self.assertEqual(len(mandatory), 0, msg=f"absent {mandatory=} in {path=}")

    def test_valid__version(self):
        """version"""
        path = os.path.join(ROOT, PACKAGE_, "__init__.py")
        with open(path) as fh:
            text = fh.read()
            version_init = (re.findall("^__version__ = \"(.+)\"", text, re.M) or [""])[0]
            self.assertNotEqual(version_init, "", msg=f"__version__ in {path=}")

        path = os.path.join(ROOT, "setup.py")
        with open(path) as fh:
            text = fh.read()
            version_setup = (re.findall("^VERSION = \"(.+)\"", text, re.M) or [""])[0]
            self.assertNotEqual(version_setup, "", msg=f"VERSION in {path=}")

        self.assertRegex(version_init, version_setup, msg="the same version everywhere")
        regex = r"\d+(\.(\d+((a|b|c|rc)\d+)?|post\d+|dev\d+))+"
        version = version_init
        self.assertRegex(version, regex, msg="version naming convention")

        path = os.path.join(ROOT, "README.md")
        with open(path) as fh:
            text = fh.read()
            regex = PACKAGE + r"-(.+)\.tar\.gz"
            versions_readme = re.findall(regex, text, re.M)
            for version_readme in versions_readme:
                self.assertEqual(version_readme, version, msg=f"package name in {path=}")

        path = os.path.join(ROOT, "CHANGELOG.txt")
        with open(path) as fh:
            text = fh.readline().strip()
            version_changelog = (re.findall(r"(.+)\s\(\d\d\d\d-\d\d-\d\d\)$", text) or [""])[0]
            self.assertEqual(version_changelog, version, msg=f"version in {path=}")


if __name__ == "__main__":
    unittest.main()
