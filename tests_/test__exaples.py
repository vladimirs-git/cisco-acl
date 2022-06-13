"""Unittests examples"""

import os
import runpy
import unittest

from setup import ROOT


class Test(unittest.TestCase):
    """Unittests examples"""

    def test_valid__examples(self):
        """Examples"""
        root = os.path.join(ROOT, "examples")
        for root_i, _, files_i in os.walk(root):
            for file_ in files_i:
                if file_.endswith(".py"):
                    path = os.path.join(root_i, file_)
                    runpy.run_path(path)


if __name__ == "__main__":
    unittest.main()
