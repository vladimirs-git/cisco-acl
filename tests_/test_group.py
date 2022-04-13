"""unittest cisco_acl/group.py"""

import unittest

from cisco_acl.group import Group


# noinspection DuplicatedCode
class Test(unittest.TestCase):
    """Group"""

    # ========================== redefined ===========================

    def test__init__(self):
        """Group.__init__()"""

        for items, req in [
            (["a"], ["a"]),
            (["a", "b"], ["a", "b"]),
        ]:
            group = Group(items)
            result = group.items
            self.assertEqual(result, req, msg=f"{items=}")

    def test__getitem__(self):
        """Group.__getitem__()"""
        group = Group(["a", "b"])
        for idx, req in [
            (0, "a"),
            (1, "b"),
        ]:
            result = group[idx]
            self.assertEqual(result, req, msg=f"{idx=}")

    def test__iter__(self):
        """Group.__iter__()"""
        group = Group(["a", "b"])
        for idx, result in enumerate(group):
            req = group[idx]
            self.assertEqual(result, req, msg=f"{idx=}")

    def test__len__(self):
        """Group.__len__()"""
        for items, req in [
            ([], 0),
            (["a", "b"], 2),
        ]:
            group = Group(items)
            result = len(group)
            self.assertEqual(result, req, msg=f"{group=}")

    # =========================== methods ============================

    def test__add(self):
        """Group.add()"""
        for items, req in [
            ([], []),
            (["a", "b"], ["a", "b"]),
            (["b", "a"], ["b", "a"]),
            (["a", "b", "a"], ["a", "b"]),
        ]:
            group = Group()
            for item in items:
                group.add(item)
            result = group.items
            self.assertEqual(result, req, msg=f"{items=}")

    def test__delete(self):
        """Group.delete()"""
        for items, req in [
            ([], ["a", "b", "c"]),
            (["a", "b"], ["c"]),
            (["a", "b", "a"], ["c"]),
        ]:
            group = Group()
            group.items = ["a", "b", "c"]
            for item in items:
                group.delete(item)
            result = group.items
            self.assertEqual(result, req, msg=f"{items=}")

    def test__delete_all(self):
        """Group.delete_all()"""
        group = Group()
        group.items = ["a"]
        group.delete_all()
        result = group.items
        self.assertEqual(result, [], msg="delete_all")

    def test__update(self):
        """Group.update()"""
        for items, req in [
            ([], []),
            (["a", "b"], ["a", "b"]),
            (["b", "a"], ["b", "a"]),
            (["a", "b", "a"], ["a", "b"]),
        ]:
            group = Group()
            group.update(items)
            result = group.items
            self.assertEqual(result, req, msg=f"{items=}")


if __name__ == "__main__":
    unittest.main()
