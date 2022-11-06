"""Unittest cisco_acl/group.py"""

import unittest

from cisco_acl.group import Group


# noinspection DuplicatedCode
class Test(unittest.TestCase):
    """Group"""

    # ======================= special methods ========================

    def test_valid__init__(self):
        """Group.__init__()"""

        for items, req in [
            (None, []),
            ([], []),
            ("ab", ["a", "b"]),
            (["a", "b"], ["a", "b"]),
        ]:
            group = Group(items)
            result = group.items
            self.assertEqual(result, req, msg=f"{items=}")

    def test_invalid__init__(self):
        """Group.__init__()"""
        for items, error in [
            (1, TypeError),
        ]:
            with self.assertRaises(error, msg=f"{items=}"):
                Group(items)

    def test_valid__add__(self):
        """Group.__add__()"""
        group1 = Group(["a"])
        for items, req in [
            (["b", "c"], ["a", "b", "c"]),
            (["a", "b"], ["a", "b"]),
        ]:
            group3 = group1 + Group(items)
            result = group3.items
            self.assertEqual(result, req, msg=f"{items=}")

    def test_invalid__add__(self):
        """Group.__add__()"""
        for items, error in [
            (1, TypeError),
        ]:
            with self.assertRaises(error, msg=f"{items=}"):
                Group(items)

    def test_valid__contains__(self):
        """Group.__contains__()"""
        group = Group(["a", "b"])
        for item, req in [
            ("a", True),
            ("c", False),
        ]:
            result = item in group
            self.assertEqual(result, req, msg=f"{item=}")

    def test_valid__delitem__(self):
        """Group.__delitem__()"""
        group = Group(["a", "b", "c"])
        for idx, req in [
            (1, ["a", "c"]),
            (1, ["a"]),
        ]:
            del group[idx]
            result = group.items
            self.assertEqual(result, req, msg=f"{idx=}")

    def test_valid__getitem__(self):
        """Group.__getitem__()"""
        group = Group(["a", "b"])
        for idx, req in [
            (0, "a"),
            (1, "b"),
        ]:
            result = group[idx]
            self.assertEqual(result, req, msg=f"{idx=}")

    def test_valid__iter__(self):
        """Group.__iter__()"""
        group = Group(["a", "b"])
        for idx, result in enumerate(group):
            req = group[idx]
            self.assertEqual(result, req, msg=f"{idx=}")

    def test_valid__len__(self):
        """Group.__len__()"""
        for items, req in [
            ([], 0),
            (["a", "b"], 2),
        ]:
            group = Group(items)
            result = len(group)
            self.assertEqual(result, req, msg=f"{group=}")

    def test_valid__reversed__(self):
        """Group.__reversed__()"""
        group = Group([1, 2, 3])
        result = list(reversed(group))
        req = [3, 2, 1]
        self.assertEqual(result, req, msg=f"{group=}")

    # =========================== method =============================

    def test_valid__add(self):
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

    def test_valid__append(self):
        """Group.append()"""
        group = Group()
        for item, req in [
            ("a", ["a"]),
            ("b", ["a", "b"]),
            ("a", ["a", "b", "a"]),
        ]:
            group.append(item)
            result = group.items
            self.assertEqual(result, req, msg=f"{item=}")

    def test_valid__clear(self):
        """Group.clear()"""
        group = Group(["a"])
        group.clear()
        result = group.items
        self.assertEqual(result, [], msg="clear")

    def test_valid__delete(self):
        """Group.delete()"""

        for items, item, req in [
            (["a", "b", "c"], "b", ["a", "c"]),
            (["a", "c"], "b", ["a", "c"]),
            ([["a"], ["b"], ["c"]], ["b"], [["a"], ["c"]]),
        ]:
            group = Group(items)
            group.delete(item)
            result = group.items
            self.assertEqual(result, req, msg=f"{items=}")

    def test_valid__extend(self):
        """Group.extend()"""
        group = Group()
        for item, req in [
            (["a"], ["a"]),
            ({"b"}, ["a", "b"]),
            (("a",), ["a", "b", "a"]),
        ]:
            group.extend(item)
            result = group.items
            self.assertEqual(result, req, msg=f"{item=}")

    def test_invalid__extend(self):
        """Group.extend()"""
        group = Group()
        for item, error in [
            ("a", TypeError),
        ]:
            with self.assertRaises(error, msg=f"{item=}"):
                group.extend(item)

    def test_valid__index(self):
        """Group.index()"""
        group = Group(["a", "b", "c"])
        for item, req in [
            ("a", 0),
            ("b", 1),
        ]:
            result = group.index(item)
            self.assertEqual(result, req, msg=f"{item=}")

    def test_invalid__index(self):
        """Group.index()"""
        group = Group(["a", "b", "c"])
        for item, error in [
            ("d", ValueError),
        ]:
            with self.assertRaises(error, msg=f"{item=}"):
                group.index(item)

    def test_valid__insert(self):
        """Group.insert()"""
        group = Group(["a", "b", "c"])
        group.insert(1, "d")
        result = group.items
        req = ["a", "d", "b", "c"]
        self.assertEqual(result, req, msg="insert")

    def test_valid__pop(self):
        """Group.pop()"""
        group = Group(["a", "b", "c", "b"])
        for idx, item, req in [
            (1, "b", ["a", "c", "b"]),
            (2, "b", ["a", "c"]),
        ]:
            result_ = group.pop(idx)
            self.assertEqual(result_, item, msg=f"{item=}")
            result = group.items
            self.assertEqual(result, req, msg=f"{item=}")

        result_ = group.pop()
        self.assertEqual(result_, "c", msg=f"{item=}")
        result = group.items
        self.assertEqual(result, ["a"], msg=f"{item=}")

    def test_invalid__pop(self):
        """Group.pop()"""
        group = Group(["a", "b"])
        for item, error in [
            (2, IndexError),
        ]:
            with self.assertRaises(error, msg="pop"):
                group.pop(item)

    def test_valid__remove(self):
        """Group.remove()"""
        group = Group(["a", "b", "c", "b"])
        for item, req in [
            ("b", ["a", "c", "b"]),
            ("b", ["a", "c"]),
        ]:
            group.remove(item)
            result = group.items
            self.assertEqual(result, req, msg=f"{item=}")

    def test_invalid__remove(self):
        """Group.remove()"""
        group = Group(["a", "b"])
        for item, error in [
            ("c", ValueError),
        ]:
            with self.assertRaises(error, msg=f"{item=}"):
                group.remove(item)

    def test_valid__reverse(self):
        """Group.reverse()"""
        group = Group([1, 2, 3])
        group.reverse()
        result = group.items
        req = [3, 2, 1]
        self.assertEqual(result, req, msg="reverse")

    def test_valid__sort(self):
        """Group.sort()"""
        group = Group([3, 1, 2])
        group.sort()
        result = group.items
        req = [1, 2, 3]
        self.assertEqual(result, req, msg="sort")
        group.sort(reverse=True)
        result = group.items
        req = [3, 2, 1]
        self.assertEqual(result, req, msg="sort reverse=True")

    def test_valid__update(self):
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
