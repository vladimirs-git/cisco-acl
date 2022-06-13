"""Group of Items"""

from __future__ import annotations

from typing import Iterable


class Group:
    """Group of Items"""

    def __init__(self, items=None):
        self.items = []
        if items:
            self.items = list(items)

    # ======================= special methods ========================

    def __add__(self, other) -> Group:
        """Returns self.items + other.items"""
        group = Group(self.items.copy())
        group.update(other.items)
        return group

    def __contains__(self, item) -> bool:
        """Returns key in self"""
        return item in self.items

    def __delitem__(self, idx: int) -> None:
        """Deletes self.items[key]"""
        self.items.__delitem__(idx)

    def __getitem__(self, idx: int):
        return self.items[idx]

    def __iter__(self):
        return iter(self.items)

    def __len__(self) -> int:
        return len(self.items)

    def __reversed__(self):
        """Returns a reverse iterator over the list"""
        for item in self.items[::-1]:
            yield item

    # =========================== methods ============================

    def add(self, item) -> None:
        """Adds new item to self.items list, if it is not in self.items"""
        if item not in self.items:
            self.items.append(item)

    def append(self, item) -> None:
        """Appends item to the end of the self.items list"""
        self.items.append(item)

    def clear(self) -> None:
        """Removes all items from the self.items list"""
        self.items = []

    def copy(self):
        """Returns a shallow copy of the self.items list"""
        return self.items.copy()

    def count(self, item):
        """Returns number of occurrences of the self.items"""
        return self.items.count(item)

    def delete(self, item) -> None:
        """Removes item from the self.items list"""
        if item in self.items:
            self.items.remove(item)

    def extend(self, items: Iterable) -> None:
        """Extends the self.items list by appending items"""
        if isinstance(items, (list, set, tuple)):
            self.items.extend(list(items))
            return
        raise TypeError(f"{items=} {list} expected")

    def index(self, *args) -> int:
        """Returns first index of item
        Raises ValueError if the value is not present"""
        return self.items.index(*args)

    def insert(self, *args) -> None:
        """Inserts item before index"""
        return self.items.insert(*args)

    def pop(self, *args):
        """Removes and return item at index (default last)
        Raises IndexError if list is empty or index is out of range"""
        return self.items.pop(*args)

    def remove(self, *args) -> None:
        """Removes first occurrence of items in the self.items
        Raises ValueError if the item is not present"""
        self.items.remove(*args)

    def reverse(self) -> None:
        """Reverses order of items in the self.items list"""
        self.items.reverse()

    def sort(self, *args, **kwargs) -> None:
        """Sorts the self.items list in ascending order
        :example:
            self.items.sort(reverse=True|False, key=myFunc)
        """
        self.items.sort(*args, **kwargs)

    def update(self, items: list) -> None:
        """Extends list by adding items to self.items list, if it is not in the self.items"""
        for item in items:
            self.add(item)
