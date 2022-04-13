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
        """Return self.items + other.items."""
        group = Group(self.items.copy())
        group.update(other.items)
        return group

    def __contains__(self, item) -> bool:
        """Return key in self."""
        return item in self.items

    def __delitem__(self, idx: int) -> None:
        """Delete self.items[key]."""
        self.items.__delitem__(idx)

    def __getitem__(self, idx: int):
        return self.items[idx]

    def __iter__(self):
        return iter(self.items)

    def __len__(self) -> int:
        return len(self.items)

    def __reversed__(self):
        """Return a reverse iterator over the list."""
        for item in self.items[::-1]:
            yield item

    # =========================== methods ============================

    def add(self, item) -> None:
        """Add new item to list, if it is not in list."""
        if item not in self.items:
            self.items.append(item)

    def append(self, item) -> None:
        """Append item to the end of the list."""
        self.items.append(item)

    def clear(self) -> None:
        """Remove all items from the list."""
        self.items = []

    def copy(self):
        """Return a shallow copy of the list."""
        return self.items.copy()

    def count(self, item):
        """Return number of occurrences of items."""
        return self.items.count(item)

    def delete(self, items) -> None:
        """Remove item from group."""
        if items in self.items:
            self.items.remove(items)

    def extend(self, items: Iterable) -> None:
        """Extend list by appending items."""
        if isinstance(items, (list, set, tuple)):
            self.items.extend(list(items))
            return
        raise TypeError(f"{items=} {list} expected")

    def index(self, *args) -> int:
        """Return first index of item. Raises ValueError if the value is not present."""
        return self.items.index(*args)

    def insert(self, *args) -> None:
        """Insert item before index."""
        return self.items.insert(*args)

    def pop(self, *args):
        """Remove and return item at index (default last).
        Raises IndexError if list is empty or index is out of range."""
        return self.items.pop(*args)

    def remove(self, *args) -> None:
        """Remove first occurrence of items. Raises ValueError if the item is not present."""
        self.items.remove(*args)

    def reverse(self) -> None:
        """ Reverse order of items in list."""
        self.items.reverse()

    def sort(self, *args, **kwargs) -> None:
        """Sort the list in ascending order.
        Example:
            self.items.sort(reverse=True|False, key=myFunc)
        """
        self.items.sort(*args, **kwargs)

    def update(self, items: list) -> None:
        """Extend list by adding items, if it is not in list."""
        for item in items:
            self.add(item)
