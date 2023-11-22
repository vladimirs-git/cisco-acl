"""Group of Items."""

from __future__ import annotations

from typing import Iterable


class Group:
    """Group of Items."""

    def __init__(self, items=None):
        """Init Group."""
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
        """__getitem__."""
        return self.items[idx]

    def __iter__(self):
        """Iterate."""
        return iter(self.items)

    def __len__(self) -> int:
        """__len__."""
        return len(self.items)

    def __reversed__(self):
        """Return a reverse iterator over the list."""
        for item in self.items[::-1]:
            yield item

    # =========================== method =============================

    def add(self, item) -> None:
        """Add new item to self.items list, if it is not in self.items."""
        if item not in self.items:
            self.items.append(item)

    def append(self, item) -> None:
        """Append item to the end of the self.items list."""
        self.items.append(item)

    def clear(self) -> None:
        """Remove all items from the self.items list."""
        self.items = []

    def copy(self):
        """Return a shallow copy of the self.items list."""
        return self.items.copy()

    def count(self, item):
        """Return number of occurrences of the self.items."""
        return self.items.count(item)

    def delete(self, item) -> None:
        """Remove item from the self.items list."""
        if item in self.items:
            self.items.remove(item)

    def extend(self, items: Iterable) -> None:
        """Extend the self.items list by appending items."""
        if isinstance(items, (list, set, tuple)):
            self.items.extend(list(items))
            return
        raise TypeError(f"{items=} {list} expected")

    def index(self, *args) -> int:
        """Return first index of item.

        Raise ValueError if the value is not present.
        """
        return self.items.index(*args)

    def insert(self, *args) -> None:
        """Insert item before index."""
        return self.items.insert(*args)

    def pop(self, *args):
        """Remove and return item at index (default last).

        Raise IndexError if list is empty or index is out of range.
        """
        return self.items.pop(*args)

    def remove(self, *args) -> None:
        """Remove first occurrence of items in the self.items.

        Raise ValueError if the item is not present.
        """
        self.items.remove(*args)

    def reverse(self) -> None:
        """Reverse order of items in the self.items list."""
        self.items.reverse()

    def sort(self, *args, **kwargs) -> None:
        """Sort the self.items list in ascending order.

        :example:
            self.items.sort(reverse=True|False, key=myFunc)
        """
        self.items.sort(*args, **kwargs)

    def update(self, items: list) -> None:
        """Extend list by adding items to self.items list, if it is not in the self.items."""
        for item in items:
            self.add(item)
