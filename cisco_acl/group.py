"""Group of Items"""

from __future__ import annotations

from typing import Sequence


class Group(Sequence):
    """Group of Items"""

    def __init__(self, items=None):
        self.items = []
        items = items or []
        for item in items:
            self.items.append(item)

    def __getitem__(self, idx):
        return self.items[idx]

    def __iter__(self):
        return iter(self.items)

    def __len__(self):
        return len(self.items)

    def __add__(self, other) -> Group:
        group = Group()
        group.items = self.items
        group.update(other.items)
        return group

    # =========================== methods ============================

    def add(self, item) -> None:
        """Append new item to group"""
        if item not in self.items:
            self.items.append(item)

    def delete(self, item) -> None:
        """Remove item from group"""
        if item in self.items:
            self.items.remove(item)

    def delete_all(self) -> None:
        """Remove item from group"""
        self.items = []

    def update(self, items) -> None:
        """Append new items to group"""
        for item in items:
            self.add(item)
