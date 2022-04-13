"""Interfaces with applied ACL"""

from cisco_acl import helpers as h
from cisco_acl.types_ import LStr, UStr


class Interface:
    """Interfaces with applied ACL"""

    def __init__(self, **kwargs):
        """Interfaces with applied ACL.
        :param kwargs: Params
            input: Interfaces, where Acl is used on input.
            output: Interfaces, where Acl is used on output.
        """
        self.input = kwargs.get("input") or []
        self.output = kwargs.get("output") or []

    # =========================== property ===========================

    @property
    def input(self) -> LStr:
        """Interfaces, where Acl is used on input"""
        return self._input

    @input.setter
    def input(self, items: UStr) -> None:
        items_: LStr = h.convert_to_lstr(name="input", items=items)
        self._input = sorted(items_)

    @input.deleter
    def input(self) -> None:
        self._input = []

    @property
    def output(self) -> LStr:
        """Interfaces, where Acl is used on output"""
        return self._output

    @output.setter
    def output(self, items: UStr) -> None:
        items_: LStr = h.convert_to_lstr(name="output", items=items)
        self._output = sorted(items_)

    @output.deleter
    def output(self) -> None:
        self._output = []
