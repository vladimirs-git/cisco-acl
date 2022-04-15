"""ACL Remark"""
from __future__ import annotations

from functools import total_ordering
from typing import List

from netaddr import IPNetwork  # type: ignore

from cisco_acl import helpers as h
from cisco_acl.base_ace import BaseAce


@total_ordering
class Remark(BaseAce):
    """ACL Remark"""

    __slots__ = ("_platform", "_note", "_line", "_sequence", "_action", "_text")

    def __init__(self, line: str, **kwargs):
        """ACL Remark.
        :param line: ACE line.
        :param kwargs: Params.
            note: Object description (used only in object).

        Example:
        line: "10 remark text"
        note: "description"

        result:
            self.line = "10 remark text"
            self.sequence = 10
            self.action = "remark"
            self.text = "text"
            self.note = "description"
        """
        super().__init__(line, **kwargs)
        self._uuid = self._uuid  # hold docstring and suppress pylint W0235

    def __hash__(self) -> int:
        return self.line.__hash__()

    def __eq__(self, other) -> bool:
        """== equality"""
        if self.__class__ == other.__class__:
            if self.__hash__() == other.__hash__():
                return True
        return False

    def __lt__(self, other) -> bool:
        """< less than"""
        if hasattr(other, "sequence"):
            if self.sequence == other.sequence:
                if isinstance(other, Remark):
                    return self.text < other.text
                return True
            return self.sequence < other.sequence
        if isinstance(other, str):
            return False
        return True

    # =========================== property ===========================

    @property
    def line(self) -> str:
        """ACE remark line.
        Example:
            Remark("10 remark text")
            :return: "10 remark text" """
        items = [self.ssequence, self.action, self.text]
        return " ".join([s for s in items if s])

    @line.setter
    def line(self, line) -> None:
        line = self._init_line(line)
        h.check_line_length(line)
        ace_d = h.parse_action(line)
        action = ace_d["action"]
        expected = "remark"
        if action != expected:
            raise ValueError(f"invalid {action=}, {expected=}")
        self.sequence = int(ace_d["sequence"]) if ace_d["sequence"] else 0
        self._action = action
        self._text = ace_d["text"]

    @property
    def action(self) -> str:
        """ACE remark action.
        Example: Remark("10 remark text")
            :return: "remark" """
        return self._action

    @property
    def text(self) -> str:
        """ACE remark text.
        Example:
            Remark("10 remark text")
            :return: "text" """
        return self._text

    @text.setter
    def text(self, text: str) -> None:
        if not isinstance(text, str):
            raise TypeError(f"{text=} {str} expected")
        text = str(text).strip()
        if not text:
            raise ValueError(f"{text=} value required")
        self._text = text


LRemark = List[Remark]
