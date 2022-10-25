"""Remark - comments in ACL"""
from __future__ import annotations

from functools import total_ordering
from typing import List

from cisco_acl import helpers as h
from cisco_acl.base_ace import BaseAce
from cisco_acl.types_ import DAny


@total_ordering
class Remark(BaseAce):
    """Remark - comments in ACL"""

    def __init__(self, line: str = "", **kwargs):
        """Remark
        :param line: string of ACEs
        :type line: str

        :param platform: Platform: "ios", "nxos" (default "ios")
        :type platform: str

        Helpers
        :param note: Object description
        :type note: Any

        :example:
            line: "10 remark text"
            result:
                self.line: "10 remark text"
                self.sequence: 10
                self.action: "remark"
                self.text: "text"
        """
        self._action = "remark"
        self._sequence = 0
        self._text = ""
        super().__init__(**kwargs)
        if sequence := h.init_int(kwargs.get("sequence") or 0):
            self._sequence = sequence
        if kwargs.get("text"):
            self._text = h.init_remark_text(kwargs.get("text") or "")
        if line:
            self.line = line

    def __lt__(self, other) -> bool:
        """< less than"""
        if hasattr(other, "sequence"):
            if self._sequence == other.sequence:
                if isinstance(other, Remark):
                    return self._text < other.text
                return True
            return self._sequence < other.sequence
        if isinstance(other, str):
            return False
        return True

    # =========================== property ===========================

    @property
    def action(self) -> str:
        """ACE remark action

        :example:
            Remark("10 remark text")
            return: "remark"
        """
        return self._action

    @property
    def line(self) -> str:
        """ACE remark line

        :example:
            Remark("10 remark text")
            return: "10 remark text" """
        items = [self._sequence_s(), self._action, self._text]
        return " ".join([s for s in items if s])

    @line.setter
    def line(self, line) -> None:
        line = h.init_line(line)
        ace_d = h.parse_action(line)

        action = ace_d["action"]
        expected = "remark"
        if action != expected:
            raise ValueError(f"invalid {action=}, {expected=}")

        self._sequence = h.init_int(ace_d["sequence"])
        self._text = h.init_remark_text(ace_d["text"])

    @property
    def text(self) -> str:
        """ACE remark text

        :example:
            Remark("10 remark text")
            return: "text"
        """
        return self._text

    @text.setter
    def text(self, text: str) -> None:
        self._text = h.init_remark_text(text)

    # =========================== methods ============================

    def data(self, uuid: bool = False) -> DAny:
        """Converts *Remark* object to *dict*
        :param uuid: Returns self.uuid in data
        :type uuid: bool

        :return: Remark data
        """
        data = dict(
            # init
            line=self.line,
            platform=self._platform,
            note=self.note,
            # property
            sequence=self._sequence,
            action=self._action,
            text=self._text,
        )
        if uuid:
            data["uuid"] = self.uuid
        return data


LRemark = List[Remark]
