"""ACE. Option"""
from __future__ import annotations

from functools import total_ordering

from cisco_acl import helpers as h
from cisco_acl.base import Base
from cisco_acl.types_ import LStr, DAny

LOGS = ("log", "log-input")


@total_ordering
class Option(Base):
    """ACE. Option"""

    def __init__(self, line: str = "", **kwargs):
        """ACE. Option
        :param str line: Option line
        :param str platform: Platform: "ios", "nxos" (default "ios")

        Helpers
        :param str note: Object description

        :example:
            option = Option("ack dscp ef log")
            result:
                option.line == "ack log"
                option.flags == {"ack", "dscp", "ef"}
                option.logs == {"log"}
        """
        self._line: str = ""
        self._flags: LStr = []
        self._logs: LStr = []
        super().__init__(**kwargs)  # platform, note
        self.line = line

    # ========================== redefined ===========================

    def __hash__(self) -> int:
        return tuple(self._flags).__hash__()

    def __eq__(self, other) -> bool:
        """== equality"""
        return self.__hash__() == other.__hash__()

    def __lt__(self, other) -> bool:
        """< less than"""
        if self.__class__ == other.__class__:
            return self._flags < self._flags
        return False

    # =========================== property ===========================

    @property
    def flags(self) -> LStr:
        """ACE Option flags, items that related to packet forwarding"""
        return self._flags

    @property
    def line(self) -> str:
        """ACE Option items as **str"""
        return self._line

    @line.setter
    def line(self, line: str) -> None:
        line = h.init_line(line)
        self._line = line

        items: LStr = [s.strip() for s in line.split()]
        items = [s for s in items if s]
        self._flags = [s for s in items if s not in LOGS]
        self._logs = [s for s in items if s in LOGS]

    @property
    def logs(self) -> LStr:
        """ACE Option logs, items that not related to packet forwarding"""
        return self._logs

    # =========================== methods ============================

    def copy(self) -> Option:
        """Copies the self object"""
        kwargs = self.data()
        return Option(**kwargs)

    def data(self) -> DAny:
        """Returns *Option* data as *dict*
        :return: Option data

        :example:
        option = Option("ack log")
            option.data() ->
                {"line": "ack log",
                 "platform": "ios",
                 "note": "",
                 "flags": ["ack"],
                 "logs": ["log"]}
        """
        data = dict(
            # init
            line=self.line,
            platform=self._platform,
            note=self.note,
            # property
            flags=self._flags,
            logs=self._logs,
        )
        return data
