"""ACE. Option."""
from __future__ import annotations

import string
from functools import total_ordering

from cisco_acl import helpers as h
from cisco_acl.base import Base
from cisco_acl.types_ import LStr, DAny

LOGS = ("log", "log-input")


@total_ordering
class Option(Base):
    """ACE. Option."""

    def __init__(self, line: str = "", **kwargs):
        """Init Option.

        :param line: Option line.
        :param platform: Platform: "asa", "ios", "nxos". Default "ios".
        :type platform: str

        :param version: Software version, default is "0".
        :type version: str

        Helpers
        :param note: Object description.
        :type note: Any

        :example:
            option = Option("ack dscp ef log")
            option.line -> "ack log"
            option.flags -> {"ack", "dscp", "ef"}
            option.logs -> {"log"}
        """
        self._line: str = ""
        self._flags: LStr = []
        self._logs: LStr = []
        super().__init__(**kwargs)  # platform, note
        self.line = line

    # ========================== redefined ===========================

    def __hash__(self) -> int:
        """__hash__."""
        return tuple(self._flags).__hash__()

    def __eq__(self, other) -> bool:
        """== equality."""
        return self.__hash__() == other.__hash__()

    def __lt__(self, other) -> bool:
        """< less than."""
        if self.__class__ == other.__class__:
            return self._flags < self._flags
        return False

    # =========================== property ===========================

    @property
    def flags(self) -> LStr:
        """ACE Option flags, items that related to packet forwarding."""
        return self._flags

    @property
    def line(self) -> str:
        """ACE Option items as string."""
        return self._line

    @line.setter
    def line(self, line: str) -> None:
        line = h.init_line(line)
        self._line = line

        options: LStr = [s.strip() for s in line.split()]
        options = [s for s in options if s]
        for option in options:
            if option[0] not in string.ascii_lowercase:
                raise ValueError(f"invalid {option=}")

        self._flags = [s for s in options if s not in LOGS]
        self._logs = [s for s in options if s in LOGS]

    @property
    def logs(self) -> LStr:
        """ACE Option logs, items that not related to packet forwarding."""
        return self._logs

    # =========================== method =============================

    def data(self, uuid: bool = False) -> DAny:
        """Return Option data as dictionary.

        :param uuid: Return self.uuid in data.
        :type uuid: bool

        :return: Option data.

        :example:
        option = Option("ack log")
        option.data() -> {
            "line": "ack log",
            "platform": "ios",
            "version": "0",
            "note": "",
            "flags": ["ack"],
            "logs": ["log"],
        }
        """
        data = dict(
            # init
            line=self.line,
            platform=self._platform,
            version=str(self.version),
            note=self.note,
            # property
            flags=self._flags,
            logs=self._logs,
        )
        if uuid:
            data["uuid"] = self.uuid
        return data
