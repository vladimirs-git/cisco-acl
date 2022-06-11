"""Base - Parent of: AceBase, Address, Port, Protocol
BaseAce - Parent of: Ace, Remark"""

import uuid
from abc import ABC, abstractmethod
from typing import Any

from cisco_acl import helpers as h
from cisco_acl.static import PLATFORMS, DEFAULT_PLATFORM
from cisco_acl.types_ import StrInt, LStr


class Base(ABC):
    """Base - Parent of: AceBase, Address, Port, Protocol"""

    def __init__(self, **kwargs):
        """Base - Parent of: AceBase, Address, Port, Protocol
        :param platform: Supported platforms: "ios", "cnx". By default: "ios"
        :param note: Object description (can be used for ACEs sorting)
        """
        self._uuid = str(uuid.uuid1())
        self._platform = self._init_platform(**kwargs)
        self.note: Any = kwargs.get("note") or ""

    def __repr__(self):
        params = [f"{self.line!r}"]
        if self.platform != DEFAULT_PLATFORM:
            params.append(f"platform={self.platform!r}")
        if self.note:
            params.append(f"note={self.note!r}")
        kwargs = ", ".join(params)
        return f"{self.__class__.__name__}({kwargs})"

    def __str__(self):
        return self.line

    # ============================= init =============================

    @staticmethod
    def _init_platform(**kwargs) -> str:
        """Init device platform type: "ios", "cnx" """
        platform = kwargs.get("platform") or DEFAULT_PLATFORM
        if platform not in PLATFORMS:
            raise ValueError(f"invalid {platform=}, expected={PLATFORMS}")
        return platform

    @staticmethod
    def _init_line(line: str) -> str:
        """Init line, replace spaces"""
        return h.line_wo_spaces(line)

    @staticmethod
    def _init_lines(line: str) -> LStr:
        """Init multiple lines, replace spaces"""
        return h.lines_wo_spaces(line)

    @staticmethod
    def _init_line_int(line: StrInt) -> str:
        """Init line, int convert to str, replace spaces"""
        if isinstance(line, int):
            if line < 0:
                raise ValueError(f"{line=} positive expected")
            line = str(line)
        if not isinstance(line, str):
            raise TypeError(f"{line=} {str} expected")
        return h.replace_spaces(line)

    # =========================== property ===========================

    @property  # type:ignore
    @abstractmethod
    def line(self) -> str:
        """ACE line"""
        return ""

    @line.setter  # type:ignore
    @abstractmethod
    def line(self, line: str):
        return

    @property
    def uuid(self) -> str:
        """Universally Unique Identifier"""
        return self._uuid

    @uuid.setter
    def uuid(self, uuid_: str) -> None:
        if not isinstance(uuid_, str):
            raise TypeError(f"{uuid_=} {str} expected")
        self._uuid = uuid_

    @uuid.deleter
    def uuid(self) -> None:
        self.uuid = ""

    @property
    def platform(self) -> str:
        """Device platform type: "ios", "cnx" """
        return self._platform

    @platform.setter
    def platform(self, platform: str) -> None:
        self._platform = self._init_platform(platform=platform)
