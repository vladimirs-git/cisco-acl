"""Base - Parent of: Address, Port, Protocol, BaseAce"""

import uuid
from typing import Any

from cisco_acl import helpers as h
from cisco_acl.static import IOS
from cisco_acl.types_ import LStr


class Base:
    """Base - Parent of: Address, Port, Protocol, BaseAce"""

    def __init__(self, **kwargs):
        """Base
        :param platform: Platform: "ios", "nxos" (default "ios")

        Helpers
        :param note: Object description
        """
        self._uuid: str = str(uuid.uuid1())
        self._platform: str = h.init_platform(**kwargs)
        note = kwargs.get("note")
        if note is None:
            note = ""
        self.note: Any = note

    def __repr__(self):
        params = self._repr__parameters()
        kwargs = ", ".join(params)
        name = self.__class__.__name__
        return f"{name}({kwargs})"

    def __str__(self):
        return self.line

    # =========================== property ===========================

    @property
    def line(self) -> str:
        """Stub"""
        return ""

    @line.setter
    def line(self, line: str) -> None:  # pylint: disable=no-self-use
        """Stub"""
        return

    @property
    def platform(self) -> str:
        """Platform: "ios" Cisco IOS, "nxos" Cisco Nexus NX-OS"""
        return self._platform

    @platform.setter
    def platform(self, platform: str) -> None:
        """Changes platform
        :param str platform: Platform: "ios", "nxos" (default "ios")
        """
        self._platform = h.init_platform(platform=platform)
        self.line = self.line

    @property
    def uuid(self) -> str:
        """Universally Unique Identifier"""
        return self._uuid

    @uuid.setter
    def uuid(self, uuid_: str) -> None:
        if not isinstance(uuid_, str):
            raise TypeError(f"{uuid_=} {str} expected")
        self._uuid = uuid_

    # =========================== helpers ============================

    def _repr__add_param(self, param: str, params: LStr) -> LStr:
        """Adds param to list of params"""
        if value := getattr(self, param):
            params.append(f"{param}={value!r}")
        return params

    def _repr__parameters(self) -> LStr:
        """Returns parameters for __repr__"""
        params: LStr = [f"{self.line!r}"]
        if self._platform != IOS:
            params.append(f"platform={self._platform!r}")
        params = self._repr__add_param("note", params)
        return params
