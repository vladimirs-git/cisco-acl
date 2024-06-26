"""Base - Parent of: Address, Port, Protocol, Ace, AceBase, Acl, AceGroup."""

from abc import ABC, abstractmethod
from typing import Any
from uuid import uuid1

from netports import SwVersion

from cisco_acl import helpers as h
from cisco_acl.helpers import IOS
from cisco_acl.types_ import LStr, DAny


class Base(ABC):
    """Base - Parent of: Address, Port, Protocol, Ace, AceBase, Acl, AceGroup."""

    def __init__(self, **kwargs):
        """Init Base.

        :param platform: Platform: "asa", "ios", "nxos". Default "ios".
        :type platform: str

        :param version: Software version, default is "0".
        :type version: str

        Helpers
        :param uuid: Unique identifier.
        :type uuid: str

        :param note: Object description.
        :type note: Any
        """
        self._platform: str = h.init_platform(**kwargs)
        self._uuid: str = self._init_uuid(**kwargs)
        self.version: SwVersion = h.init_version(**kwargs)
        self.note: Any = self._init_note(**kwargs)

    def __repr__(self):
        """__repr__."""
        params = self._repr__params()
        kwargs = ", ".join(params)
        name = self.__class__.__name__
        return f"{name}({kwargs})"

    def __str__(self):
        """__str__."""
        return self.line

    @staticmethod
    def _init_uuid(**kwargs) -> str:
        """Init uuid."""
        if uuid := str(kwargs.get("uuid") or ""):
            return uuid
        return str(uuid1())

    @staticmethod
    def _init_note(**kwargs) -> Any:
        """Init note."""
        note = kwargs.get("note")
        if note is None:
            return ""
        return note

    # =========================== property ===========================

    @property
    def line(self) -> str:
        """Stub."""
        return ""

    @line.setter
    def line(self, line: str) -> None:
        """Stub."""
        _ = line  # noqa

    @property
    def platform(self) -> str:
        """Platform: Platform: "asa", "ios", "nxos"."""
        return self._platform

    @platform.setter
    def platform(self, platform: str) -> None:
        self._platform = h.init_platform(platform=platform)
        uuid = self.uuid
        self.line = self.line
        self.uuid = uuid

    @property
    def uuid(self) -> str:
        """Universally Unique Identifier."""
        return self._uuid

    @uuid.setter
    def uuid(self, uuid_: str) -> None:
        if not isinstance(uuid_, str):
            raise TypeError(f"{uuid_=} {str} expected")
        self._uuid = uuid_

    # =========================== method =============================

    def copy(self):
        """Copy the self object."""
        kwargs = self.data()
        return self.__class__(**kwargs)

    @abstractmethod
    def data(self, uuid: bool = False) -> DAny:
        """Convert self object to the dictionary.

        :param uuid: Return self.uuid in data.
        :type uuid: bool

        :return: The dictionary.
        """

    # =========================== helper =============================

    def _repr__add_param(self, param: str, params: LStr) -> LStr:
        """Add a param to the list of params."""
        if value := getattr(self, param):
            params.append(f"{param}={value!r}")
        return params

    def _repr__params(self) -> LStr:
        """Return parameters for __repr__."""
        params: LStr = [f"{self.line!r}"]
        if self._platform != IOS:
            params.append(f"platform={self._platform!r}")
        version = str(self.version)
        if version != "0":
            params.append(f"{version=!r}")
        params = self._repr__add_param("note", params)
        return params
