"""AceBase, parent of: Ace, Remark, AceGroup."""

from abc import ABC, abstractmethod

from cisco_acl import helpers as h
from cisco_acl.base import Base
from cisco_acl.types_ import StrInt, DAny
from cisco_acl.wildcard import init_max_ncwb


class AceBase(Base, ABC):
    """AceBase, parent of: Ace, Remark, AceGroup."""

    def __init__(self, **kwargs):
        """Init AceBase.

        :param platform: Platform: "asa", "ios", "nxos". Default "ios".
        :type platform: str

        Helpers
        :param note: Object description.
        :type note: Any

        :param max_ncwb: Max count of non-contiguous wildcard bits.
        :type max_ncwb: int

        :param protocol_nr: Well-known ip protocols as numbers.
            True  - all ip protocols as numbers,
            False - well-known ip protocols as names (default).
        :type protocol_nr: bool

        :param port_nr: Well-known TCP/UDP ports as numbers.
            True  - all tcp/udp ports as numbers,
            False - well-known tcp/udp ports as names (default).
        :type port_nr: bool

        Alternate way to get `name` and ACEs `items`, if `line` absent.
        :param str type: ACL type: "extended", "standard" (default "extended").
        """
        self._line: str = ""
        self._sequence: int = 0
        self._type: str = "extended"
        self._protocol_nr: bool = False
        self._port_nr: bool = False
        # noinspection PyProtectedMember
        self.max_ncwb: int = init_max_ncwb(**kwargs)
        super().__init__(**kwargs)  # platform, note
        if kwargs.get("type"):
            self._type = h.init_type(**kwargs)
        if sequence := kwargs.get("sequence"):
            self._sequence = h.init_int(sequence)
        if protocol_nr := kwargs.get("protocol_nr"):
            self._protocol_nr = bool(protocol_nr)
        if port_nr := kwargs.get("port_nr"):
            self._port_nr: bool = bool(port_nr)

    def __hash__(self) -> int:
        """__hash__."""
        return self.line.__hash__()

    def __eq__(self, other) -> bool:
        """== equality."""
        if self.__class__ == other.__class__:
            return self.__hash__() == other.__hash__()
        return False

    def __repr__(self):
        """__repr__."""
        params = self._repr__params()
        params = self._repr__add_param("protocol_nr", params)
        params = self._repr__add_param("port_nr", params)
        kwargs = ", ".join(params)
        name = self.__class__.__name__
        return f"{name}({kwargs})"

    # =========================== property ===========================

    @property
    def port_nr(self) -> bool:
        """Well-known TCP/UDP ports as numbers."""
        return self._port_nr

    @port_nr.setter
    def port_nr(self, port_nr: bool) -> None:
        self._port_nr = bool(port_nr)
        data = self.data(uuid=True)
        self.__init__(**data)  # type: ignore

    @property
    def protocol_nr(self) -> bool:
        """Well-known ip protocols as numbers."""
        return self._protocol_nr

    @protocol_nr.setter
    def protocol_nr(self, protocol_nr: bool) -> None:
        self._protocol_nr = bool(protocol_nr)
        data = self.data(uuid=True)
        self.__init__(**data)  # type: ignore

    @property
    def sequence(self) -> int:
        """ACE sequence number in ACL.

        :return: Sequence number.

        :example: Ace without sequence number
            self: Ace("permit ip any any")
            return: 0

        :example: Ace with sequence number.
            ace = Ace("10 permit ip any any")
            ace.sequence -> 10
        """
        return self._sequence

    @sequence.setter
    def sequence(self, sequence: StrInt) -> None:
        self._sequence = h.init_int(sequence)

    @property
    def type(self) -> str:
        """ACL type: standard, extended."""
        return self._type

    @type.setter
    def type(self, type_: str) -> None:
        self._type = h.init_type(type=type_, platform=self.platform)
        data = self.data(uuid=True)
        self.__init__(**data)  # type: ignore

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

    def _sequence_s(self) -> str:
        """Return string of sequence, empty string if sequence==0."""
        if self._sequence:
            return str(self._sequence)
        return ""
