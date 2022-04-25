"""Typing"""
from typing import (
    Any,
    Dict,
    Iterable,
    List,
    Optional,
    Set,
    Union,
)

from netaddr import IPNetwork  # type: ignore

DAny = Dict[str, Any]
DStr = Dict[str, str]
IInt = Iterable[int]
IStr = Iterable[str]
LInt = List[int]
LStr = List[str]
OIPNetwork = Optional[IPNetwork]
OInt = Optional[int]
SInt = Set[int]
SStr = Set[str]
StrInt = Union[str, int]
UIInt = Union[bytes, float, int, str, Iterable[Union[bytes, float, int, str]]]

LDStr = List[DStr]
LStrInt = List[StrInt]

UStr = Union[str, IStr]
