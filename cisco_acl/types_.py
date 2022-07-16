"""Typing"""
from ipaddress import IPv4Network
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union

DAny = Dict[str, Any]
DInt = Dict[str, int]
DStr = Dict[str, str]
DiStr = Dict[int, str]
IInt = Iterable[int]
IStr = Iterable[str]
LInt = List[int]
LStr = List[str]
OInt = Optional[int]
OIpNetwork = Optional[IPv4Network]
SInt = Set[int]
SStr = Set[str]
StrInt = Union[str, int]
T2Str = Tuple[str, str]
T3Str = Tuple[str, str, str]
UIInt = Union[bytes, float, int, str, Iterable[Union[bytes, float, int, str]]]

LDStr = List[DStr]
LStrInt = List[StrInt]

UStr = Union[str, IStr]
