"""Typing"""
from ipaddress import IPv4Network
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union

DAny = Dict[str, Any]
DInt = Dict[str, int]
DStr = Dict[str, str]
DiStr = Dict[int, str]
IInt = Iterable[int]
IStr = Iterable[str]
LAny = List[Any]
LInt = List[int]
LStr = List[str]
OInt = Optional[int]
OIpNetwork = Optional[IPv4Network]
SInt = Set[int]
SStr = Set[str]
StrInt = Union[str, int]
T2Str = Tuple[str, str]
T3Str = Tuple[str, str, str]
TStr = Tuple[str, ...]
UIInt = Union[bytes, float, int, str, Iterable[Union[bytes, float, int, str]]]

DDAny = Dict[str, DAny]
DLAny = Dict[str, LAny]
DLStr = Dict[str, LStr]
LDAny = List[DAny]
LDStr = List[DStr]
LStrInt = List[StrInt]
UStr = Union[str, IStr]
LLStr = List[LStr]

DLDStr = Dict[str, LDStr]
