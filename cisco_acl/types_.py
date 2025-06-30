"""Typing."""

from ipaddress import IPv4Network, IPv4Address
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union

from netports import SwVersion

DAny = Dict[str, Any]
DInt = Dict[str, int]
DStr = Dict[str, str]
DiStr = Dict[int, str]
IInt = Iterable[int]
IStr = Iterable[str]
LAny = List[Any]
LBool = List[bool]
LInt = List[int]
LStr = List[str]
OBool = Optional[bool]
OInt = Optional[int]
OIpNet = Optional[IPv4Network]
OStr = Optional[str]
SInt = Set[int]
SStr = Set[str]
StrInt = Union[str, int]
T2IStr = Tuple[int, str]
T2Str = Tuple[str, str]
T3Str = Tuple[str, str, str]
TStr = Tuple[str, ...]
UIInt = Union[bytes, float, int, str, Iterable[Union[bytes, float, int, str]]]
UVersion = Union[SwVersion, str]

DDAny = Dict[str, DAny]
DLAny = Dict[str, LAny]
DLStr = Dict[str, LStr]
LDAny = List[DAny]
LDStr = List[DStr]
LIpNet = List[IPv4Network]
LLStr = List[LStr]
LOIpNet = List[OIpNet]
LStrInt = List[StrInt]
LT2IStr = List[T2IStr]
OLStr = Optional[LStr]
T2IpAddr = Tuple[IPv4Address, IPv4Address]
TLintInt = Tuple[LInt, int]
UStr = Union[str, IStr]

DDLStr = Dict[str, DLStr]
DLDStr = Dict[str, LDStr]

