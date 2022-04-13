"""Typing"""
from typing import (
    Dict,
    Iterable,
    List,
    Optional,
    Set,
    Union,
)

from netaddr import IPNetwork  # type: ignore

# basic
# DAny = Dict[str, Any]
# DInt = Dict[str, int]
# DiStr = Dict[int, str]
# IIter = Iterable[Iterable]
# LAny = List[Any]
# LBool = List[bool]
# LLStr = List[List[str]]
# LObj = List[object]
# LOrd = List[OrderedDict]
# LTInt = List[Tuple[int, ...]]
# LTuple = List[Tuple[str, object]]
# LUOrdS = List[Union[OrderedDict, str]]
# OAny = Optional[Any]
# OStr = Optional[str]
# Ord = OrderedDict
SStr = Set[str]
# TAny = Tuple[Any, ...]
# TStr = Tuple[str, ...]
# TStr2 = Tuple[str, str]
# TStr3 = Tuple[str, str, str]
# TStr6 = Tuple[str, str, str, str, str, str]
DStr = Dict[str, str]
IInt = Iterable[int]
IStr = Iterable[str]
LInt = List[int]
LStr = List[str]
OIPNetwork = Optional[IPNetwork]
OInt = Optional[int]
SInt = Set[int]
StrInt = Union[str, int]
UIInt = Union[bytes, float, int, str, Iterable[Union[bytes, float, int, str]]]

# two-level
# DDAny = Dict[str, DAny]
# DDInt = Dict[str, DInt]
# DDStr = Dict[str, DStr]
# DDiStr = Dict[str, DiStr]
# DLAny = Dict[str, LAny]
# DLStr = Dict[str, LStr]
# DSStr = Dict[str, SStr]
# DSet = Dict[str, SStr]
# DiDss = Dict[int, DStr]
# DiSet = Dict[int, SStr]
# Diff = Tuple[str, str, TStr]
# IDAny = Iterable[DAny]
# LDAny = List[DAny]
# LDiff = List[Diff]
# LLAny = List[LAny]
# LSStr = List[SStr]
# LTAny = List[TAny]
# LTStr = List[TStr]
# LTStr2 = List[TStr2]
# LTStr3 = List[TStr3]
# SDAny = Set[DAny]
# STStr2 = Set[TStr2]
# TBDAny = Tuple[bool, DAny]
# TOStr = Tuple[OStr, str]
# UInts = Union[int, str, IInt]
# ULDStr = Union[LStr, LDStr]
# ULStr = Union[LStr, str]
# UOLOrd = Union[OrderedDict, LOrd]
LDStr = List[DStr]
LStrInt = List[StrInt]

# multi-level
# DDDAny = Dict[str, DDAny]
# DDDInt = Dict[str, DDInt]
# DDiDStr = Dict[str, DiDss]
# DLDAny = Dict[str, LDAny]
# DLDStr = Dict[str, LDStr]
# LTBDAny = List[TBDAny]
# UDAny = Union[DAny, LDAny]
UStr = Union[str, IStr]
