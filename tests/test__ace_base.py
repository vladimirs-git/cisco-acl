"""Unittest ace_base.py"""
from typing import Any

import pytest

from cisco_acl import Ace, AceGroup, Remark
from tests.helpers_test import PERMIT_IP, REMARK

SEQUENCES = [
    ("", 0),
    ("0", 0),
    ("1", 1),
    (0, 0),
    (1, 1),
    (-1, ValueError),
    ("a", ValueError),
    ("-1", ValueError),
]


@pytest.mark.parametrize("sequence, expected", SEQUENCES)
def test_valid__remark__sequence(sequence, expected: Any):
    """Remark.sequence"""
    for platform in ["ios", "nxos"]:
        if isinstance(expected, int):
            obj = Remark(f"{sequence} {REMARK}", platform=platform)
            actual = obj.sequence
            assert actual == expected

            # setter
            obj.sequence = sequence
            actual = obj.sequence
            assert actual == expected

        else:
            with pytest.raises(expected):
                Remark(f"{sequence} {REMARK}", platform=platform)

            # setter
            obj = Remark(REMARK, platform=platform)
            with pytest.raises(expected):
                obj.sequence = sequence


@pytest.mark.parametrize("sequence, expected", SEQUENCES)
def test_valid__ace__sequence(sequence, expected):
    """Ace.sequence"""
    for platform in ["ios", "nxos"]:
        if isinstance(expected, int):
            obj = Ace(f"{sequence} {PERMIT_IP}", platform=platform)
            actual = obj.sequence
            assert actual == expected

            # setter
            obj.sequence = sequence
            actual = obj.sequence
            assert actual == expected

        else:
            with pytest.raises(expected):
                Ace(f"{sequence} {PERMIT_IP}", platform=platform)

            # setter
            obj = Ace(PERMIT_IP, platform=platform)
            with pytest.raises(expected):
                obj.sequence = sequence


@pytest.mark.parametrize("sequence, expected", SEQUENCES)
def test_valid__ace_group__sequence(sequence, expected):
    """AceGroup.sequence"""
    for platform in ["ios", "nxos"]:
        if isinstance(expected, int):
            obj = AceGroup(f"{sequence} {REMARK}\n{PERMIT_IP}", platform=platform)
            actual = obj.sequence
            assert actual == expected

            # setter
            obj.sequence = sequence
            actual = obj.sequence
            assert actual == expected

        else:
            obj = AceGroup(f"{sequence} {REMARK}\n{sequence} {PERMIT_IP}", platform=platform)
            actual = obj.sequence
            assert actual == 0

            # setter
            obj = AceGroup(f"{REMARK}\n{PERMIT_IP}", platform=platform)
            with pytest.raises(expected):
                obj.sequence = sequence
