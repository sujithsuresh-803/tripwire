import copy
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
_POLICY = yaml.safe_load((ROOT / "policy/policy.yaml").read_text(encoding="utf-8"))


@pytest.fixture
def policy():
    return copy.deepcopy(_POLICY)


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


@pytest.fixture
def clock():
    return Clock()
