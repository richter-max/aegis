"""Bench config loading and validation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis.config import load_bench_config
from aegis.scenarios import corpus


def _write(tmp_path: Path, data: dict) -> Path:
    path = tmp_path / "cfg.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_all_selects_whole_corpus(tmp_path: Path) -> None:
    cfg = load_bench_config(_write(tmp_path, {"scenarios": "all"}))
    assert cfg.scenarios == corpus.all_names()


def test_explicit_list_is_preserved(tmp_path: Path) -> None:
    cfg = load_bench_config(_write(tmp_path, {"scenarios": ["indirect_injection_01"]}))
    assert cfg.scenarios == ["indirect_injection_01"]


def test_filter_object_is_applied(tmp_path: Path) -> None:
    cfg = load_bench_config(
        _write(tmp_path, {"scenarios": {"tiers": ["evasive"], "include_benign": False}})
    )
    assert cfg.scenarios
    assert all(corpus.get_scenario(n).tier == "evasive" for n in cfg.scenarios)


def test_defaults_cover_all_policies_and_guards(tmp_path: Path) -> None:
    cfg = load_bench_config(_write(tmp_path, {"scenarios": "all"}))
    assert cfg.policies == ["strict", "permissive"]
    assert cfg.guards == ["none", "keywords", "semantic", "layered"]


def test_singular_guard_key_still_accepted(tmp_path: Path) -> None:
    cfg = load_bench_config(_write(tmp_path, {"scenarios": "all", "guard": "layered"}))
    assert cfg.guards == ["layered"]


def test_unknown_scenario_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Unknown scenarios"):
        load_bench_config(_write(tmp_path, {"scenarios": ["nope"]}))


def test_unknown_guard_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Unknown guard"):
        load_bench_config(_write(tmp_path, {"scenarios": "all", "guards": ["magic"]}))


def test_unknown_policy_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Unknown policy"):
        load_bench_config(_write(tmp_path, {"scenarios": "all", "policies": ["yolo"]}))


def test_empty_selection_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="zero scenarios"):
        load_bench_config(_write(tmp_path, {"scenarios": {"families": ["nonexistent"]}}))


def test_shipped_configs_all_load() -> None:
    for path in sorted(Path("configs/experiments").glob("*.json")):
        cfg = load_bench_config(path)
        assert cfg.scenarios, path.name
