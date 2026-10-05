"""Opt-in real CIC-IDS2017 Parquet preparation smoke test.

Set INTRIQO_RUN_REAL_CICIDS2017=1 and optionally INTRIQO_CICIDS2017_ROOT and
INTRIQO_CICIDS2017_OUTPUT. This is deliberately excluded from normal CI.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from intriqo_ml.datasets import load_config, prepare_dataset


@pytest.mark.skipif(
    os.environ.get("INTRIQO_RUN_REAL_CICIDS2017") != "1",
    reason="opt-in real external CIC-IDS2017 dataset smoke test",
)
def test_real_cicids2017_parquet_preparation() -> None:
    root = Path(os.environ.get(
        "INTRIQO_CICIDS2017_ROOT",
        "/run/media/rayan/Workspace/08_Datasets/cicids2017/machine_learning",
    ))
    output = Path(os.environ.get(
        "INTRIQO_CICIDS2017_OUTPUT",
        "/run/media/rayan/Workspace/08_Datasets/cicids2017/prepared/intriqo-cicids2017-smoke",
    ))
    config_path = Path(__file__).resolve().parents[2] / "configs/datasets/cicids2017-dev.json"
    result = prepare_dataset(load_config(config_path), root, output, force=True)
    assert result.manifest["model_implementation"] is None
    assert result.manifest["selected_files"][0]["format"] == "parquet"
    assert result.manifest["counts"]["valid_rows"] > 0
