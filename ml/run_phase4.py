"""Orchestrate Phase 4: generate → preprocess → rule baseline evaluation."""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Allow `python ml/run_phase4.py` from repo root.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.config import ARTIFACTS, DATA_PROCESSED, DATA_RAW, RANDOM_SEED  # noqa: E402
from ml.evaluate_baseline import main as eval_main  # noqa: E402
from ml.generate_synthetic import GeneratorConfig, generate_dataset, save_dataset  # noqa: E402
from ml.preprocess import run_preprocess  # noqa: E402


def run() -> None:
    print("=== Phase 4.1 Generate synthetic dataset ===")
    events, sessions, meta = generate_dataset(GeneratorConfig(seed=RANDOM_SEED))
    save_dataset(events, sessions, meta, DATA_RAW)

    print("\n=== Phase 4.2 Preprocess & split ===")
    report = run_preprocess(DATA_RAW / "session_events.csv", DATA_PROCESSED, seed=RANDOM_SEED)
    print(json.dumps(report["imbalance"]["all"], indent=2))

    print("\n=== Phase 4.3 Rule-based baseline ===")
    # Reuse CLI entry by setting argv defaults.
    sys.argv = ["evaluate_baseline.py"]
    eval_main()

    summary = {
        "phase": 4,
        "status": "complete",
        "raw_dir": str(DATA_RAW),
        "processed_dir": str(DATA_PROCESSED),
        "artifacts_dir": str(ARTIFACTS / "baseline"),
        "disclaimer": meta["disclaimer"],
    }
    out = ARTIFACTS / "phase4_summary.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"\nPhase 4 summary -> {out}")


if __name__ == "__main__":
    run()
