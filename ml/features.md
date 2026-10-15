# Feature Dictionary

All features are computed at **session-event window** granularity (one row per event, with cumulative / trailing-window aggregates).  
Derived during `ml/generate_synthetic.py` for synthetic data and (later) mirrored by the live feature extractor in Phase 7.

| Feature | Type | Derivation |
|---------|------|------------|
| `failed_login_count` | int | Cumulative auth failures in the session so far |
| `requests_per_minute` | float | Count of events in the trailing 5 minutes / 5 |
| `resource_sensitivity_mean` | float | Mean sensitivity (1–5) of resources touched so far |
| `resource_sensitivity_max` | int | Max sensitivity so far |
| `device_trusted` | binary | Session device trust flag (0/1) |
| `minutes_since_auth` | float | Minutes since session start / auth |
| `access_frequency` | float | Event count / session duration minutes |
| `unusual_context` | binary | Unexpected access context indicator (simulated) |
| `session_duration_minutes` | float | Elapsed session time |
| `distinct_resources` | int | Distinct successful resource names so far |
| `behavioral_deviation` | float | Z-like deviation of request rate vs user baseline (+ noise) |
| `hour_of_day` | int | 0–23 |
| `is_off_hours` | binary | 1 if hour < 6 or ≥ 22 |
| `failed_auth_ratio` | float | `failed_login_count / event_index+1` |
| `sensitive_access_ratio` | float | Fraction of events with sensitivity ≥ 4 |
| `event_burst_score` | float | CV of recent inter-arrival gaps |
| `event_index` | int | 0-based position in session (sequence order) |

## Label

| Column | Meaning |
|--------|---------|
| `label_suspicious` | 1 = suspicious window; 0 = normal |

Labeling uses a **latent multi-factor composite** during generation (not stored as a feature). No single column is a deterministic copy of the label.

## Leakage controls

- Splits are performed by `session_id` (and users do not straddle splits when using the group splitter).
- Scaler / encoding statistics fit on **training sessions only**.
- `session_is_suspicious_scenario` and `has_behavioral_drift` are **metadata**, not model inputs.
