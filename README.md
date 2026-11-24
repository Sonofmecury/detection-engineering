# Detection engineering library

Twenty inspectable detection rules, one pinned event contract and a replay suite. A small compiler translates an explicit subset of Sigma rules into parameterized SQLite queries and runs them on the events. Python 3.11+ with SQLite JSON support, no third-party dependencies.

```sh
python engine.py fixtures/evaluation.jsonl --benchmark
python engine.py fixtures/evaluation.jsonl > alerts.jsonl
python -m unittest discover -v
```

JSON rule files use the JSON subset of YAML. The backend supports one named selection, exact case-insensitive strings, logical AND within a selection, and an exact source discriminator. Wildcards, modifiers, correlation and arbitrary SigmaHQ rule packs are outside this backend’s contract. Convert vendor telemetry in a separate normalization step before replay.

Each event needs `source`, unique `id`, `entity`, ISO timestamp and the documented selection fields. The runner evaluates actual data fields. The benchmark separately compares matches with expected rule UUID labels and reports TP, FP, FN, TN, precision and recall. Non-benchmark mode emits one JSON line per alert for the [SOC response lab](https://github.com/Sonofmecury/soc-response-lab).

The supplied fixtures contain 40 labelled positive events and 60 benign or wrong-source examples. They intentionally isolate rule behavior and don’t estimate production false-positive rates. Treat ATT&CK tags as context where relevant. Operational tuning requires baseline log volume, telemetry field validation and review of real false positives. The narrow rule pack includes both behavior observations and telemetry health signals.
