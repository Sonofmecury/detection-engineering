"""Run a documented subset of Sigma equality detections on SQLite."""
import argparse
import json
import re
import sqlite3
from pathlib import Path

FIELDS = {"activity", "outcome", "signature", "identity_type"}
RULE_DIR = Path(__file__).with_name("rules")


def load_rules(directory=RULE_DIR):
    rules = [json.loads(path.read_text(encoding="utf-8")) for path in sorted(directory.glob("*.yml"))]
    ids = [rule["id"] for rule in rules]
    if not ids or len(ids) != len(set(ids)):
        raise ValueError("A rule pack must contain unique rule IDs")
    return rules


def compile_rule(rule):
    detection = rule["detection"]
    if set(detection) != {"selection", "condition"} or detection["condition"] != "selection":
        raise ValueError("Only a single explicit selection condition is supported")
    selection = detection["selection"]
    if not isinstance(selection, dict) or not selection or set(selection) - FIELDS:
        raise ValueError("Selection references unsupported or missing fields")
    source = rule["logsource"]["product"]
    if not re.fullmatch(r"[a-z][a-z0-9_]*", source):
        raise ValueError("Invalid event source")
    clauses = ["source = ?"]
    parameters = [source]
    for field, value in sorted(selection.items()):
        if not isinstance(value, str) or any(c in value for c in "*?\\"):
            raise ValueError("Only plain exact string values are supported")
        clauses.append("lower(json_extract(payload, ?)) = lower(?)")
        parameters.extend(["$." + field, value])
    return "SELECT event_index FROM events WHERE " + " AND ".join(clauses) + " ORDER BY event_index", parameters


def read_events(path):
    with path.open(encoding="utf-8-sig") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def run(events, rules):
    for event in events:
        if not isinstance(event, dict) or not all(isinstance(event.get(key), str) and event[key]
                                                for key in ("source", "id", "entity", "timestamp")):
            raise ValueError("Every event needs source, id, entity and timestamp")
    if len({event["id"] for event in events}) != len(events):
        raise ValueError("An event replay requires unique IDs")
    matches = []
    with sqlite3.connect(":memory:") as conn:
        conn.execute("CREATE TABLE events(event_index INTEGER PRIMARY KEY, source TEXT NOT NULL, payload TEXT NOT NULL)")
        conn.executemany("INSERT INTO events VALUES (?, ?, ?)",
                         ((index, event["source"], json.dumps(event)) for index, event in enumerate(events)))
        for rule in rules:
            query, values = compile_rule(rule)
            for (index,) in conn.execute(query, values):
                event = events[index]
                matches.append({"id": rule["id"] + ":" + event["id"], "event_id": event["id"],
                                "rule": rule["id"], "timestamp": event["timestamp"],
                                "entity": event["entity"], "severity": rule["level"],
                                "source": event["source"], "activity": event["activity"]})
    return sorted(matches, key=lambda row: (row["timestamp"], row["id"]))


def benchmark(events, rules):
    actual = {(row["rule"], row["event_id"]) for row in run(events, rules)}
    by_id = {}
    for event in events:
        label = event.get("expected_rule")
        if not isinstance(label, list):
            raise ValueError("Missing expected_rule list in evaluation event")
        by_id[event["id"]] = set(label)
    known = {rule["id"] for rule in rules}
    if set().union(*by_id.values()) - known:
        raise ValueError("Fixture labels reference unknown rules")
    report = []
    for rule in sorted(known):
        expected = {event_id for event_id, rules in by_id.items() if rule in rules}
        observed = {event_id for rule_id, event_id in actual if rule_id == rule}
        tp, fp, fn = len(expected & observed), len(observed - expected), len(expected - observed)
        report.append({"rule": rule, "tp": tp, "fp": fp, "fn": fn,
                       "tn": len(events) - len(expected | observed),
                       "precision": tp / (tp + fp) if tp + fp else None,
                       "recall": tp / (tp + fn) if tp + fn else None})
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events", type=Path)
    parser.add_argument("--benchmark", action="store_true")
    args = parser.parse_args()
    events, rules = read_events(args.events), load_rules()
    if args.benchmark:
        results = benchmark(events, rules)
        print(json.dumps(results, indent=2))
        raise SystemExit(any(row["fp"] or row["fn"] for row in results))
    for match in run(events, rules):
        print(json.dumps(match, sort_keys=True))


if __name__ == "__main__":
    main()
