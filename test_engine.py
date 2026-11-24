import copy
from pathlib import Path
import unittest

from engine import benchmark, compile_rule, load_rules, read_events, run


class DetectionTest(unittest.TestCase):
    def setUp(self):
        self.rules = load_rules()
        self.events = read_events(Path(__file__).parent / "fixtures" / "evaluation.jsonl")

    def test_20_rules_on_100_fixtures(self):
        result = benchmark(self.events, self.rules)
        self.assertEqual(len(self.events), 100)
        self.assertEqual(len(result), 20)
        for row in result:
            with self.subTest(rule=row["rule"]):
                self.assertEqual((row["tp"], row["fp"], row["fn"], row["tn"]), (2, 0, 0, 98))

    def test_id_must_be_unique(self):
        with self.assertRaises(ValueError):
            run([self.events[0]] * 2, self.rules)

    def test_rejects_unsupported_operators(self):
        rule = copy.deepcopy(self.rules[0])
        rule["detection"]["selection"]["activity"] = "una*"
        with self.assertRaises(ValueError):
            compile_rule(rule)

    def test_query_executes_and_does_not_rely_on_label(self):
        clean = [{k: v for k, v in e.items() if k != "expected_rule"} for e in self.events]
        self.assertEqual(len(run(clean, self.rules)), 40)
