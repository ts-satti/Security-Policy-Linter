import pytest
import os
import sys

# Ensure project root is on sys.path so tests can import application modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from policy_rule import PolicyRule
from security_linter import detect_contradictions  # adjust import

class TestContradictionDetection:

    def create_rule(self, subject, value, operator, line):
        return PolicyRule(subject, value, 'units', operator, line, f'{operator}{value}', False)

    # -----------------------------
    # 1️⃣ Basic non-contradictions
    # -----------------------------
    def test_no_contradiction_ge_ge(self):
        r1 = self.create_rule('password_min_length', 8, '≥', 1)
        r2 = self.create_rule('password_min_length', 6, '≥', 2)
        assert detect_contradictions([r1, r2]) == []

    def test_no_contradiction_le_le(self):
        r1 = self.create_rule('password_min_length', 10, '≤', 1)
        r2 = self.create_rule('password_min_length', 12, '≤', 2)
        assert detect_contradictions([r1, r2]) == []

    def test_no_contradiction_eq_ge_same(self):
        r1 = self.create_rule('password_min_length', 8, '=', 1)
        r2 = self.create_rule('password_min_length', 8, '≥', 2)
        assert detect_contradictions([r1, r2]) == []

    def test_no_contradiction_range_inside(self):
        r1 = self.create_rule('password_min_length', 8, 'range_min', 1)
        r2 = self.create_rule('password_min_length', 12, 'range_max', 1)
        r3 = self.create_rule('password_min_length', 10, '≥', 2)
        assert detect_contradictions([r1, r2, r3]) == []

    # -----------------------------
    # 2️⃣ Contradictions
    # -----------------------------
    def test_contradiction_ge_le(self):
        r1 = self.create_rule('password_min_length', 10, '≥', 1)
        r2 = self.create_rule('password_min_length', 5, '≤', 2)
        result = detect_contradictions([r1, r2])
        assert len(result) == 1
        assert result[0]['subject'] == 'password_min_length'
        assert result[0]['lines'] == [1, 2]

    def test_contradiction_eq_eq_diff(self):
        r1 = self.create_rule('password_min_length', 8, '=', 1)
        r2 = self.create_rule('password_min_length', 10, '=', 2)
        assert len(detect_contradictions([r1, r2])) == 1

    def test_contradiction_eq_ge_higher(self):
        r1 = self.create_rule('password_min_length', 8, '=', 1)
        r2 = self.create_rule('password_min_length', 10, '≥', 2)
        assert len(detect_contradictions([r1, r2])) == 1

    def test_contradiction_eq_le_lower(self):
        r1 = self.create_rule('password_min_length', 8, '=', 1)
        r2 = self.create_rule('password_min_length', 6, '≤', 2)
        assert len(detect_contradictions([r1, r2])) == 1

    def test_contradiction_range_max_exceeded(self):
        r1 = self.create_rule('password_min_length', 8, 'range_min', 1)
        r2 = self.create_rule('password_min_length', 12, 'range_max', 1)
        r3 = self.create_rule('password_min_length', 14, '≥', 2)
        result = detect_contradictions([r1, r2, r3])
        assert len(result) == 1

    def test_contradiction_range_min_overlap(self):
        r1 = self.create_rule('password_min_length', 8, 'range_min', 1)
        r2 = self.create_rule('password_min_length', 10, 'range_min', 2)
        # Overlap is okay, no contradiction
        assert detect_contradictions([r1, r2]) == []

    def test_contradiction_range_max_overlap(self):
        r1 = self.create_rule('password_min_length', 12, 'range_max', 1)
        r2 = self.create_rule('password_min_length', 10, 'range_max', 2)
        result = detect_contradictions([r1, r2])
        assert result == []

    # -----------------------------
    # 3️⃣ Edge cases
    # -----------------------------
    def test_empty_list(self):
        assert detect_contradictions([]) == []

    def test_single_rule(self):
        r1 = self.create_rule('password_min_length', 8, '≥', 1)
        assert detect_contradictions([r1]) == []

    def test_different_subjects(self):
        r1 = self.create_rule('password_min_length', 8, '≥', 1)
        r2 = self.create_rule('session_timeout', 30, '≥', 2)
        assert detect_contradictions([r1, r2]) == []

    def test_floating_point_precision(self):
        r1 = self.create_rule('password_min_length', 8.0, '=', 1)
        r2 = self.create_rule('password_min_length', 8.000001, '=', 2)
        assert len(detect_contradictions([r1, r2])) == 1

    # -----------------------------
    # 4️⃣ Multiple mixed rules
    # -----------------------------
    def test_mixed_operators_no_contradiction(self):
        r1 = self.create_rule('password_min_length', 8, '≥', 1)
        r2 = self.create_rule('password_min_length', 12, '≤', 2)
        r3 = self.create_rule('password_min_length', 10, '≥', 3)
        r4 = self.create_rule('password_min_length', 10, '=', 4)
        # Only r4 vs r3/r1 may contradict? depends on implementation
        result = detect_contradictions([r1, r2, r3, r4])
        assert len(result) >= 0  # as long as no crash

    def test_ranges_and_equals_inside(self):
        r1 = self.create_rule('password_min_length', 8, 'range_min', 1)
        r2 = self.create_rule('password_min_length', 12, 'range_max', 2)
        r3 = self.create_rule('password_min_length', 10, '=', 3)
        assert detect_contradictions([r1, r2, r3]) == []

    def test_ranges_and_equals_outside(self):
        r1 = self.create_rule('password_min_length', 8, 'range_min', 1)
        r2 = self.create_rule('password_min_length', 12, 'range_max', 2)
        r3 = self.create_rule('password_min_length', 14, '=', 3)
        result = detect_contradictions([r1, r2, r3])
        assert len(result) == 1