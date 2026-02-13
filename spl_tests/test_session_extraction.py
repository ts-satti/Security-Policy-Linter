import pytest
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from security_linter import extract_session_timeout_rules

class TestSessionTimeoutExtraction:

    def test_expires_after_minutes(self):
        rules = extract_session_timeout_rules("The session expires after 15 minutes.", 5)
        assert len(rules) == 1
        r = rules[0]
        assert r.value == 15.0
        assert r.unit == 'minute'
        assert r.comparator == '≤'

    def test_timeout_is_hours(self):
        rules = extract_session_timeout_rules("Session timeout is 2 hours.", 7)
        assert len(rules) == 1
        r = rules[0]
        assert r.value == 2.0
        assert r.unit == 'hour'
        assert r.comparator == '='

    def test_decimal_days(self):
        rules = extract_session_timeout_rules("Maximum session lifetime of 0.5 days.", 10)
        assert len(rules) == 1
        r = rules[0]
        assert r.value == 0.5
        assert r.unit == 'day'
        assert r.comparator == '≤'

    def test_idle_terminated(self):
        rules = extract_session_timeout_rules("Idle session terminated after 30 minutes.", 12)
        assert len(rules) == 1
        r = rules[0]
        assert r.value == 30.0
        assert r.unit == 'minute'
        assert r.comparator == '≤'

    def test_logged_out(self):
        rules = extract_session_timeout_rules("Users are logged out after 1 hour of inactivity.", 15)
        assert len(rules) == 1
        r = rules[0]
        assert r.value == 1.0
        assert r.unit == 'hour'
        assert r.comparator == '≤'

    def test_no_match(self):
        rules = extract_session_timeout_rules("This sentence has no timeout rule.", 20)
        assert len(rules) == 0

    # ---------- NEW TESTS (ALL WITH self) ----------
    def test_timeout_less_than(self):
        rules = extract_session_timeout_rules("Session must expire in less than 30 minutes.", 25)
        assert len(rules) == 1
        r = rules[0]
        assert r.comparator == '<'
        assert r.value == 30.0
        assert r.unit == 'minute'

    def test_timeout_greater_than(self):
        rules = extract_session_timeout_rules("Session should last more than 1 hour.", 26)
        assert len(rules) == 1
        r = rules[0]
        assert r.comparator == '>'
        assert r.value == 1.0
        assert r.unit == 'hour'

    def test_timeout_range(self):
        rules = extract_session_timeout_rules(
            "Session timeout must be at least 15 minutes but no more than 30 minutes.", 30
        )
        assert len(rules) == 2
        assert rules[0].comparator == '≥'
        assert rules[0].value == 15.0
        assert rules[1].comparator == '≤'
        assert rules[1].value == 30.0

    def test_mixed_units_in_sentence(self):
        s1 = "Timeout is 1 hour for admins."
        s2 = "Timeout is 45 minutes for users."
        rules1 = extract_session_timeout_rules(s1, 35)
        rules2 = extract_session_timeout_rules(s2, 36)
        all_rules = rules1 + rules2
        assert len(all_rules) == 2
        assert {r.unit for r in all_rules} == {'hour', 'minute'}

    def test_abbreviated_units(self):
        rules = extract_session_timeout_rules("Session expires after 30 mins.", 40)
        assert len(rules) == 1
        r = rules[0]
        assert r.unit == 'minute'
        assert r.value == 30.0

    def test_multiple_rules_in_text(self):
        s1 = "Idle timeout is 15 minutes."
        s2 = "Maximum session lifetime is 0.5 days."
        rules1 = extract_session_timeout_rules(s1, 45)
        rules2 = extract_session_timeout_rules(s2, 46)
        all_rules = rules1 + rules2
        assert len(all_rules) == 2
        assert {r.unit for r in all_rules} == {'minute', 'day'}

    def test_non_numeric_timeout(self):
        rules = extract_session_timeout_rules("Sessions expire quickly.", 50)
        assert len(rules) == 0

    def test_exception_in_sentence(self):
        s = "Session timeout is 30 minutes, except for privileged accounts."
        rules = extract_session_timeout_rules(s, 55)
        assert len(rules) == 1
        assert rules[0].exception is True

    def test_zero_timeout(self):
        s = "Session timeout is 0 minutes."
        rules = extract_session_timeout_rules(s, 55)
        assert len(rules) == 0

    def test_case_and_spaces(self):
        rules = extract_session_timeout_rules("SESSION Expires AFTER  30  MINUTES.", 60)
        assert len(rules) == 1
        r = rules[0]
        assert r.value == 30.0
        assert r.unit == 'minute'

    def test_contradictory_rules_in_same_sentence(self):
        s = "Session timeout must be at least 15 minutes but no more than 30 minutes."
        rules = extract_session_timeout_rules(s, 70)
        assert len(rules) == 2
        assert rules[0].comparator == '≥'
        assert rules[0].value == 15.0
        assert rules[1].comparator == '≤'
        assert rules[1].value == 30.0