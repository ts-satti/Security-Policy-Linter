import pytest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from policy_rule import PolicyRule
from security_linter import normalise_timeout_rule

def test_normalise_hours_to_minutes():
    rule = PolicyRule('session_timeout', 1.5, 'hours', '≤', 10, 'Timeout ≤ 1.5 hours.', False)
    norm = normalise_timeout_rule(rule)
    assert norm.value == 90.0
    assert norm.unit == 'minutes'
    assert norm.comparator == '≤'
    assert norm.line_number == 10
    assert norm.sentence == 'Timeout ≤ 1.5 hours.'
    assert norm.exception is False

def test_normalise_days_to_minutes():
    rule = PolicyRule('session_timeout', 2, 'days', '≥', 12, 'Timeout ≥ 2 days.', False)
    norm = normalise_timeout_rule(rule)
    assert norm.value == 2880.0
    assert norm.unit == 'minutes'
    assert norm.comparator == '≥'

def test_no_normalisation_needed_minutes():
    rule = PolicyRule('session_timeout', 30, 'minute', '=', 5, 'Timeout = 30 min.', False)
    norm = normalise_timeout_rule(rule)
    assert norm.value == 30.0
    assert norm.unit == 'minutes'
    assert norm.comparator == '='
    assert norm.line_number == 5
    assert norm.sentence == 'Timeout = 30 min.'
    assert norm.exception is False

def test_minutes_plural_and_singular():
    rule1 = PolicyRule('session_timeout', 45, 'minutes', '=', 1, 'Timeout = 45 minutes.', False)
    rule2 = PolicyRule('session_timeout', 45, 'minute', '=', 2, 'Timeout = 45 minute.', False)
    
    norm1 = normalise_timeout_rule(rule1)
    norm2 = normalise_timeout_rule(rule2)
    
    assert norm1.value == 45.0
    assert norm1.unit == 'minutes'
    
    assert norm2.value == 45.0
    assert norm2.unit == 'minutes'

def test_normalise_seconds_to_minutes():
    rule = PolicyRule('session_timeout', 120, 'seconds', '<', 1, 'Timeout < 120 sec.', False)
    norm = normalise_timeout_rule(rule)
    assert norm.value == 2.0
    assert norm.unit == 'minutes'
    assert norm.comparator == '<'

def test_fractional_days_to_minutes():
    rule = PolicyRule('session_timeout', 0.5, 'days', '≤', 3, 'Timeout ≤ 0.5 days.', False)
    norm = normalise_timeout_rule(rule)
    assert norm.value == 720.0  # 0.5 days * 24 hours/day * 60 minutes/hour
    assert norm.unit == 'minutes'

def test_zero_and_negative_values_rejected():
    with pytest.raises(ValueError, match="positive"):
        PolicyRule('session_timeout', 0, 'hours', '=', 1, 'Zero timeout')
    with pytest.raises(ValueError, match="positive"):
        PolicyRule('session_timeout', -1, 'days', '=', 1, 'Negative timeout')

def test_unknown_unit_passthrough():
    rule = PolicyRule('session_timeout', 1, 'weeks', '>', 1, 'Timeout > 1 week.', False)
    norm = normalise_timeout_rule(rule)
    assert norm is rule          # unchanged (or compare fields)
    assert norm.unit == 'weeks'
    assert norm.value == 1.0