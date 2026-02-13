import pytest
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from security_linter import detect_contradictions, extract_session_timeout_rules

def test_session_contradiction_mixed_units():
    rules = []
    rules.extend(extract_session_timeout_rules("Session timeout is 1 hour.", 1))
    rules.extend(extract_session_timeout_rules("Session timeout is 30 minutes.", 2))
    contradictions = detect_contradictions(rules)
    assert len(contradictions) == 1
    c = contradictions[0]
    assert c['subject'] == 'session_timeout'
    assert c['lines'] == [1, 2]
    assert c['values'] == [1.0, 30.0]
    assert c['units'] == ['hour', 'minute']
    assert c['comparators'] == ['=', '=']

def test_session_contradiction_same_unit():
    rules = []
    rules.extend(extract_session_timeout_rules("Session timeout is 10 minutes.", 1))
    rules.extend(extract_session_timeout_rules("Session timeout is 20 minutes.", 2))
    contradictions = detect_contradictions(rules)
    assert len(contradictions) == 1
    c = contradictions[0]
    assert c['subject'] == 'session_timeout'
    assert c['lines'] == [1, 2]
    assert c['values'] == [10.0, 20.0]
    assert c['units'] == ['minute', 'minute']

def test_session_contradiction_three_rules():
    """Three contradictory exact rules → three pairwise contradictions."""
    rules = []
    rules.extend(extract_session_timeout_rules("Session timeout is 1 hour.", 1))    # 60 min
    rules.extend(extract_session_timeout_rules("Session timeout is 30 minutes.", 2)) # 30 min
    rules.extend(extract_session_timeout_rules("Session timeout is 45 minutes.", 3)) # 45 min
    contradictions = detect_contradictions(rules)
    assert len(contradictions) == 3  # (1,2), (1,3), (2,3)
    # Optionally, check that each pair appears
    line_pairs = {(c['lines'][0], c['lines'][1]) for c in contradictions}
    assert line_pairs == {(1,2), (1,3), (2,3)}

def test_session_contradiction_with_comparators():
    rules = []
    rules.extend(extract_session_timeout_rules("Session timeout ≤ 1 hour.", 1))
    rules.extend(extract_session_timeout_rules("Session timeout ≥ 90 minutes.", 2))
    contradictions = detect_contradictions(rules)
    assert len(contradictions) == 1
    c = contradictions[0]
    assert c['comparators'] == ['≤', '≥']

def test_session_no_contradiction():
    rules = []
    rules.extend(extract_session_timeout_rules("Session timeout ≤ 1 hour.", 1))
    rules.extend(extract_session_timeout_rules("Session timeout ≤ 60 minutes.", 2))
    contradictions = detect_contradictions(rules)
    assert contradictions == []

def test_session_mixed_invalid_units():
    """Now seconds are supported; 1 hour (60 min) vs 90 seconds (1.5 min) → contradiction."""
    rules = []
    rules.extend(extract_session_timeout_rules("Session timeout is 1 hour.", 1))
    rules.extend(extract_session_timeout_rules("Session timeout is 90 seconds.", 2))
    contradictions = detect_contradictions(rules)
    assert len(contradictions) == 1
    c = contradictions[0]
    assert c['values'] == [1.0, 90.0]
    assert c['units'] == ['hour', 'second']

def test_session_single_rule():
    rules = extract_session_timeout_rules("Session timeout is 30 minutes.", 1)
    contradictions = detect_contradictions(rules)
    assert contradictions == []