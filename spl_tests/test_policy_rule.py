import os
import sys
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from policy_rule import PolicyRule, SUBJECTS

class TestPolicyRule:
    """Test suite for PolicyRule validation and behavior."""

    def test_valid_rule(self):
        rule = PolicyRule(
            subject='password_min_length',
            value=8.0,
            unit='characters',
            comparator='≥',
            line_number=42,
            sentence='Passwords must be at least 8 characters.',
            exception=False
        )
        assert rule.subject == 'password_min_length'
        assert rule.value == 8.0
        assert rule.unit == 'characters'
        assert rule.comparator == '≥'
        assert rule.line_number == 42
        assert rule.sentence == 'Passwords must be at least 8 characters.'
        assert rule.exception is False

    def test_invalid_subject(self):
        with pytest.raises(ValueError, match="subject must be one of"):
            PolicyRule(
                subject='not_a_valid_subject',
                value=8.0,
                unit='characters',
                comparator='≥',
                line_number=42,
                sentence='...'
            )

    def test_negative_value(self):
        with pytest.raises(ValueError, match="positive"):
            PolicyRule(
                subject='password_min_length',
                value=-5.0,
                unit='characters',
                comparator='≥',
                line_number=42,
                sentence='...'
            )

    def test_zero_value(self):
        with pytest.raises(ValueError, match="positive"):
            PolicyRule(
                subject='password_min_length',
                value=0.0,
                unit='characters',
                comparator='≥',
                line_number=42,
                sentence='...'
            )

    def test_non_numeric_value(self):
        with pytest.raises(ValueError, match="numeric"):
            PolicyRule(
                subject='password_min_length',
                value="eight",
                unit='characters',
                comparator='≥',
                line_number=42,
                sentence='...'
            )

    def test_empty_unit(self):
        with pytest.raises(ValueError, match="non-empty"):
            PolicyRule(
                subject='password_min_length',
                value=8.0,
                unit='   ',
                comparator='≥',
                line_number=42,
                sentence='...'
            )

    def test_invalid_comparator(self):
        with pytest.raises(ValueError, match="invalid comparator"):
            PolicyRule(
                subject='password_min_length',
                value=8.0,
                unit='characters',
                comparator='!=',
                line_number=42,
                sentence='...'
            )

    def test_line_number_zero(self):
        with pytest.raises(ValueError, match="positive integer"):
            PolicyRule(
                subject='password_min_length',
                value=8.0,
                unit='characters',
                comparator='≥',
                line_number=0,
                sentence='...'
            )

    def test_line_number_negative(self):
        with pytest.raises(ValueError, match="positive integer"):
            PolicyRule(
                subject='password_min_length',
                value=8.0,
                unit='characters',
                comparator='≥',
                line_number=-3,
                sentence='...'
            )

    def test_empty_sentence(self):
        with pytest.raises(ValueError, match="non-empty"):
            PolicyRule(
                subject='password_min_length',
                value=8.0,
                unit='characters',
                comparator='≥',
                line_number=42,
                sentence='   '
            )

    def test_exception_default_false(self):
        rule = PolicyRule(
            subject='password_min_length',
            value=8.0,
            unit='characters',
            comparator='≥',
            line_number=42,
            sentence='Passwords must be at least 8 characters.'
        )
        assert rule.exception is False

    def test_exception_true(self):
        rule = PolicyRule(
            subject='password_min_length',
            value=8.0,
            unit='characters',
            comparator='≥',
            line_number=42,
            sentence='...',
            exception=True
        )
        assert rule.exception is True

    # ----- NEW TESTS (with self added) -----
    def test_large_value(self):
        rule = PolicyRule(
            subject='password_min_length',
            value=1e6,
            unit='characters',
            comparator='≥',
            line_number=42,
            sentence='Huge password length is allowed.'
        )
        assert rule.value == 1e6

    def test_whitespace_stripping(self):
        """Whitespace is automatically stripped from subject, unit, sentence."""
        rule = PolicyRule(
            subject='  password_min_length  ',
            value=8.0,
            unit=' characters ',
            comparator='≥',
            line_number=42,
            sentence='  Must be 8 chars.  '
        )
        assert rule.subject == 'password_min_length'
        assert rule.unit == 'characters'
        assert rule.sentence == 'Must be 8 chars.'

    def test_comparator_case(self):
        """Comparator must be exactly one of the approved literals."""
        with pytest.raises(ValueError, match="invalid comparator"):
            PolicyRule(
                subject='password_min_length',
                value=8.0,
                unit='characters',
                comparator='>=',          # invalid – must be '≥'
                line_number=42,
                sentence='...'
            )

    def test_exception_non_boolean(self):
        """exception must be a boolean."""
        with pytest.raises(ValueError, match="exception must be bool"):
            PolicyRule(
                subject='password_min_length',
                value=8.0,
                unit='characters',
                comparator='≥',
                line_number=42,
                sentence='...',
                exception="yes"          # invalid
            )

    def test_multiple_invalid_fields(self):
        """Multiple errors – the first detected validation error is raised."""
        with pytest.raises(ValueError):
            PolicyRule(
                subject='invalid_subject',
                value=-1,
                unit='',
                comparator='!=',
                line_number=-10,
                sentence='   '
            )
