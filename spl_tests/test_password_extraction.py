import os
import sys
import pytest

# Ensure project root is on sys.path so tests can import application modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from policy_rule import PolicyRule
from security_linter import extract_password_min_length_rules  # adjust import

class TestPasswordMinLengthExtraction:

    # ------------------ MINIMUM LENGTH PATTERNS ------------------
    def test_at_least_pattern(self):
        sentence = "Passwords must be at least 8 characters."
        rules = extract_password_min_length_rules(sentence, 10)
        assert len(rules) == 1
        rule = rules[0]
        assert rule.subject == 'password_min_length'
        assert rule.value == 8.0
        assert rule.comparator == '≥'
        assert rule.unit == 'characters'
        assert rule.line_number == 10
        assert rule.sentence == sentence
        assert rule.exception is False

    def test_minimum_of_pattern(self):
        sentence = "Minimum password length of 12."
        rules = extract_password_min_length_rules(sentence, 5)
        assert len(rules) == 1
        assert rules[0].value == 12.0
        assert rules[0].comparator == '≥'

    def test_no_fewer_than(self):
        sentence = "Passwords must contain no fewer than 16 characters."
        rules = extract_password_min_length_rules(sentence, 9)
        assert len(rules) == 1
        assert rules[0].value == 16.0
        assert rules[0].comparator == '≥'

    def test_min_words(self):
        sentence = "Passwords must be at least eight characters."
        rules = extract_password_min_length_rules(sentence, 1)
        assert len(rules) == 1
        assert rules[0].value == 8.0
        assert rules[0].comparator == '≥'

    def test_min_phrase_variation(self):
        sentence = "Passwords should have a minimum of 10 characters."
        rules = extract_password_min_length_rules(sentence, 1)
        assert len(rules) == 1
        assert rules[0].value == 10.0
        assert rules[0].comparator == '≥'

    # ------------------ MAXIMUM LENGTH PATTERNS ------------------
    def test_at_most_pattern(self):
        sentence = "Passwords must be at most 6 characters."
        rules = extract_password_min_length_rules(sentence, 2)
        assert len(rules) == 1
        assert rules[0].value == 6.0
        assert rules[0].comparator == '≤'

    def test_must_be_at_most(self):
        sentence = "Passwords must be at most 6 characters."
        rules = extract_password_min_length_rules(sentence, 2)
        assert len(rules) == 1
        rule = rules[0]
        assert rule.value == 6.0
        assert rule.comparator == '≤'

    def test_maximum_of_pattern(self):
        sentence = "Maximum password length of 12."
        rules = extract_password_min_length_rules(sentence, 3)
        assert len(rules) == 1
        assert rules[0].value == 12.0
        assert rules[0].comparator == '≤'

    def test_must_not_exceed(self):
        sentence = "Passwords must not exceed 64 characters."
        rules = extract_password_min_length_rules(sentence, 4)
        assert len(rules) == 1
        assert rules[0].value == 64.0
        assert rules[0].comparator == '≤'

    def test_maximum_fallback(self):
        sentence = "The maximum is 10 characters."
        rules = extract_password_min_length_rules(sentence, 5)
        assert len(rules) == 1
        rule = rules[0]
        assert rule.value == 10.0
        assert rule.comparator == '≤'

    # ------------------ EXACT LENGTH PATTERNS ------------------
    def test_exactly_pattern(self):
        sentence = "Passwords must be exactly 8 characters."
        rules = extract_password_min_length_rules(sentence, 2)
        assert len(rules) == 1
        assert rules[0].value == 8.0
        assert rules[0].comparator == '='

    def test_exact_words(self):
        sentence = "Passwords must be exactly ten characters."
        rules = extract_password_min_length_rules(sentence, 3)
        assert len(rules) == 1
        assert rules[0].value == 10.0
        assert rules[0].comparator == '='

    def test_x_character_passwords(self):
        sentence = "Use 10-character passwords."
        rules = extract_password_min_length_rules(sentence, 7)
        assert len(rules) == 1
        assert rules[0].value == 10.0
        assert rules[0].comparator == '='

    def test_must_be_x_characters(self):
        sentence = "Passwords shall be 14 characters."
        rules = extract_password_min_length_rules(sentence, 3)
        assert len(rules) == 1
        assert rules[0].value == 14.0
        assert rules[0].comparator == '='

    # ------------------ RANGE PATTERNS ------------------
    def test_between_pattern(self):
        sentence = "Passwords must be between 8 and 16 characters."
        rules = extract_password_min_length_rules(sentence, 4)
        assert len(rules) == 2
        assert rules[0].value == 8.0 and rules[0].comparator == '≥'
        assert rules[1].value == 16.0 and rules[1].comparator == '≤'

    def test_hyphen_range(self):
        sentence = "Use 8-12 character passwords."
        rules = extract_password_min_length_rules(sentence, 6)
        assert len(rules) == 2
        assert rules[0].value == 8.0 and rules[0].comparator == '≥'
        assert rules[1].value == 12.0 and rules[1].comparator == '≤'

    def test_range_with_to(self):
        sentence = "Passwords must be 8 to 16 characters."
        rules = extract_password_min_length_rules(sentence, 6)
        assert len(rules) == 2
        assert rules[0].value == 8.0 and rules[0].comparator == '≥'
        assert rules[1].value == 16.0 and rules[1].comparator == '≤'

    def test_range_with_up_to(self):
        sentence = "Passwords must have a length from 8 up to 16 characters."
        rules = extract_password_min_length_rules(sentence, 6)
        assert len(rules) == 2
        assert rules[0].value == 8.0 and rules[0].comparator == '≥'
        assert rules[1].value == 16.0 and rules[1].comparator == '≤'

    def test_at_least_but_not_more(self):
        sentence = "Passwords must be at least 8 but not more than 64 characters."
        rules = extract_password_min_length_rules(sentence, 8)
        assert len(rules) == 2
        assert rules[0].value == 8.0 and rules[0].comparator == '≥'
        assert rules[1].value == 64.0 and rules[1].comparator == '≤'

    # ------------------ SYMBOLS ------------------
    def test_ge_symbol(self):
        sentence = "Password length ≥ 15."
        rules = extract_password_min_length_rules(sentence, 12)
        assert len(rules) == 1
        assert rules[0].value == 15.0
        assert rules[0].comparator == '≥'

    def test_le_symbol(self):
        sentence = "Password length <= 30."
        rules = extract_password_min_length_rules(sentence, 14)
        assert len(rules) == 1
        assert rules[0].value == 30.0
        assert rules[0].comparator == '≤'

    # ------------------ EXCEPTIONS ------------------
    def test_exception_detection(self):
        sentence = "Passwords must be at least 8 characters, except for legacy systems."
        rules = extract_password_min_length_rules(sentence, 11)
        assert len(rules) == 1
        assert rules[0].exception is True

    # ------------------ NO MATCH ------------------
    def test_no_match(self):
        sentence = "This sentence contains no password length requirement."
        rules = extract_password_min_length_rules(sentence, 1)
        assert len(rules) == 0

    # ------------------ MULTIPLE RULES ------------------
    def test_multiple_rules_in_one_sentence(self):
        sentence = "Minimum length is 8; maximum length is 16."
        rules = extract_password_min_length_rules(sentence, 5)
        assert len(rules) >= 1

    # ------------------ ABBREVIATIONS ------------------
    def test_chars_abbreviation(self):
        sentence = "Passwords must be at least 8 chars."
        rules = extract_password_min_length_rules(sentence, 1)
        assert len(rules) == 1
        assert rules[0].value == 8.0
        assert rules[0].comparator == '≥'

    # ------------------ AMBIGUOUS CASES ------------------
    def test_may_contain(self):
        sentence = "Passwords may contain 8 characters."
        rules = extract_password_min_length_rules(sentence, 1)
        assert len(rules) == 1
        # Conservative: treat as exact
        assert rules[0].value == 8.0
        assert rules[0].comparator == '='
