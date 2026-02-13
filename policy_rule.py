"""
Unified rule model for security policy constraints.
Immutable, self-validating dataclass.
"""
from dataclasses import dataclass
from typing import Literal, Union

# Standardized subject identifiers.
SubjectType = Literal[
    'password_min_length',
    'password_max_length',
    'session_timeout',
    'password_history',
    'account_lockout_threshold',
    'encryption_key_length'
]

# Runtime list for validation
SUBJECTS = (
    'password_min_length',
    'password_max_length',
    'session_timeout',
    'password_history',
    'account_lockout_threshold',
    'encryption_key_length',
)

ComparatorType = Literal['≥', '>', '=', '≤', '<', 'range_min', 'range_max']

@dataclass(frozen=True)
class PolicyRule:
    """
    A single, normalised policy constraint.
    All fields are validated at creation; whitespace is stripped automatically.
    """
    subject: SubjectType
    value: float
    unit: str
    comparator: ComparatorType
    line_number: int
    sentence: str
    exception: bool = False

    def __post_init__(self):
        """Validate and normalise fields."""
        # ----- NORMALISE: strip whitespace -----
        subject_stripped = self.subject.strip()
        unit_stripped = self.unit.strip()
        sentence_stripped = self.sentence.strip()

        # Use object.__setattr__ to modify frozen dataclass
        if subject_stripped != self.subject:
            object.__setattr__(self, 'subject', subject_stripped)
        if unit_stripped != self.unit:
            object.__setattr__(self, 'unit', unit_stripped)
        if sentence_stripped != self.sentence:
            object.__setattr__(self, 'sentence', sentence_stripped)

        # ----- VALIDATION -----
        # Subject
        if not self.subject:
            raise ValueError("subject must be non-empty after stripping")
        if self.subject not in SUBJECTS:
            raise ValueError(f"subject must be one of: {', '.join(SUBJECTS)}")

        # Value
        if not isinstance(self.value, (int, float)):
            raise ValueError(f"value must be numeric, got {type(self.value).__name__}")
        if self.value <= 0:
            raise ValueError(f"value must be positive, got {self.value}")

        # Unit
        if not self.unit:
            raise ValueError("unit must be non-empty after stripping")

        # Comparator
        if self.comparator not in ('≥', '>', '=', '≤', '<', 'range_min', 'range_max'):
            raise ValueError(f"invalid comparator: {self.comparator}")

        # Line number
        if not isinstance(self.line_number, int) or self.line_number < 1:
            raise ValueError("line_number must be a positive integer")

        # Sentence
        if not self.sentence:
            raise ValueError("sentence must be non-empty after stripping")

        # Exception flag
        if not isinstance(self.exception, bool):
            raise ValueError(f"exception must be bool, got {type(self.exception).__name__}")
        
        