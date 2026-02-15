#!/usr/bin/env python3
import argparse
from copy import deepcopy
import re
import sys
from typing import List, Tuple, Optional
from policy_rule import PolicyRule, SubjectType, ComparatorType
from copy import deepcopy

def _rule_to_interval(rule: PolicyRule) -> Tuple[float, bool, float, bool]:
    """
    Convert a PolicyRule to an interval (lower, lower_inc, upper, upper_inc).
    lower_inc: True if lower bound is inclusive.
    upper_inc: True if upper bound is inclusive.
    """
    v = rule.value
    c = rule.comparator

    # Default: unbounded both ends
    lower = float('-inf')
    lower_inc = False
    upper = float('inf')
    upper_inc = False

    if c in ('≥', 'range_min'):
        lower = v
        lower_inc = True
    elif c == '>':
        lower = v
        lower_inc = False
    elif c in ('≤', 'range_max'):
        upper = v
        upper_inc = True
    elif c == '<':
        upper = v
        upper_inc = False
    elif c == '=':
        lower = v
        lower_inc = True
        upper = v
        upper_inc = True
    # No other comparators exist in current model

    return lower, lower_inc, upper, upper_inc


def _intervals_intersect(
    l1: float, inc1: bool, u1: float, inc1u: bool,
    l2: float, inc2: bool, u2: float, inc2u: bool
) -> bool:
    """
    Return True if the two intervals have any real number in common.
    """
    # Compute the intersection bounds
    lower = max(l1, l2)
    upper = min(u1, u2)

    if lower > upper:
        return False

    # If lower == upper, need to check inclusivity
    if lower == upper:
        # Both bounds must be inclusive at that point
        lower_ok = (
            (lower == l1 and inc1) or
            (lower == l2 and inc2) or
            (lower > l1 and lower > l2)  # strictly greater than both lower bounds → automatically inside
        )
        upper_ok = (
            (upper == u1 and inc1u) or
            (upper == u2 and inc2u) or
            (upper < u1 and upper < u2)  # strictly less than both upper bounds → automatically inside
        )
        return lower_ok and upper_ok

    # lower < upper → interval non‑empty regardless of inclusivity at endpoints
    return True



class NormalisationError(Exception):
    """Raised when rule normalisation fails."""


def normalise_rule(rule: PolicyRule) -> PolicyRule:
    """
    Return a normalised copy of the rule.

    Security guarantees:
    - Never mutates the input rule
    - Explicit subject handling
    - Fail-closed on unknown or malformed rules
    """

    # 1️⃣ Basic validation
    if rule is None:
        raise NormalisationError("PolicyRule is None")

    if not hasattr(rule, 'subject'):
        raise NormalisationError(f"Invalid PolicyRule object: {rule}")

    if not isinstance(rule.subject, str) or not rule.subject.strip():
        raise NormalisationError(f"Invalid rule subject: {rule.subject}")

    subject = rule.subject.strip()

    # 2️⃣ Defensive copy (no side effects)
    rule_copy = deepcopy(rule)
    # 3️⃣ Subject-specific normalisation
    if subject == 'session_timeout':
        try:
            normalised = normalise_timeout_rule(rule_copy)
        except Exception as e:
            raise NormalisationError(
                f"Failed to normalise session_timeout "
                f"(line {rule.line_number})"
            ) from e

        if normalised is None:
            raise NormalisationError(
                f"normalise_timeout_rule returned None "
                f"(line {rule.line_number})"
            )

        return normalised

    # 4️⃣ Explicit pass-through subjects (SAFE BY DESIGN)
    if subject in {'password_min_length', 'password_history'}:
        return rule_copy

    # 5️⃣ Fail-closed on unknown subjects
    raise NormalisationError(
        f"No normalisation logic defined for subject '{subject}' "
        f"(line {getattr(rule, 'line', 'unknown')})"
    )



def detect_contradictions(rules: List[PolicyRule]) -> List[dict]:
    """
    Detect contradictions among rules of the same subject and unit.
    Normalises all rules first, then compares normalised versions,
    but reports original values/units.
    """
    contradictions = []
    # Pair each original rule with its normalised version
    paired = [(r, normalise_rule(r)) for r in rules]

    # Group by (subject, normalised_unit)
    groups = {}
    for orig, norm in paired:
        key = (norm.subject, norm.unit)   # normalised unit is always base unit
        groups.setdefault(key, []).append((orig, norm))

    for (subject, unit), pair_list in groups.items():
        if len(pair_list) < 2:
            continue

        for i, (orig_a, norm_a) in enumerate(pair_list):
            for orig_b, norm_b in pair_list[i+1:]:
                # Convert normalised rules to intervals
                la, linc_a, ua, uinc_a = _rule_to_interval(norm_a)
                lb, linc_b, ub, uinc_b = _rule_to_interval(norm_b)

                if not _intervals_intersect(
                    la, linc_a, ua, uinc_a,
                    lb, linc_b, ub, uinc_b
                ):
                    contradictions.append({
                        'type': 'Contradiction',
                        'subject': subject,
                        'lines': [orig_a.line_number, orig_b.line_number],
                        'values': [orig_a.value, orig_b.value],
                        'units': [orig_a.unit, orig_b.unit],
                        'comparators': [orig_a.comparator, orig_b.comparator],
                        'texts': [orig_a.sentence, orig_b.sentence]
                    })
    return contradictions


def is_overly_complex(text, threshold=2):
    """
    Flags a line as overly complex if it contains too many mandatory terms.
    
    Args:
        text (str): The line of text to analyze.
        threshold (int): The max allowed mandatory terms. Default is 2.
    
    Returns:
        tuple: (bool, list) (True if complex, list of found terms)
    """

    #terms that indicate mandatery requirements
    mandatory_patterns = [
        r'\bmust\b',
        r'\bshall\b',
        r'\brequired\b',
        r'\bare to\b',
        r'\bis to\b',
        r'\bhave to\b',
        r'\bneed to\b',
        ]
    find_terms = []
    lower_text = text.lower()

    for pattern in mandatory_patterns:
        matches = re.findall(pattern, lower_text)
        if matches:
            find_terms.extend(matches)
    term_count = len(find_terms)
    is_complex = term_count > threshold
    return is_complex, find_terms


VAGUE_PHRASES = [
    "as soon as possible",
    "from time to time",
    "on a regular basis",
    "without undue delay",
    "where feasible",
    "where practical",
    "as needed",
    "as appropriate",
    "best efforts",
    "if possible",
    "unless otherwise required",
    "to the extent practicable",
    "when circumstances permit",
    "based on risk",
    "operational constraints",
    "unless explicitly stated otherwise",
    "industry standard",
    "business need",
    "management approval",               
    "best practices",                   
    "critical systems",                  
    "in accordance with company policy",
    "appropriate controls",
    "safeguard data",
    "safeguard sensitive systems",
    "safeguard the environment",
    "suspicious activity",
    "unusual behavior",
    "abnormal events",
    "potential incidents",
    "elevated risks",
    "known threats",
    "significant vulnerabilities",
    "it team",
    "security team",
    "it department",
    "security department",
    "management must",

]

VAGUE_SINGLE_WORDS = [
    "timely",
    "promptly",
    "periodically",
    "appropriate",
    "reasonable",
    "adequate",
    "sufficient",
    "necessary",
    "regularly",
    "unusual",
    "strong",
    "robust",
    "acceptable",
    "suspicious",
    "abnormal",
    "potential",
    "elevated",
    "known",
    "significant",
    "industry-standard",

]

RESPONSIBILITY_VAGUE_TERMS = [
    "relevant",
    "appropriate",
    "designated",
    "expected",
    "individuals",
    "parties",
    "roles",
    "staff",
    "teams", 
]


DEFINITION_PATTERNS = [
    r'\bmeans\b',
    r'\bis defined as\b',
    r'\brefers to\b',
]

BOILERPLATE_PATTERNS = [
    r'one or all of the following',
    r'may be implemented',
    r'can be implemented',
]

def has_vague_language(text):
    if not text or not isinstance(text, str):
        return False, []

    lower = text.lower()

    # ----- SKIP DEFINITIONS -----
    if any(re.search(p, lower) for p in DEFINITION_PATTERNS):
        return False, []

    # ----- SKIP STANDALONE "AS APPROPRIATE" -----
    if re.fullmatch(r'as appropriate\s*:?', lower):
        return False, []

    # ----- SKIP OTHER BOILERPLATE -----
    if any(re.search(p, lower) for p in BOILERPLATE_PATTERNS):
        return False, []
    
    # ----- Skip bullet‑point policy titles -----
    if re.match(r'^\s*[●•\-]\s*[A-Za-z][A-Za-z\s]+(?::\s*)?$', text):
        return False, []

    found = set()

    # ----- PHRASE VAGUENESS -----
    for phrase in VAGUE_PHRASES:
        
        if phrase in lower:
            found.add(phrase)

    # ----- SINGLE‑WORD VAGUENESS -----
    for term in VAGUE_SINGLE_WORDS:
        if re.search(rf'\b{re.escape(term)}\b', lower):
            found.add(term)

    # ----- RESPONSIBILITY VAGUENESS -----
    for term in RESPONSIBILITY_VAGUE_TERMS:
        if re.search(rf'\b{re.escape(term)}\b', lower):
            found.add(term)

    return bool(found), sorted(found)


WEAK_TERMS = [
    'should', 'may', 'could', 'might', 'can',
    'optional', 'suggest', 'recommend', 'consider'
]

PERMISSIVE_PATTERNS = [
    r'may be implemented',
    r'can be implemented',
    r'one or all of the following',
    r'may be granted',
    r'may temporarily suspend',      
    r'may be subject to',            
    r'may access',                   
    r'may review',                   
    r'may monitor',                  
    r'may disclose',                 
]

def has_weak_language(text):
    if not text or not isinstance(text, str):
        return False, []

    lower = text.lower()

    # ----- 1. SKIP PERMISSIVE BOILERPLATE (implementation options) -----
    for pattern in PERMISSIVE_PATTERNS:
        if re.search(pattern, lower):
            return False, []

    # ----- 2. IF SENTENCE ALREADY MANDATORY, IT IS NOT WEAK -----
    if re.search(r'\b(must|shall|required)\b', lower):
        return False, []

    # ----- 3. DETECT WEAK TERMS WITH NEGATION HANDLING -----
    found = []
    for term in WEAK_TERMS:
        for match in re.finditer(r'\b' + re.escape(term) + r'\b', lower):
            pos = match.start()
            start = max(0, pos - 50)
            end = min(len(lower), pos + 50)
            context = lower[start:end]

            neg_before = re.search(
                r'\b(not|no)\b(?:\s+\w+){0,3}\s+' + re.escape(term) + r'\b',
                context
            )
            neg_after = re.search(
                r'\b' + re.escape(term) + r'\b\s+(?:\w+\s+){0,3}?\b(not|no|never)\b',
                context
            )

            if not (neg_before or neg_after):
                found.append(term)
                break   # only count each weak term once per sentence

    return bool(found), found


# --- Unbound Reference Detection ---
REFERENCE_PHRASES = [
    "comply with",
    "in accordance with",
    "per",
    "according to",
    "as defined in",
    "as specified in",
    "based on",
    "meet the requirements of",
    "as outlined in",                     
    "following the guidelines provided by",  
    "following the guidelines",            
]

# Patterns that indicate a specific document/standard is cited
DOCUMENT_ID_PATTERNS = [
    r'\b(?:ISO|IEC|NIST|IEEE|STD)(?:\s+[A-Z]+)?(?:\s*/\s*[A-Z]+)?\s*\d+(?:[-–—]\d+)*(?:\.\d+)?\b',
    r'\b[A-Z]{2,}[-–—‐‑]?\d+(?:[-–—‐‑]\d+)*\b', 
    r'\b[A-Z]{2,}(?:\s+[A-Z]+)?\s+\d+(?:[-–—]\d+)*\b',
    r'\b(?:FERPA|GLBA|HIPAA|HITECH|CCPA|FIPS-199|PCI\s+DSS(?:\s+\d+\.\d+)?)\b',
    r'\bversion\s+[\d\.]+',
    r'\bv[\d\.]+\b',
    r'\brevision\s+[\d\.]+',
    r'\b(?:draft|final|release)\s+[\d\.]+\b',
]

def has_unbound_reference(text):
    """
    Returns (bool, list) – True if an unbound reference is found,
    i.e., the sentence references an external document without an identifier.
    """
    lower = text.lower()
    # Check for a reference phrase
    found_phrase = None
    phrases_escaped = [re.escape(p) for p in REFERENCE_PHRASES]
    pattern = r'\b(?:' + '|'.join(phrases_escaped) + r')\b'
    match = re.search(pattern, lower)
    if not match:
        return False, []
    found_phrase = match.group(0)

    for phrase in REFERENCE_PHRASES:
        if phrase in lower:
            found_phrase = phrase
            break
    if not found_phrase:
        return False, []

    # If a document ID pattern matches, it's bound → not a problem
    for pattern in DOCUMENT_ID_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return False, []

    # If we get here, it's an unbound reference
    return True, [found_phrase]



def split_into_sentences(text):
    """
    A naive but functional sentence splitter for policy text.
    Splits on [.?!] followed by whitespace or end of string.
    
    Args:
        text_block (str): A line or paragraph of text.
    
    Returns:
        list: Sentences.
    """
    sentences = re.split(r'(?<=[.?!])\s+', text)
    return [s.strip() for s in sentences if s.strip()]



def analyze_policy(file_path, complexity_threshold=2):
    """d
    Main analysis function. Reads file and applies detection rules.
    
    Args:
        file_path (str): Path to the policy file.
        complexity_threshold (int): Threshold for complex sentences.
    
    Returns:
        list: Findings ready for reporting.
    """
    extracted_rules = []
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)
    except PermissionError:
        print(f"Error: Permission denied for file '{file_path}'.")
        sys.exit(1)
    except UnicodeDecodeError:
        print(f"Error: Could not decode file '{file_path}'. Ensure it's a valid text file.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: Could not read file: {e}")
        sys.exit(1)

    for line_num, raw_line in enumerate(lines, start=1):       
        raw_line = raw_line.strip('\n')
        if not raw_line.strip():
            continue
       # print(f"Processing Line {line_num}: {repr(raw_line)}")
        sentences = split_into_sentences(raw_line)
       # print(f" Sentences: {sentences}")
        for sentence in sentences:
            complex_flag, found_terms = is_overly_complex(sentence, complexity_threshold)
         #   print(f"    Sentence: {sentence} -> Flag: {complex_flag}, Terms: {found_terms}")
            if complex_flag:
                findings.append({
                    'line': line_num,
                    'type': 'Overly Complex',
                    'text': sentence,
                    'details':{
                        'found_terms': found_terms,
                        'term_count': len(found_terms),
                        'threshold': complexity_threshold
                    }
                    
                })
            # Vague language detection
            vague_flag, vague_terms = has_vague_language(sentence)
            if vague_flag:
                findings.append({
                    'line': line_num,
                    'type': 'Vague Language',
                    'text': sentence,
                    'details': {
                        'found_terms': vague_terms,
                        'term_count': len(vague_terms)
                    }
                }) 
            # Weak language detection
            weak_flag, weak_terms = has_weak_language(sentence)
            if weak_flag:
                findings.append({
                    'line': line_num,
                    'type': 'Weak Language',
                    'text': sentence,
                    'details': {
                        'found_terms': weak_terms,
                        'term_count': len(weak_terms)
                    }
                })
            # Unbound reference detection
            unbound_flag, found_phrases = has_unbound_reference(sentence)
            if unbound_flag:
                findings.append({
                    'line': line_num,
                    'type': 'Unbound Reference',
                    'text': sentence,
                    'details': {
                        'found_phrases': found_phrases
                    }
                })

            password_rules = extract_password_min_length_rules(sentence, line_num)
            extracted_rules.extend(password_rules)
            session_rules = extract_session_timeout_rules(sentence, line_num)
            extracted_rules.extend(session_rules)
            
    # After processing all sentences
    
    contradiction_findings = detect_contradictions(extracted_rules)
    findings.extend(contradiction_findings)
    return findings

def extract_session_timeout_rules(sentence: str, line_number: int) -> List[PolicyRule]:
    """Extract session timeout constraints from a sentence."""
    lower = sentence.lower()
    extracted: List[PolicyRule] = []

    exception_pattern = r'\b(?:except|unless|break[-\s]?glass)\b'
    has_exception = bool(re.search(exception_pattern, lower))

    # ---------- Unit normalisation map ----------
    UNIT_MAP = {
        'min': 'minute', 'mins': 'minute', 'minute': 'minute', 'minutes': 'minute',
        'hour': 'hour', 'hours': 'hour',
        'day': 'day', 'days': 'day',
        'second': 'second', 'seconds': 'second', 'sec': 'second', 'secs': 'second'
    }

    def normalise_unit(raw_unit: str) -> str:
        raw = raw_unit.lower().rstrip('s')
        return UNIT_MAP.get(raw, raw)

    def make_rule(value: float, raw_unit: str, comparator: ComparatorType) -> Optional[PolicyRule]:
        if value <= 0:
            return None
        unit = normalise_unit(raw_unit)
        if unit not in ('minute', 'hour', 'day', 'second'):
            return None
        return PolicyRule(
            subject="session_timeout",
            value=value,
            unit=unit,
            comparator=comparator,
            line_number=line_number,
            sentence=sentence.strip(),
            exception=has_exception
        )

    def add_rule(value: float, raw_unit: str, comparator: ComparatorType) -> bool:
        rule = make_rule(value, raw_unit, comparator)
        if rule:
            # ----- DUPLICATE PREVENTION (keeps rule set clean) -----
            for existing in extracted:
                if (existing.subject == rule.subject and
                    existing.value == rule.value and
                    existing.unit == rule.unit and
                    existing.comparator == rule.comparator and
                    existing.line_number == rule.line_number):
                    return False   # already have this exact rule
            extracted.append(rule)
            return True
        return False

    # =========================================================================
    # 1️⃣ RANGE PATTERNS (MUST COME FIRST – they capture complete constraints)
    # =========================================================================
    m = re.search(r'at least (\d+(?:\.\d+)?).*?no more than (\d+(?:\.\d+)?)\s*(min(?:ute)?s?|hour?s?|days?|seconds?|secs?)', lower)
    if m:
        unit = m.group(3)
        add_rule(float(m.group(1)), unit, '≥')
        add_rule(float(m.group(2)), unit, '≤')
        return extracted   # ← EARLY RETURN – no other patterns should match this sentence

    m = re.search(r'between (\d+(?:\.\d+)?) and (\d+(?:\.\d+)?)\s*(min(?:ute)?s?|hour?s?|days?|seconds?|secs?)', lower)
    if m:
        unit = m.group(3)
        add_rule(float(m.group(1)), unit, '≥')
        add_rule(float(m.group(2)), unit, '≤')
        return extracted

    # =========================================================================
    # 2️⃣ STANDARD TIMEOUT PHRASINGS (single rule, accumulate)
    # =========================================================================
    # --- "session expires after ..." (FIX: trailing period, multiple spaces) ---
    m = re.search(r'session.*?expires? after\s*(\d+(?:\.\d+)?)\s*(min(?:ute)?s?|hour?s?|days?|seconds?|secs?)\.?', lower)
    if m:
        add_rule(float(m.group(1)), m.group(2), '≤')

    m = re.search(r'idle session.*?terminated after (\d+(?:\.\d+)?)\s*(min(?:ute)?s?|hour?s?|days?|seconds?|secs?)\.?', lower)
    if m:
        add_rule(float(m.group(1)), m.group(2), '≤')

    m = re.search(r'session timeout (?:is|of) (\d+(?:\.\d+)?)\s*(min(?:ute)?s?|hour?s?|days?|seconds?|secs?)\.?', lower)
    if m:
        add_rule(float(m.group(1)), m.group(2), '=')

    m = re.search(r'maximum session lifetime (?:is|of)?\s*(\d+(?:\.\d+)?)\s*(min(?:ute)?s?|hour?s?|days?|seconds?|secs?)\.?', lower)
    if m:
        add_rule(float(m.group(1)), m.group(2), '≤')

    m = re.search(r'logged out after (\d+(?:\.\d+)?)\s*(min(?:ute)?s?|hour?s?|days?|seconds?|secs?)\.?', lower)
    if m:
        add_rule(float(m.group(1)), m.group(2), '≤')

    m = re.search(r'session must expire within (\d+(?:\.\d+)?)\s*(min(?:ute)?s?|hour?s?|days?|seconds?|secs?)\.?', lower)
    if m:
        add_rule(float(m.group(1)), m.group(2), '≤')

    m = re.search(r'timeout (?:is|of) (\d+(?:\.\d+)?)\s*(min(?:ute)?s?|hour?s?|days?|seconds?|secs?)\.?', lower)
    if m:
        add_rule(float(m.group(1)), m.group(2), '=')

    m = re.search(r'idle timeout (?:is|of) (\d+(?:\.\d+)?)\s*(min(?:ute)?s?|hour?s?|days?|seconds?|secs?)\.?', lower)
    if m:
        add_rule(float(m.group(1)), m.group(2), '=')

    # =========================================================================
    # 3️⃣ COMPARATOR‑BASED PATTERNS (≤, ≥, <, >)
    # =========================================================================
    m = re.search(r'session timeout\s*(≤|<=|less than or equal to)\s*(\d+(?:\.\d+)?)\s*(min(?:ute)?s?|hour?s?|days?|seconds?|secs?)\.?', lower)
    if m:
        add_rule(float(m.group(2)), m.group(3), '≤')

    m = re.search(r'session timeout\s*(≥|>=|greater than or equal to)\s*(\d+(?:\.\d+)?)\s*(min(?:ute)?s?|hour?s?|days?|seconds?|secs?)\.?', lower)
    if m:
        add_rule(float(m.group(2)), m.group(3), '≥')

    m = re.search(r'session timeout\s*(<|less than)\s*(\d+(?:\.\d+)?)\s*(min(?:ute)?s?|hour?s?|days?|seconds?|secs?)\.?', lower)
    if m:
        add_rule(float(m.group(2)), m.group(3), '<')

    m = re.search(r'session timeout\s*(>|greater than)\s*(\d+(?:\.\d+)?)\s*(min(?:ute)?s?|hour?s?|days?|seconds?|secs?)\.?', lower)
    if m:
        add_rule(float(m.group(2)), m.group(3), '>')

    # =========================================================================
    # 4️⃣ GENERIC INEQUALITIES (less than / more than – placed LAST to avoid overlap)
    # =========================================================================
    # --- "expire in less than ..." ---
    m = re.search(r'(?:expire|timeout).*?less than (\d+(?:\.\d+)?)\s*(min(?:ute)?s?|hour?s?|days?|seconds?|secs?)\.?', lower)
    if m:
        add_rule(float(m.group(1)), m.group(2), '<')

    # --- "last more than / greater than" – SAFEGUARDED: only match if NOT preceded by "no" ---
    m = re.search(r'(?<!\bno\s)(?:last|be|timeout).*?(?:more than|greater than) (\d+(?:\.\d+)?)\s*(min(?:ute)?s?|hour?s?|days?|seconds?|secs?)\.?', lower)
    if m:
        add_rule(float(m.group(1)), m.group(2), '>')

    return extracted

def extract_password_min_length_rules(sentence: str, line_number: int) -> List[PolicyRule]:
    """
    Extract all password length constraints.
    Supports digits, English number words, all common phrasings, and abbreviations.
    """
    # ---------- Preprocess: convert English number words to digits ----------
    word_to_num = {
        "one": 1, "two": 2, "three": 3, "four": 4, "five": 5,
        "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10,
        "eleven": 11, "twelve": 12, "thirteen": 13, "fourteen": 14, "fifteen": 15,
        "sixteen": 16, "seventeen": 17, "eighteen": 18, "nineteen": 19, "twenty": 20
    }

    def replace_number_words(text: str) -> str:
        tokens = text.split()
        new_tokens = []
        for token in tokens:
            # Remove trailing punctuation for lookup
            clean = token.lower().rstrip('.,;:!?')
            if clean in word_to_num:
                # Replace with digit, keep original punctuation if any
                suffix = token[len(clean):] if len(token) > len(clean) else ''
                new_tokens.append(str(word_to_num[clean]) + suffix)
            else:
                new_tokens.append(token)
        return ' '.join(new_tokens)

    processed = replace_number_words(sentence)
    lower = processed.lower()
    extracted: List[PolicyRule] = []

    # --- Exception detection ---
    exception_pattern = r'\b(?:except|unless|break[-\s]?glass)\b'
    has_exception = bool(re.search(exception_pattern, lower))

    def make_rule(value: float, comparator: ComparatorType, unit: str = "characters") -> PolicyRule:
        return PolicyRule(
            subject="password_min_length",
            value=value,
            unit=unit,
            comparator=comparator,
            line_number=line_number,
            sentence=sentence.strip(),  # original sentence, not processed
            exception=has_exception
        )

    # =========================================================================
    # 1️⃣ RANGE PATTERNS (two numbers → two rules: min ≥, max ≤)
    # =========================================================================
    m = re.search(r'at least\s+(\d+).*?not more than\s+(\d+)', lower)
    if m:
        extracted.append(make_rule(float(m.group(1)), '≥'))
        extracted.append(make_rule(float(m.group(2)), '≤'))
        return extracted

    m = re.search(r'between\s+(\d+)\s+and\s+(\d+)\s+char(?:acter)?s?', lower)
    if m:
        extracted.append(make_rule(float(m.group(1)), '≥'))
        extracted.append(make_rule(float(m.group(2)), '≤'))
        return extracted

    m = re.search(r'(\d+)\s*[-–]\s*(\d+)\s+char(?:acter)?s?', lower)
    if m:
        extracted.append(make_rule(float(m.group(1)), '≥'))
        extracted.append(make_rule(float(m.group(2)), '≤'))
        return extracted

    m = re.search(r'(\d+)\s+to\s+(\d+)\s+char(?:acter)?s?', lower)
    if m:
        extracted.append(make_rule(float(m.group(1)), '≥'))
        extracted.append(make_rule(float(m.group(2)), '≤'))
        return extracted

    m = re.search(r'(\d+)\s+up to\s+(\d+)\s+char(?:acter)?s?', lower)
    if m:
        extracted.append(make_rule(float(m.group(1)), '≥'))
        extracted.append(make_rule(float(m.group(2)), '≤'))
        return extracted
    

    # =========================================================================
    # 2️⃣ MAXIMUM‑ONLY PATTERNS (single number, ≤)
    # =========================================================================
    m = re.search(r'up to (\d+)\s+char(?:acter)?s?', lower)
    if m:
        extracted.append(make_rule(float(m.group(1)), '≤'))
        return extracted

    m = re.search(r'must be at most (\d+)\s*char(?:acter)?s?', lower)
    if m:
        extracted.append(make_rule(float(m.group(1)), '≤'))
        return extracted

    m = re.search(r'maximum\s+password\s+length(?:\s+(?:is|of))?\s*(\d+)', lower)
    if m:
        extracted.append(make_rule(float(m.group(1)), '≤'))
        return extracted

    m = re.search(r'must not exceed (\d+)\s*char(?:acter)?s?', lower)
    if m:
        extracted.append(make_rule(float(m.group(1)), '≤'))
        return extracted

    m = re.search(r'maximum.*?(\d+)', lower)
    if m:
        extracted.append(make_rule(float(m.group(1)), '≤'))
        return extracted

    # =========================================================================
    # 3️⃣ EXACT CONTAIN PATTERN (no "at least") – NEW (fixes test_may_contain)
    # =========================================================================
    m = re.search(r'(?:may|must|shall)\s+contain\s+(\d+)\s+char(?:acter)?s?', lower)
    if m:
        extracted.append(make_rule(float(m.group(1)), '='))
        return extracted

    # =========================================================================
    # 4️⃣ MINIMUM‑ONLY & EXACT PATTERNS (single number, ≥ or =)
    # =========================================================================

    # --- 4a. "minimum of X characters" / "minimum X characters" (fixes test_min_words) ---
    m = re.search(r'(?:a\s+)?minimum(?:\s+of)?\s*(\d+)\s+char(?:acter)?s?', lower)
    if m:
        extracted.append(make_rule(float(m.group(1)), '≥'))
        return extracted

    # --- 4b. "minimum password length [of] X" ---
    m = re.search(r'(?:minimum\s+password\s+length|password\s+length\s+minimum)(?:\s+of)?\s*(\d+)', lower)
    if m:
        extracted.append(make_rule(float(m.group(1)), '≥'))
        return extracted

    # --- 4c. "must / shall / may contain at least X characters" ---
    m = re.search(r'(?:must|shall|may)\s+contain\s+at least\s+(\d+)\s+char(?:acter)?s?', lower)
    if m:
        extracted.append(make_rule(float(m.group(1)), '≥'))
        return extracted

    # --- 4d. "must / shall be at least X" (with optional second number for range) ---
    m = re.search(r'(?:must|shall|should|is to|are to)?\s*be\s+at least\s+(\d+)(?:\s*[-–]?\s*(\d+))?\s*char(?:acter)?s?', lower)
    if m:
        extracted.append(make_rule(float(m.group(1)), '≥'))
        if m.group(2):
            extracted.append(make_rule(float(m.group(2)), '≤'))
        return extracted

    # --- 4e. "X‑character passwords" (exact) ---
    m = re.search(r'(?<!\d\s)(\d+)[-\s]?char(?:acter)?\s+passwords?', lower)
    if m:
        extracted.append(make_rule(float(m.group(1)), '='))
        return extracted

    # --- 4f. "exactly X characters" / "exact X characters" (fixes test_exact_words) ---
    m = re.search(r'(?:exactly|exact)\s+(\d+)\s*char(?:acter)?s?', lower)
    if m:
        extracted.append(make_rule(float(m.group(1)), '='))
        return extracted

    # --- 4g. "must / shall be X characters" (exact) ---
    m = re.search(r'(?:must|shall|should)\s+be\s+(\d+)\s+char(?:acter)?s?', lower)
    if m:
        extracted.append(make_rule(float(m.group(1)), '='))
        return extracted

    # --- 4h. "no fewer than X", "not less than X", "at minimum X" ---
    m = re.search(r'(?:no\s+fewer\s+than|not\s+less\s+than|at\s+minimum)\s+(\d+)', lower)
    if m:
        extracted.append(make_rule(float(m.group(1)), '≥'))
        return extracted

    # --- 4i. "≥ X", ">= X", "greater than or equal to X" ---
    m = re.search(r'(?:≥|>=|greater than or equal to)\s*(\d+)', lower)
    if m:
        extracted.append(make_rule(float(m.group(1)), '≥'))
        return extracted

    # --- 4j. "≤ X", "<= X", "not more than X" ---
    m = re.search(r'(?:≤|<=|not more than)\s*(\d+)', lower)
    if m:
        extracted.append(make_rule(float(m.group(1)), '≤'))
        return extracted

    # =========================================================================
    # 5️⃣ FALLBACK PATTERNS (catch‑all, low priority)
    # =========================================================================
    m = re.search(r'minimum.*?(\d+)', lower)
    if m:
        extracted.append(make_rule(float(m.group(1)), '≥'))
        return extracted

    m = re.search(r'maximum.*?(\d+)', lower)
    if m:
        extracted.append(make_rule(float(m.group(1)), '≤'))
        return extracted

    return extracted


def normalise_timeout_rule(rule: PolicyRule) -> PolicyRule:
    """Convert session timeout rule to minutes (canonical base unit)."""
    if rule.subject != 'session_timeout':
        return rule

    unit = rule.unit.lower().rstrip('s')  # 'minutes' -> 'minute', 'seconds' -> 'second', etc.

    factors = {
        'second': 1/60,
        'minute': 1,
        'hour': 60,
        'day': 1440
    }

    if unit not in factors:
        return rule  # unknown unit – leave unchanged

    new_value = rule.value * factors[unit]
    return PolicyRule(
        subject=rule.subject,
        value=new_value,
        unit='minutes',
        comparator=rule.comparator,
        line_number=rule.line_number,
        sentence=rule.sentence,
        exception=rule.exception
    )

        
def print_findings(findings, show_all_lines=False):
    """
    Prints findings in a readable format, handling multiple finding types.
    """
    if not findings:
        print("✅ No issues found.")
        return

    print(f"\n🔍 Found {len(findings)} potential issue(s):")
    print("-" * 80)

    for i, finding in enumerate(findings, 1):
        # Only print generic line/type for findings that have a single 'line' field
        if 'line' in finding:
            print(f"\n{i}. Line {finding['line']}: {finding['type']}")
        else:
            print(f"\n{i}. {finding['type']}")  # fallback for types without single line

        # Only print generic "Text:" for findings that have a single 'text' field
        if 'text' in finding:
            print(f"   Text: \"{finding['text']}\"")

        # Type‑specific details
        if finding['type'] == 'Overly Complex':
            print(f"   Found {finding['details']['term_count']} mandatory terms: {', '.join(finding['details']['found_terms'])}")
            print(f"   Threshold: {finding['details']['threshold']} terms")
        elif finding['type'] == 'Vague Language':
            print(f"   Found {finding['details']['term_count']} vague term(s): {', '.join(finding['details']['found_terms'])}")
        elif finding['type'] == 'Weak Language':
            print(f"   Found {finding['details']['term_count']} weak term(s): {', '.join(finding['details']['found_terms'])}")
        elif finding['type'] == 'Contradiction':
            print(f"   Comparators: {finding['comparators'][0]} vs {finding['comparators'][1]}")
            print(f"   Subject: {finding['subject']}")
            print(f"   Lines {finding['lines'][0]} and {finding['lines'][1]}:")
            print(f"     - \"{finding['texts'][0]}\"")
            print(f"     - \"{finding['texts'][1]}\"")
        elif finding['type'] == 'Unbound Reference':
            print(f"   References external standard without identifier: \"{finding['text']}\"")
            print(f"   Trigger phrase: {', '.join(finding['details']['found_phrases'])}")
           
    print("-" * 80)
    print("💡 Suggestion: Review flagged items and clarify where possible.")

def main():
    """Command line interface for Security Policy Linter."""
    import argparse
    import sys
    import os

    parser = argparse.ArgumentParser(
        description=(
            "Static analysis tool for detecting contradictions, vague language, "
            "weak requirements, and overly complex statements in security policies."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog="""
Examples:
  %(prog)s policy.txt
  %(prog)s policy.txt --threshold 2
  %(prog)s policy.txt --verbose
        """
    )

    parser.add_argument(
        'file',
        help='Path to the security policy file to analyze.'
    )

    parser.add_argument(
        '-t', '--threshold',
        type=int,
        default=2,
        help='Maximum allowed mandatory terms in a single sentence.'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show verbose output including skipped lines.'
    )

    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"❌ Error: File not found: {args.file}")
        sys.exit(2)

    print(f"\nAnalyzing: {args.file}")
    print(f"Complexity Threshold: {args.threshold} mandatory terms\n")

    findings = analyze_policy(args.file, args.threshold)
    print_findings(findings, args.verbose)

    sys.exit(1 if findings else 0)

if __name__ == '__main__':
    main()