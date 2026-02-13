import pytest
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from security_linter import has_vague_language, has_weak_language

# (sentence, expected_vague, expected_weak)
TEST_CASES = [

    # TIME-BASED VAGUENESS
    ("Security incidents must be reported in a timely manner.", True, False),
    ("Critical vulnerabilities shall be remediated as soon as possible.", True, False),
    ("Logs must be reviewed on a regular basis.", True, False),
    ("Access reviews shall be conducted periodically.", True, False),
    ("Security alerts should be investigated promptly.", True, True),  # 'should' = weak
    ("Patches must be applied without undue delay.", True, False),
    ("Backups shall be tested from time to time.", True, False),
    ("User access must be revoked when necessary.", True, False),
    ("Systems shall be updated as needed.", True, False),
    ("Incident response actions must occur as appropriate.", True, False),


    # RESPONSIBILITY & OWNERSHIP VAGUENESS
    ("Appropriate personnel shall ensure that systems are secured.", True, False),
    ("Management is responsible for maintaining security controls.", False, False),  # NOT vague
    ("Relevant teams should address identified risks.", True, True),
    ("Designated staff may approve security exceptions.", True, True),
    ("Authorized individuals shall manage access privileges.", True, False),
    ("System owners are expected to enforce security requirements.", True, False),
    ("Responsible parties must review security findings.", True, False),
    ("Security controls shall be implemented by the organization.", False, False),
    ("Issues should be escalated to the appropriate team.", True, True),
    ("Access approvals are handled by designated roles.", True, False),


    # CONTROL STRENGTH VAGUENESS
    ("Systems must implement reasonable security measures.", True, False),
    ("Adequate protections shall be in place to safeguard data.", True, False),
    ("Sufficient safeguards must be applied to sensitive systems.", True, False),
    ("Appropriate controls shall be selected based on risk.", True, False),
    ("Industry-standard security practices must be followed.", True, False),
    ("Strong passwords should be used for all accounts.", True, True),
    ("Robust authentication mechanisms shall be implemented.", True, False),
    ("Acceptable encryption must be used for data protection.", True, False),
    ("Best efforts shall be made to secure the environment.", True, False),
    ("Commercially reasonable security controls must be maintained.", True, False),


    # CONDITIONAL / ESCAPE-HATCH LANGUAGE
    ("Multi-factor authentication shall be implemented where feasible.", True, False),
    ("Controls must be applied where practical.", True, False),
    ("Security monitoring should be enabled if possible.", True, True),
    ("Policies shall be enforced unless otherwise required.", True, False),
    ("Measures must be implemented to the extent practicable.", True, False),
    ("Controls shall be applied when circumstances permit.", True, False),
    ("Security reviews are conducted as deemed necessary.", True, False),
    ("Exceptions may be granted based on operational constraints.", True, True),
    ("Requirements apply unless explicitly stated otherwise.", True, False),
    ("Controls shall be selected based on risk.", True, False),


    # MONITORING & RESPONSE VAGUENESS
    ("Suspicious activity must be investigated.", True, False),
    ("Unusual behavior should be reviewed by the SOC.", True, True),
    ("Abnormal events shall be logged and analyzed.", True, False),
    ("Potential incidents must be escalated.", True, False),
    ("Elevated risks shall be addressed.", True, False),
    ("Known threats should be mitigated.", True, True),
    ("Significant vulnerabilities must be remediated.", True, False),
    ("Appropriate response actions shall be taken.", True, False),
    ("Necessary remediation steps must be performed.", True, False),
    ("Reasonable investigation shall be conducted.", True, False),


    # --- TRUE POSITIVES (should flag) ---
    ("will regularly monitor the effectiveness", True, False),
    ("Security measures sufficient to reduce risks", True, False),
    ("procedures to regularly review records", True, False),

    # --- FALSE POSITIVES (should NOT flag) ---
    ("implemented by one or all of the following, as appropriate:", False, False),
    ("This safeguard may be implemented by", False, False),  # permissive, not weak
    ("as appropriate", False, False),
    # ... add at least 20
]

@pytest.mark.parametrize("sentence,exp_vague,exp_weak", TEST_CASES)
def test_vague_precision(sentence, exp_vague, exp_weak):
    vague_flag, _ = has_vague_language(sentence)
    weak_flag, _ = has_weak_language(sentence)
    assert vague_flag == exp_vague
    assert weak_flag == exp_weak