import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from security_linter import has_unbound_reference

def test_unbound_reference_detection():
    """
    Comprehensive test suite for unbound reference detection.
    Flags sentences that reference external documents without a specific identifier.
    """

    # =========================================================================
    # 1️⃣ SHOULD FLAG – reference phrase present, NO document identifier
    # =========================================================================
    assert has_unbound_reference("Passwords must comply with corporate password standards.") == (True, ["comply with"])
    assert has_unbound_reference("All controls must be in accordance with company policy.") == (True, ["in accordance with"])
    assert has_unbound_reference("Follow the procedures per the security manual.") == (True, ["per"])
    assert has_unbound_reference("According to internal guidelines, access must be restricted.") == (True, ["according to"])
    assert has_unbound_reference("As defined in the policy, all users must authenticate.") == (True, ["as defined in"])
    assert has_unbound_reference("Implement controls as specified in the documentation.") == (True, ["as specified in"])
    assert has_unbound_reference("Based on the security framework, encryption is required.") == (True, ["based on"])
    assert has_unbound_reference("Meet the requirements of the corporate standard.") == (True, ["meet the requirements of"])
    assert has_unbound_reference("As outlined in the policy document.") == (True, ["as outlined in"])
    assert has_unbound_reference("Following the guidelines provided by the security team.") == (True, ["following the guidelines provided by"])

    # =========================================================================
    # 2️⃣ SHOULD NOT FLAG – reference phrase present, BUT has document identifier
    # =========================================================================
    assert has_unbound_reference("Passwords must comply with ISO 27001.") == (False, [])
    assert has_unbound_reference("Controls per NIST SP 800-53 are required.") == (False, [])
    assert has_unbound_reference("Follow version 2.0 of the standard.") == (False, [])
    assert has_unbound_reference("Implement controls as defined in ISO/IEC 27002.") == (False, [])
    assert has_unbound_reference("According to revision 5 of the policy.") == (False, [])
    assert has_unbound_reference("Based on STD-001, all systems must be patched.") == (False, [])
    assert has_unbound_reference("Meet the requirements of NIST 800-53 rev4.") == (False, [])
    assert has_unbound_reference("As specified in the company's security standard v3.2.") == (False, [])
    assert has_unbound_reference("Comply with internal policy document POL‑2024‑001.") == (False, [])

    # =========================================================================
    # 3️⃣ SHOULD NOT FLAG – no reference phrase at all
    # =========================================================================
    assert has_unbound_reference("Passwords must be 8 characters.") == (False, [])
    assert has_unbound_reference("All employees shall complete security training.") == (False, [])
    assert has_unbound_reference("Access rights must be reviewed quarterly.") == (False, [])
    assert has_unbound_reference("Firewalls shall be configured to block unauthorized traffic.") == (False, [])
    assert has_unbound_reference("Incidents shall be reported immediately.") == (False, [])