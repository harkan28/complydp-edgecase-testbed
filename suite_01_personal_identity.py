"""
COMPLYDP EDGE-CASE TEST SUITE: PERSONAL IDENTITY (ID)
Contains all 100 test scenarios (ID-001 to ID-100).
Includes Positive PII cases, API flows, Masked cases, and Negative Control Traps.
"""

import re
import json
import hashlib
from typing import Dict, Any, List, Optional

# ==============================================================================
# [TEST_ID: ID-001] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `full_name` in the repository schema or source code, includin
# Evidence: Verify the exact `full_name` declaration, its type/validation/usage, and whether it is lin
# ==============================================================================
def test_case_id_001():
    """Test scenario for ID-001: full_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    full_name = "active_sample_value_for_full_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "full_name": full_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-002] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `first_name + last_name` in the repository schema or source c
# Evidence: Verify the exact `first_name + last_name` declaration, its type/validation/usage, and whet
# ==============================================================================
def test_case_id_002():
    """Test scenario for ID-002: first_name + last_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    first_name___last_name = "active_sample_value_for_first_name___last_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "first_name___last_name": first_name___last_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-003] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `displayName` in the repository schema or source code, includ
# Evidence: Verify the exact `displayName` declaration, its type/validation/usage, and whether it is l
# ==============================================================================
def test_case_id_003():
    """Test scenario for ID-003: displayName"""
    # ACTIVE TEST CASE: Represents identifiable user data
    displayName = "active_sample_value_for_displayName"
    payload = {
        "user_id": "USR_99214_TEST",
        "displayName": displayName,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-004] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `preferred_name` in the repository schema or source code, inc
# Evidence: Verify the exact `preferred_name` declaration, its type/validation/usage, and whether it i
# ==============================================================================
def test_case_id_004():
    """Test scenario for ID-004: preferred_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    preferred_name = "active_sample_value_for_preferred_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "preferred_name": preferred_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-005] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `legal_name` in the repository schema or source code, includi
# Evidence: Verify the exact `legal_name` declaration, its type/validation/usage, and whether it is li
# ==============================================================================
def test_case_id_005():
    """Test scenario for ID-005: legal_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    legal_name = "active_sample_value_for_legal_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "legal_name": legal_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-006] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `alias` in the repository schema or source code, including na
# Evidence: Verify the exact `alias` declaration, its type/validation/usage, and whether it is linked 
# ==============================================================================
def test_case_id_006():
    """Test scenario for ID-006: alias"""
    # ACTIVE TEST CASE: Represents identifiable user data
    alias = "active_sample_value_for_alias"
    payload = {
        "user_id": "USR_99214_TEST",
        "alias": alias,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-007] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `maiden_name` in the repository schema or source code, includ
# Evidence: Verify the exact `maiden_name` declaration, its type/validation/usage, and whether it is l
# ==============================================================================
def test_case_id_007():
    """Test scenario for ID-007: maiden_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    maiden_name = "active_sample_value_for_maiden_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "maiden_name": maiden_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-008] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `user.name` in the repository schema or source code, includin
# Evidence: Verify the exact `user.name` declaration, its type/validation/usage, and whether it is lin
# ==============================================================================
def test_case_id_008():
    """Test scenario for ID-008: user.name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    user_name = "active_sample_value_for_user_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "user_name": user_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-009] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `profile.identity.name` in the repository schema or source co
# Evidence: Verify the exact `profile.identity.name` declaration, its type/validation/usage, and wheth
# ==============================================================================
def test_case_id_009():
    """Test scenario for ID-009: profile.identity.name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    profile_identity_name = "active_sample_value_for_profile_identity_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "profile_identity_name": profile_identity_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-010] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `account_owner` in the repository schema or source code, incl
# Evidence: Verify the exact `account_owner` declaration, its type/validation/usage, and whether it is
# ==============================================================================
def test_case_id_010():
    """Test scenario for ID-010: account_owner"""
    # ACTIVE TEST CASE: Represents identifiable user data
    account_owner = "active_sample_value_for_account_owner"
    payload = {
        "user_id": "USR_99214_TEST",
        "account_owner": account_owner,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-011] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `full_name` when split across first/last-name fields; insp
# Evidence: Capture the full JSON/object path for `full_name`, the parent record or user key, and the 
# ==============================================================================
def test_case_id_011():
    """Test scenario for ID-011: full_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    full_name = "active_sample_value_for_full_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "full_name": full_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-012] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `first_name + last_name` when Unicode or accented characte
# Evidence: Capture the full JSON/object path for `first_name + last_name`, the parent record or user 
# ==============================================================================
def test_case_id_012():
    """Test scenario for ID-012: first_name + last_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    first_name___last_name = "active_sample_value_for_first_name___last_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "first_name___last_name": first_name___last_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-013] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `displayName` when multi-part name with spaces; inspect ne
# Evidence: Capture the full JSON/object path for `displayName`, the parent record or user key, and th
# ==============================================================================
def test_case_id_013():
    """Test scenario for ID-013: displayName"""
    # ACTIVE TEST CASE: Represents identifiable user data
    displayName = "active_sample_value_for_displayName"
    payload = {
        "user_id": "USR_99214_TEST",
        "displayName": displayName,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-014] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `preferred_name` when hyphenated or apostrophe-containing 
# Evidence: Capture the full JSON/object path for `preferred_name`, the parent record or user key, and
# ==============================================================================
def test_case_id_014():
    """Test scenario for ID-014: preferred_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    preferred_name = "active_sample_value_for_preferred_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "preferred_name": preferred_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-015] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `legal_name` when name nested in profile JSON; inspect nes
# Evidence: Capture the full JSON/object path for `legal_name`, the parent record or user key, and the
# ==============================================================================
def test_case_id_015():
    """Test scenario for ID-015: legal_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    legal_name = "active_sample_value_for_legal_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "legal_name": legal_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-016] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `alias` when name joined to a user ID; inspect nested obje
# Evidence: Capture the full JSON/object path for `alias`, the parent record or user key, and the code
# ==============================================================================
def test_case_id_016():
    """Test scenario for ID-016: alias"""
    # ACTIVE TEST CASE: Represents identifiable user data
    alias = "active_sample_value_for_alias"
    payload = {
        "user_id": "USR_99214_TEST",
        "alias": alias,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-017] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `maiden_name` when name passed as a URL parameter; inspect
# Evidence: Capture the full JSON/object path for `maiden_name`, the parent record or user key, and th
# ==============================================================================
def test_case_id_017():
    """Test scenario for ID-017: maiden_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    maiden_name = "active_sample_value_for_maiden_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "maiden_name": maiden_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-018] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `user.name` when name returned by a profile API; inspect n
# Evidence: Capture the full JSON/object path for `user.name`, the parent record or user key, and the 
# ==============================================================================
def test_case_id_018():
    """Test scenario for ID-018: user.name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    user_name = "active_sample_value_for_user_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "user_name": user_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-019] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `profile.identity.name` when name included in an applicati
# Evidence: Capture the full JSON/object path for `profile.identity.name`, the parent record or user k
# ==============================================================================
def test_case_id_019():
    """Test scenario for ID-019: profile.identity.name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    profile_identity_name = "active_sample_value_for_profile_identity_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "profile_identity_name": profile_identity_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-020] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `account_owner` when name assembled from intermediate vari
# Evidence: Capture the full JSON/object path for `account_owner`, the parent record or user key, and 
# ==============================================================================
def test_case_id_020():
    """Test scenario for ID-020: account_owner"""
    # ACTIVE TEST CASE: Represents identifiable user data
    account_owner = "active_sample_value_for_account_owner"
    payload = {
        "user_id": "USR_99214_TEST",
        "account_owner": account_owner,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-021] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `full_name` through an API boundary when split across first/la
# Evidence: Verify the request/response schema and call site for `full_name`, direction of flow, endpo
# ==============================================================================
def test_case_id_021():
    """Test scenario for ID-021: full_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    full_name = "active_sample_value_for_full_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "full_name": full_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-022] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `first_name + last_name` through an API boundary when Unicode 
# Evidence: Verify the request/response schema and call site for `first_name + last_name`, direction o
# ==============================================================================
def test_case_id_022():
    """Test scenario for ID-022: first_name + last_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    first_name___last_name = "active_sample_value_for_first_name___last_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "first_name___last_name": first_name___last_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-023] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `displayName` through an API boundary when multi-part name wit
# Evidence: Verify the request/response schema and call site for `displayName`, direction of flow, end
# ==============================================================================
def test_case_id_023():
    """Test scenario for ID-023: displayName"""
    # ACTIVE TEST CASE: Represents identifiable user data
    displayName = "active_sample_value_for_displayName"
    payload = {
        "user_id": "USR_99214_TEST",
        "displayName": displayName,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-024] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `preferred_name` through an API boundary when hyphenated or ap
# Evidence: Verify the request/response schema and call site for `preferred_name`, direction of flow, 
# ==============================================================================
def test_case_id_024():
    """Test scenario for ID-024: preferred_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    preferred_name = "active_sample_value_for_preferred_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "preferred_name": preferred_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-025] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `legal_name` through an API boundary when name nested in profi
# Evidence: Verify the request/response schema and call site for `legal_name`, direction of flow, endp
# ==============================================================================
def test_case_id_025():
    """Test scenario for ID-025: legal_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    legal_name = "active_sample_value_for_legal_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "legal_name": legal_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-026] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `alias` through an API boundary when name joined to a user ID;
# Evidence: Verify the request/response schema and call site for `alias`, direction of flow, endpoint/
# ==============================================================================
def test_case_id_026():
    """Test scenario for ID-026: alias"""
    # ACTIVE TEST CASE: Represents identifiable user data
    alias = "active_sample_value_for_alias"
    payload = {
        "user_id": "USR_99214_TEST",
        "alias": alias,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-027] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `maiden_name` through an API boundary when name passed as a UR
# Evidence: Verify the request/response schema and call site for `maiden_name`, direction of flow, end
# ==============================================================================
def test_case_id_027():
    """Test scenario for ID-027: maiden_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    maiden_name = "active_sample_value_for_maiden_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "maiden_name": maiden_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-028] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `user.name` through an API boundary when name returned by a pr
# Evidence: Verify the request/response schema and call site for `user.name`, direction of flow, endpo
# ==============================================================================
def test_case_id_028():
    """Test scenario for ID-028: user.name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    user_name = "active_sample_value_for_user_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "user_name": user_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-029] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `profile.identity.name` through an API boundary when name incl
# Evidence: Verify the request/response schema and call site for `profile.identity.name`, direction of
# ==============================================================================
def test_case_id_029():
    """Test scenario for ID-029: profile.identity.name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    profile_identity_name = "active_sample_value_for_profile_identity_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "profile_identity_name": profile_identity_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-030] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `account_owner` through an API boundary when name assembled fr
# Evidence: Verify the request/response schema and call site for `account_owner`, direction of flow, e
# ==============================================================================
def test_case_id_030():
    """Test scenario for ID-030: account_owner"""
    # ACTIVE TEST CASE: Represents identifiable user data
    account_owner = "active_sample_value_for_account_owner"
    payload = {
        "user_id": "USR_99214_TEST",
        "account_owner": account_owner,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-031] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `full_name` when split across first/last-name field
# Evidence: Show the source value, transformation or derivation applied to `full_name`, and resulting 
# ==============================================================================
def test_case_id_031():
    """Test scenario for ID-031: full_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    full_name = "active_sample_value_for_full_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "full_name": full_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-032] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `first_name + last_name` when Unicode or accented c
# Evidence: Show the source value, transformation or derivation applied to `first_name + last_name`, a
# ==============================================================================
def test_case_id_032():
    """Test scenario for ID-032: first_name + last_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    first_name___last_name = "active_sample_value_for_first_name___last_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "first_name___last_name": first_name___last_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-033] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `displayName` when multi-part name with spaces; fol
# Evidence: Show the source value, transformation or derivation applied to `displayName`, and resultin
# ==============================================================================
def test_case_id_033():
    """Test scenario for ID-033: displayName"""
    # ACTIVE TEST CASE: Represents identifiable user data
    displayName = "active_sample_value_for_displayName"
    payload = {
        "user_id": "USR_99214_TEST",
        "displayName": displayName,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-034] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `preferred_name` when hyphenated or apostrophe-cont
# Evidence: Show the source value, transformation or derivation applied to `preferred_name`, and resul
# ==============================================================================
def test_case_id_034():
    """Test scenario for ID-034: preferred_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    preferred_name = "active_sample_value_for_preferred_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "preferred_name": preferred_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-035] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `legal_name` when name nested in profile JSON; foll
# Evidence: Show the source value, transformation or derivation applied to `legal_name`, and resulting
# ==============================================================================
def test_case_id_035():
    """Test scenario for ID-035: legal_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    legal_name = "active_sample_value_for_legal_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "legal_name": legal_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-036] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `alias` when name joined to a user ID; follow assig
# Evidence: Show the source value, transformation or derivation applied to `alias`, and resulting sink
# ==============================================================================
def test_case_id_036():
    """Test scenario for ID-036: alias"""
    # ACTIVE TEST CASE: Represents identifiable user data
    alias = "active_sample_value_for_alias"
    payload = {
        "user_id": "USR_99214_TEST",
        "alias": alias,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-037] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `maiden_name` when name passed as a URL parameter; 
# Evidence: Show the source value, transformation or derivation applied to `maiden_name`, and resultin
# ==============================================================================
def test_case_id_037():
    """Test scenario for ID-037: maiden_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    maiden_name = "active_sample_value_for_maiden_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "maiden_name": maiden_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-038] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `user.name` when name returned by a profile API; fo
# Evidence: Show the source value, transformation or derivation applied to `user.name`, and resulting 
# ==============================================================================
def test_case_id_038():
    """Test scenario for ID-038: user.name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    user_name = "active_sample_value_for_user_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "user_name": user_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-039] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `profile.identity.name` when name included in an ap
# Evidence: Show the source value, transformation or derivation applied to `profile.identity.name`, an
# ==============================================================================
def test_case_id_039():
    """Test scenario for ID-039: profile.identity.name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    profile_identity_name = "active_sample_value_for_profile_identity_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "profile_identity_name": profile_identity_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-040] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `account_owner` when name assembled from intermedia
# Evidence: Show the source value, transformation or derivation applied to `account_owner`, and result
# ==============================================================================
def test_case_id_040():
    """Test scenario for ID-040: account_owner"""
    # ACTIVE TEST CASE: Represents identifiable user data
    account_owner = "active_sample_value_for_account_owner"
    payload = {
        "user_id": "USR_99214_TEST",
        "account_owner": account_owner,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-041] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `full_name` when split across first
# Evidence: Identify the exact `full_name` write/read operation and target (table, document, cache, fi
# ==============================================================================
def test_case_id_041():
    """Test scenario for ID-041: full_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    full_name = "active_sample_value_for_full_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "full_name": full_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-042] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `first_name + last_name` when Unico
# Evidence: Identify the exact `first_name + last_name` write/read operation and target (table, docume
# ==============================================================================
def test_case_id_042():
    """Test scenario for ID-042: first_name + last_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    first_name___last_name = "active_sample_value_for_first_name___last_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "first_name___last_name": first_name___last_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-043] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `displayName` when multi-part name 
# Evidence: Identify the exact `displayName` write/read operation and target (table, document, cache, 
# ==============================================================================
def test_case_id_043():
    """Test scenario for ID-043: displayName"""
    # ACTIVE TEST CASE: Represents identifiable user data
    displayName = "active_sample_value_for_displayName"
    payload = {
        "user_id": "USR_99214_TEST",
        "displayName": displayName,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-044] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `preferred_name` when hyphenated or
# Evidence: Identify the exact `preferred_name` write/read operation and target (table, document, cach
# ==============================================================================
def test_case_id_044():
    """Test scenario for ID-044: preferred_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    preferred_name = "active_sample_value_for_preferred_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "preferred_name": preferred_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-045] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `legal_name` when name nested in pr
# Evidence: Identify the exact `legal_name` write/read operation and target (table, document, cache, f
# ==============================================================================
def test_case_id_045():
    """Test scenario for ID-045: legal_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    legal_name = "active_sample_value_for_legal_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "legal_name": legal_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-046] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `alias` when name joined to a user 
# Evidence: Identify the exact `alias` write/read operation and target (table, document, cache, file, 
# ==============================================================================
def test_case_id_046():
    """Test scenario for ID-046: alias"""
    # ACTIVE TEST CASE: Represents identifiable user data
    alias = "active_sample_value_for_alias"
    payload = {
        "user_id": "USR_99214_TEST",
        "alias": alias,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-047] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `maiden_name` when name passed as a
# Evidence: Identify the exact `maiden_name` write/read operation and target (table, document, cache, 
# ==============================================================================
def test_case_id_047():
    """Test scenario for ID-047: maiden_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    maiden_name = "active_sample_value_for_maiden_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "maiden_name": maiden_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-048] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `user.name` when name returned by a
# Evidence: Identify the exact `user.name` write/read operation and target (table, document, cache, fi
# ==============================================================================
def test_case_id_048():
    """Test scenario for ID-048: user.name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    user_name = "active_sample_value_for_user_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "user_name": user_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-049] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `profile.identity.name` when name i
# Evidence: Identify the exact `profile.identity.name` write/read operation and target (table, documen
# ==============================================================================
def test_case_id_049():
    """Test scenario for ID-049: profile.identity.name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    profile_identity_name = "active_sample_value_for_profile_identity_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "profile_identity_name": profile_identity_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-050] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `account_owner` when name assembled
# Evidence: Identify the exact `account_owner` write/read operation and target (table, document, cache
# ==============================================================================
def test_case_id_050():
    """Test scenario for ID-050: account_owner"""
    # ACTIVE TEST CASE: Represents identifiable user data
    account_owner = "active_sample_value_for_account_owner"
    payload = {
        "user_id": "USR_99214_TEST",
        "account_owner": account_owner,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-051] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `full_name` becomes identifiable or linkable when split acro
# Evidence: Record `full_name`'s join key/foreign key, related table or service, and the code path tha
# ==============================================================================
def test_case_id_051():
    """Test scenario for ID-051: full_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    full_name = "active_sample_value_for_full_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "full_name": full_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-052] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `first_name + last_name` becomes identifiable or linkable wh
# Evidence: Record `first_name + last_name`'s join key/foreign key, related table or service, and the 
# ==============================================================================
def test_case_id_052():
    """Test scenario for ID-052: first_name + last_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    first_name___last_name = "active_sample_value_for_first_name___last_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "first_name___last_name": first_name___last_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-053] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `displayName` becomes identifiable or linkable when multi-pa
# Evidence: Record `displayName`'s join key/foreign key, related table or service, and the code path t
# ==============================================================================
def test_case_id_053():
    """Test scenario for ID-053: displayName"""
    # ACTIVE TEST CASE: Represents identifiable user data
    displayName = "active_sample_value_for_displayName"
    payload = {
        "user_id": "USR_99214_TEST",
        "displayName": displayName,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-054] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `preferred_name` becomes identifiable or linkable when hyphe
# Evidence: Record `preferred_name`'s join key/foreign key, related table or service, and the code pat
# ==============================================================================
def test_case_id_054():
    """Test scenario for ID-054: preferred_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    preferred_name = "active_sample_value_for_preferred_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "preferred_name": preferred_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-055] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `legal_name` becomes identifiable or linkable when name nest
# Evidence: Record `legal_name`'s join key/foreign key, related table or service, and the code path th
# ==============================================================================
def test_case_id_055():
    """Test scenario for ID-055: legal_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    legal_name = "active_sample_value_for_legal_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "legal_name": legal_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-056] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `alias` becomes identifiable or linkable when name joined to
# Evidence: Record `alias`'s join key/foreign key, related table or service, and the code path that li
# ==============================================================================
def test_case_id_056():
    """Test scenario for ID-056: alias"""
    # ACTIVE TEST CASE: Represents identifiable user data
    alias = "active_sample_value_for_alias"
    payload = {
        "user_id": "USR_99214_TEST",
        "alias": alias,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-057] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `maiden_name` becomes identifiable or linkable when name pas
# Evidence: Record `maiden_name`'s join key/foreign key, related table or service, and the code path t
# ==============================================================================
def test_case_id_057():
    """Test scenario for ID-057: maiden_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    maiden_name = "active_sample_value_for_maiden_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "maiden_name": maiden_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-058] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `user.name` becomes identifiable or linkable when name retur
# Evidence: Record `user.name`'s join key/foreign key, related table or service, and the code path tha
# ==============================================================================
def test_case_id_058():
    """Test scenario for ID-058: user.name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    user_name = "active_sample_value_for_user_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "user_name": user_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-059] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `profile.identity.name` becomes identifiable or linkable whe
# Evidence: Record `profile.identity.name`'s join key/foreign key, related table or service, and the c
# ==============================================================================
def test_case_id_059():
    """Test scenario for ID-059: profile.identity.name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    profile_identity_name = "active_sample_value_for_profile_identity_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "profile_identity_name": profile_identity_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-060] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `account_owner` becomes identifiable or linkable when name a
# Evidence: Record `account_owner`'s join key/foreign key, related table or service, and the code path
# ==============================================================================
def test_case_id_060():
    """Test scenario for ID-060: account_owner"""
    # ACTIVE TEST CASE: Represents identifiable user data
    account_owner = "active_sample_value_for_account_owner"
    payload = {
        "user_id": "USR_99214_TEST",
        "account_owner": account_owner,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-061] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `full_name` to a third-party boundary when split across first/la
# Evidence: Verify the payload field `full_name`, outbound call site, destination/vendor, and whether 
# ==============================================================================
def test_case_id_061():
    """Test scenario for ID-061: full_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    full_name = "active_sample_value_for_full_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "full_name": full_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-062] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `first_name + last_name` to a third-party boundary when Unicode 
# Evidence: Verify the payload field `first_name + last_name`, outbound call site, destination/vendor,
# ==============================================================================
def test_case_id_062():
    """Test scenario for ID-062: first_name + last_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    first_name___last_name = "active_sample_value_for_first_name___last_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "first_name___last_name": first_name___last_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-063] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `displayName` to a third-party boundary when multi-part name wit
# Evidence: Verify the payload field `displayName`, outbound call site, destination/vendor, and whethe
# ==============================================================================
def test_case_id_063():
    """Test scenario for ID-063: displayName"""
    # ACTIVE TEST CASE: Represents identifiable user data
    displayName = "active_sample_value_for_displayName"
    payload = {
        "user_id": "USR_99214_TEST",
        "displayName": displayName,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-064] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `preferred_name` to a third-party boundary when hyphenated or ap
# Evidence: Verify the payload field `preferred_name`, outbound call site, destination/vendor, and whe
# ==============================================================================
def test_case_id_064():
    """Test scenario for ID-064: preferred_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    preferred_name = "active_sample_value_for_preferred_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "preferred_name": preferred_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-065] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `legal_name` to a third-party boundary when name nested in profi
# Evidence: Verify the payload field `legal_name`, outbound call site, destination/vendor, and whether
# ==============================================================================
def test_case_id_065():
    """Test scenario for ID-065: legal_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    legal_name = "active_sample_value_for_legal_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "legal_name": legal_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-066] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `alias` to a third-party boundary when name joined to a user ID;
# Evidence: Verify the payload field `alias`, outbound call site, destination/vendor, and whether the 
# ==============================================================================
def test_case_id_066():
    """Test scenario for ID-066: alias"""
    # ACTIVE TEST CASE: Represents identifiable user data
    alias = "active_sample_value_for_alias"
    payload = {
        "user_id": "USR_99214_TEST",
        "alias": alias,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-067] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `maiden_name` to a third-party boundary when name passed as a UR
# Evidence: Verify the payload field `maiden_name`, outbound call site, destination/vendor, and whethe
# ==============================================================================
def test_case_id_067():
    """Test scenario for ID-067: maiden_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    maiden_name = "active_sample_value_for_maiden_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "maiden_name": maiden_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-068] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `user.name` to a third-party boundary when name returned by a pr
# Evidence: Verify the payload field `user.name`, outbound call site, destination/vendor, and whether 
# ==============================================================================
def test_case_id_068():
    """Test scenario for ID-068: user.name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    user_name = "active_sample_value_for_user_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "user_name": user_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-069] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `profile.identity.name` to a third-party boundary when name incl
# Evidence: Verify the payload field `profile.identity.name`, outbound call site, destination/vendor, 
# ==============================================================================
def test_case_id_069():
    """Test scenario for ID-069: profile.identity.name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    profile_identity_name = "active_sample_value_for_profile_identity_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "profile_identity_name": profile_identity_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-070] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `account_owner` to a third-party boundary when name assembled fr
# Evidence: Verify the payload field `account_owner`, outbound call site, destination/vendor, and whet
# ==============================================================================
def test_case_id_070():
    """Test scenario for ID-070: account_owner"""
    # ACTIVE TEST CASE: Represents identifiable user data
    account_owner = "active_sample_value_for_account_owner"
    payload = {
        "user_id": "USR_99214_TEST",
        "account_owner": account_owner,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-071] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `full_name` when split across first/last-na
# Evidence: Record the observed representation and protection/transform function for `full_name`; dist
# ==============================================================================
def test_case_id_071():
    """Test scenario for ID-071: full_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    full_name = "active_sample_value_for_full_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "full_name": full_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-072] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `first_name + last_name` when Unicode or ac
# Evidence: Record the observed representation and protection/transform function for `first_name + las
# ==============================================================================
def test_case_id_072():
    """Test scenario for ID-072: first_name + last_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    first_name___last_name = "active_sample_value_for_first_name___last_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "first_name___last_name": first_name___last_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-073] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `displayName` when multi-part name with spa
# Evidence: Record the observed representation and protection/transform function for `displayName`; di
# ==============================================================================
def test_case_id_073():
    """Test scenario for ID-073: displayName"""
    # ACTIVE TEST CASE: Represents identifiable user data
    displayName = "active_sample_value_for_displayName"
    payload = {
        "user_id": "USR_99214_TEST",
        "displayName": displayName,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-074] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `preferred_name` when hyphenated or apostro
# Evidence: Record the observed representation and protection/transform function for `preferred_name`;
# ==============================================================================
def test_case_id_074():
    """Test scenario for ID-074: preferred_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    preferred_name = "active_sample_value_for_preferred_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "preferred_name": preferred_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-075] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `legal_name` when name nested in profile JS
# Evidence: Record the observed representation and protection/transform function for `legal_name`; dis
# ==============================================================================
def test_case_id_075():
    """Test scenario for ID-075: legal_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    legal_name = "active_sample_value_for_legal_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "legal_name": legal_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-076] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `alias` when name joined to a user ID; dete
# Evidence: Record the observed representation and protection/transform function for `alias`; distingu
# ==============================================================================
def test_case_id_076():
    """Test scenario for ID-076: alias"""
    # ACTIVE TEST CASE: Represents identifiable user data
    alias = "active_sample_value_for_alias"
    payload = {
        "user_id": "USR_99214_TEST",
        "alias": alias,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-077] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `maiden_name` when name passed as a URL par
# Evidence: Record the observed representation and protection/transform function for `maiden_name`; di
# ==============================================================================
def test_case_id_077():
    """Test scenario for ID-077: maiden_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    maiden_name = "active_sample_value_for_maiden_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "maiden_name": maiden_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-078] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `user.name` when name returned by a profile
# Evidence: Record the observed representation and protection/transform function for `user.name`; dist
# ==============================================================================
def test_case_id_078():
    """Test scenario for ID-078: user.name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    user_name = "active_sample_value_for_user_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "user_name": user_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-079] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `profile.identity.name` when name included 
# Evidence: Record the observed representation and protection/transform function for `profile.identity
# ==============================================================================
def test_case_id_079():
    """Test scenario for ID-079: profile.identity.name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    profile_identity_name = "active_sample_value_for_profile_identity_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "profile_identity_name": profile_identity_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-080] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `account_owner` when name assembled from in
# Evidence: Record the observed representation and protection/transform function for `account_owner`; 
# ==============================================================================
def test_case_id_080():
    """Test scenario for ID-080: account_owner"""
    # ACTIVE TEST CASE: Represents identifiable user data
    account_owner = "active_sample_value_for_account_owner"
    payload = {
        "user_id": "USR_99214_TEST",
        "account_owner": account_owner,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-081] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `product or company name` a
# Evidence: Verify that the only evidence is `product or company name` and that no populated, user-lin
# ==============================================================================
def test_case_id_081():
    """Test scenario for ID-081: product or company name"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_product_or_company_name = "MOCK_NON_PII_LITERAL_PRODUCT_OR_COMPANY_NAME"
    unrelated_system_config = {
        "config_key": "product or company name",
        "is_pii": False,
        "value": dummy_product_or_company_name
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: ID-082] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `fictional name in a fixtur
# Evidence: Verify that the only evidence is `fictional name in a fixture` and that no populated, user
# ==============================================================================
def test_case_id_082():
    """Test scenario for ID-082: fictional name in a fixture"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_fictional_name_in_a_fixture = "MOCK_NON_PII_LITERAL_FICTIONAL_NAME_IN_A_FIXTURE"
    unrelated_system_config = {
        "config_key": "fictional name in a fixture",
        "is_pii": False,
        "value": dummy_fictional_name_in_a_fixture
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: ID-083] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `name in README instruction
# Evidence: Verify that the only evidence is `name in README instructions` and that no populated, user
# ==============================================================================
def test_case_id_083():
    """Test scenario for ID-083: name in README instructions"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_name_in_README_instructions = "MOCK_NON_PII_LITERAL_NAME_IN_README_INSTRUCTIONS"
    unrelated_system_config = {
        "config_key": "name in README instructions",
        "is_pii": False,
        "value": dummy_name_in_README_instructions
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: ID-084] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `file_name or route_name va
# Evidence: Verify that the only evidence is `file_name or route_name variable` and that no populated,
# ==============================================================================
def test_case_id_084():
    """Test scenario for ID-084: file_name or route_name variable"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_file_name_or_route_name_variable = "MOCK_NON_PII_LITERAL_FILE_NAME_OR_ROUTE_NAME_VARIABLE"
    unrelated_system_config = {
        "config_key": "file_name or route_name variable",
        "is_pii": False,
        "value": dummy_file_name_or_route_name_variable
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: ID-085] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `public organization name` 
# Evidence: Verify that the only evidence is `public organization name` and that no populated, user-li
# ==============================================================================
def test_case_id_085():
    """Test scenario for ID-085: public organization name"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_public_organization_name = "MOCK_NON_PII_LITERAL_PUBLIC_ORGANIZATION_NAME"
    unrelated_system_config = {
        "config_key": "public organization name",
        "is_pii": False,
        "value": dummy_public_organization_name
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: ID-086] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `empty or null name field` 
# Evidence: Verify that the only evidence is `empty or null name field` and that no populated, user-li
# ==============================================================================
def test_case_id_086():
    """Test scenario for ID-086: empty or null name field"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_empty_or_null_name_field = "MOCK_NON_PII_LITERAL_EMPTY_OR_NULL_NAME_FIELD"
    unrelated_system_config = {
        "config_key": "empty or null name field",
        "is_pii": False,
        "value": dummy_empty_or_null_name_field
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: ID-087] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `unrelated identifier conta
# Evidence: Verify that the only evidence is `unrelated identifier containing 'name'` and that no popu
# ==============================================================================
def test_case_id_087():
    """Test scenario for ID-087: unrelated identifier containing 'name'"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_unrelated_identifier_containing__name_ = "MOCK_NON_PII_LITERAL_UNRELATED_IDENTIFIER_CONTAINING__NAME_"
    unrelated_system_config = {
        "config_key": "unrelated identifier containing 'name'",
        "is_pii": False,
        "value": dummy_unrelated_identifier_containing__name_
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: ID-088] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `sample avatar URL` appears
# Evidence: Verify that the only evidence is `sample avatar URL` and that no populated, user-linked `u
# ==============================================================================
def test_case_id_088():
    """Test scenario for ID-088: sample avatar URL"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_sample_avatar_URL = "MOCK_NON_PII_LITERAL_SAMPLE_AVATAR_URL"
    unrelated_system_config = {
        "config_key": "sample avatar URL",
        "is_pii": False,
        "value": dummy_sample_avatar_URL
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: ID-089] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `synthetic user record` app
# Evidence: Verify that the only evidence is `synthetic user record` and that no populated, user-linke
# ==============================================================================
def test_case_id_089():
    """Test scenario for ID-089: synthetic user record"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_synthetic_user_record = "MOCK_NON_PII_LITERAL_SYNTHETIC_USER_RECORD"
    unrelated_system_config = {
        "config_key": "synthetic user record",
        "is_pii": False,
        "value": dummy_synthetic_user_record
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: ID-090] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `name field in an unused sc
# Evidence: Verify that the only evidence is `name field in an unused schema` and that no populated, u
# ==============================================================================
def test_case_id_090():
    """Test scenario for ID-090: name field in an unused schema"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_name_field_in_an_unused_schema = "MOCK_NON_PII_LITERAL_NAME_FIELD_IN_AN_UNUSED_SCHEMA"
    unrelated_system_config = {
        "config_key": "name field in an unused schema",
        "is_pii": False,
        "value": dummy_name_field_in_an_unused_schema
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: ID-091] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `full_name`: sp
# Evidence: Record the exact `full_name` source location, available type/context, missing runtime or l
# ==============================================================================
def test_case_id_091():
    """Test scenario for ID-091: full_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    full_name = "active_sample_value_for_full_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "full_name": full_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-092] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `first_name + l
# Evidence: Record the exact `first_name + last_name` source location, available type/context, missing
# ==============================================================================
def test_case_id_092():
    """Test scenario for ID-092: first_name + last_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    first_name___last_name = "active_sample_value_for_first_name___last_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "first_name___last_name": first_name___last_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-093] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `displayName`: 
# Evidence: Record the exact `displayName` source location, available type/context, missing runtime or
# ==============================================================================
def test_case_id_093():
    """Test scenario for ID-093: displayName"""
    # ACTIVE TEST CASE: Represents identifiable user data
    displayName = "active_sample_value_for_displayName"
    payload = {
        "user_id": "USR_99214_TEST",
        "displayName": displayName,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-094] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `preferred_name
# Evidence: Record the exact `preferred_name` source location, available type/context, missing runtime
# ==============================================================================
def test_case_id_094():
    """Test scenario for ID-094: preferred_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    preferred_name = "active_sample_value_for_preferred_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "preferred_name": preferred_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-095] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `legal_name`: n
# Evidence: Record the exact `legal_name` source location, available type/context, missing runtime or 
# ==============================================================================
def test_case_id_095():
    """Test scenario for ID-095: legal_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    legal_name = "active_sample_value_for_legal_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "legal_name": legal_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-096] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `alias`: name j
# Evidence: Record the exact `alias` source location, available type/context, missing runtime or linka
# ==============================================================================
def test_case_id_096():
    """Test scenario for ID-096: alias"""
    # ACTIVE TEST CASE: Represents identifiable user data
    alias = "active_sample_value_for_alias"
    payload = {
        "user_id": "USR_99214_TEST",
        "alias": alias,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-097] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `maiden_name`: 
# Evidence: Record the exact `maiden_name` source location, available type/context, missing runtime or
# ==============================================================================
def test_case_id_097():
    """Test scenario for ID-097: maiden_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    maiden_name = "active_sample_value_for_maiden_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "maiden_name": maiden_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-098] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `user.name`: na
# Evidence: Record the exact `user.name` source location, available type/context, missing runtime or l
# ==============================================================================
def test_case_id_098():
    """Test scenario for ID-098: user.name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    user_name = "active_sample_value_for_user_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "user_name": user_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-099] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `profile.identi
# Evidence: Record the exact `profile.identity.name` source location, available type/context, missing 
# ==============================================================================
def test_case_id_099():
    """Test scenario for ID-099: profile.identity.name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    profile_identity_name = "active_sample_value_for_profile_identity_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "profile_identity_name": profile_identity_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: ID-100] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `account_owner`
# Evidence: Record the exact `account_owner` source location, available type/context, missing runtime 
# ==============================================================================
def test_case_id_100():
    """Test scenario for ID-100: account_owner"""
    # ACTIVE TEST CASE: Represents identifiable user data
    account_owner = "active_sample_value_for_account_owner"
    payload = {
        "user_id": "USR_99214_TEST",
        "account_owner": account_owner,
        "is_active_pii": True
    }
    return payload
