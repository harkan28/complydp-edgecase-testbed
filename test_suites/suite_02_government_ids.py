"""
COMPLYDP EDGE-CASE TEST SUITE: GOVERNMENT IDENTIFIERS (GOV)
Contains all 100 test scenarios (GOV-001 to GOV-100).
Includes Positive PII cases, API flows, Masked cases, and Negative Control Traps.
"""

import re
import json
import hashlib
from typing import Dict, Any, List, Optional

# ==============================================================================
# [TEST_ID: GOV-001] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `pan_number` in the repository schema or source code, includi
# Evidence: Verify the exact `pan_number` declaration, its type/validation/usage, and whether it is li
# ==============================================================================
def test_case_gov_001():
    """Test scenario for GOV-001: pan_number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    pan_number = "active_sample_value_for_pan_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "pan_number": pan_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-002] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `aadhaar_number` in the repository schema or source code, inc
# Evidence: Verify the exact `aadhaar_number` declaration, its type/validation/usage, and whether it i
# ==============================================================================
def test_case_gov_002():
    """Test scenario for GOV-002: aadhaar_number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    aadhaar_number = "active_sample_value_for_aadhaar_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "aadhaar_number": aadhaar_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-003] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `passport_no` in the repository schema or source code, includ
# Evidence: Verify the exact `passport_no` declaration, its type/validation/usage, and whether it is l
# ==============================================================================
def test_case_gov_003():
    """Test scenario for GOV-003: passport_no"""
    # ACTIVE TEST CASE: Represents identifiable user data
    passport_no = "active_sample_value_for_passport_no"
    payload = {
        "user_id": "USR_99214_TEST",
        "passport_no": passport_no,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-004] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `driving_license` in the repository schema or source code, in
# Evidence: Verify the exact `driving_license` declaration, its type/validation/usage, and whether it 
# ==============================================================================
def test_case_gov_004():
    """Test scenario for GOV-004: driving_license"""
    # ACTIVE TEST CASE: Represents identifiable user data
    driving_license = "active_sample_value_for_driving_license"
    payload = {
        "user_id": "USR_99214_TEST",
        "driving_license": driving_license,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-005] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `voter_id` in the repository schema or source code, including
# Evidence: Verify the exact `voter_id` declaration, its type/validation/usage, and whether it is link
# ==============================================================================
def test_case_gov_005():
    """Test scenario for GOV-005: voter_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    voter_id = "active_sample_value_for_voter_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "voter_id": voter_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-006] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `government_id` in the repository schema or source code, incl
# Evidence: Verify the exact `government_id` declaration, its type/validation/usage, and whether it is
# ==============================================================================
def test_case_gov_006():
    """Test scenario for GOV-006: government_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    government_id = "active_sample_value_for_government_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "government_id": government_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-007] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `tax_id` in the repository schema or source code, including i
# Evidence: Verify the exact `tax_id` declaration, its type/validation/usage, and whether it is linked
# ==============================================================================
def test_case_gov_007():
    """Test scenario for GOV-007: tax_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    tax_id = "active_sample_value_for_tax_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "tax_id": tax_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-008] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `identity_document.number` in the repository schema or source
# Evidence: Verify the exact `identity_document.number` declaration, its type/validation/usage, and wh
# ==============================================================================
def test_case_gov_008():
    """Test scenario for GOV-008: identity_document.number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    identity_document_number = "active_sample_value_for_identity_document_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "identity_document_number": identity_document_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-009] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `kyc.document_id` in the repository schema or source code, in
# Evidence: Verify the exact `kyc.document_id` declaration, its type/validation/usage, and whether it 
# ==============================================================================
def test_case_gov_009():
    """Test scenario for GOV-009: kyc.document_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    kyc_document_id = "active_sample_value_for_kyc_document_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "kyc_document_id": kyc_document_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-010] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `national_identifier` in the repository schema or source code
# Evidence: Verify the exact `national_identifier` declaration, its type/validation/usage, and whether
# ==============================================================================
def test_case_gov_010():
    """Test scenario for GOV-010: national_identifier"""
    # ACTIVE TEST CASE: Represents identifiable user data
    national_identifier = "active_sample_value_for_national_identifier"
    payload = {
        "user_id": "USR_99214_TEST",
        "national_identifier": national_identifier,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-011] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `pan_number` when format-valid identifier in a user record
# Evidence: Capture the full JSON/object path for `pan_number`, the parent record or user key, and the
# ==============================================================================
def test_case_gov_011():
    """Test scenario for GOV-011: pan_number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    pan_number = "active_sample_value_for_pan_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "pan_number": pan_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-012] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `aadhaar_number` when masked identifier with only final di
# Evidence: Capture the full JSON/object path for `aadhaar_number`, the parent record or user key, and
# ==============================================================================
def test_case_gov_012():
    """Test scenario for GOV-012: aadhaar_number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    aadhaar_number = "active_sample_value_for_aadhaar_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "aadhaar_number": aadhaar_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-013] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `passport_no` when identifier encrypted before database in
# Evidence: Capture the full JSON/object path for `passport_no`, the parent record or user key, and th
# ==============================================================================
def test_case_gov_013():
    """Test scenario for GOV-013: passport_no"""
    # ACTIVE TEST CASE: Represents identifiable user data
    passport_no = "active_sample_value_for_passport_no"
    payload = {
        "user_id": "USR_99214_TEST",
        "passport_no": passport_no,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-014] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `driving_license` when identifier split across adjacent fi
# Evidence: Capture the full JSON/object path for `driving_license`, the parent record or user key, an
# ==============================================================================
def test_case_gov_014():
    """Test scenario for GOV-014: driving_license"""
    # ACTIVE TEST CASE: Represents identifiable user data
    driving_license = "active_sample_value_for_driving_license"
    payload = {
        "user_id": "USR_99214_TEST",
        "driving_license": driving_license,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-015] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `voter_id` when identifier nested in KYC JSON; inspect nes
# Evidence: Capture the full JSON/object path for `voter_id`, the parent record or user key, and the c
# ==============================================================================
def test_case_gov_015():
    """Test scenario for GOV-015: voter_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    voter_id = "active_sample_value_for_voter_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "voter_id": voter_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-016] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `government_id` when identifier passed to a verification A
# Evidence: Capture the full JSON/object path for `government_id`, the parent record or user key, and 
# ==============================================================================
def test_case_gov_016():
    """Test scenario for GOV-016: government_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    government_id = "active_sample_value_for_government_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "government_id": government_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-017] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `tax_id` when identifier extracted from an uploaded image 
# Evidence: Capture the full JSON/object path for `tax_id`, the parent record or user key, and the cod
# ==============================================================================
def test_case_gov_017():
    """Test scenario for GOV-017: tax_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    tax_id = "active_sample_value_for_tax_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "tax_id": tax_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-018] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `identity_document.number` when identifier referenced by a
# Evidence: Capture the full JSON/object path for `identity_document.number`, the parent record or use
# ==============================================================================
def test_case_gov_018():
    """Test scenario for GOV-018: identity_document.number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    identity_document_number = "active_sample_value_for_identity_document_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "identity_document_number": identity_document_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-019] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `kyc.document_id` when identifier appears in a migration o
# Evidence: Capture the full JSON/object path for `kyc.document_id`, the parent record or user key, an
# ==============================================================================
def test_case_gov_019():
    """Test scenario for GOV-019: kyc.document_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    kyc_document_id = "active_sample_value_for_kyc_document_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "kyc_document_id": kyc_document_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-020] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `national_identifier` when random string that coincidental
# Evidence: Capture the full JSON/object path for `national_identifier`, the parent record or user key
# ==============================================================================
def test_case_gov_020():
    """Test scenario for GOV-020: national_identifier"""
    # ACTIVE TEST CASE: Represents identifiable user data
    national_identifier = "active_sample_value_for_national_identifier"
    payload = {
        "user_id": "USR_99214_TEST",
        "national_identifier": national_identifier,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-021] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `pan_number` through an API boundary when format-valid identif
# Evidence: Verify the request/response schema and call site for `pan_number`, direction of flow, endp
# ==============================================================================
def test_case_gov_021():
    """Test scenario for GOV-021: pan_number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    pan_number = "active_sample_value_for_pan_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "pan_number": pan_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-022] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `aadhaar_number` through an API boundary when masked identifie
# Evidence: Verify the request/response schema and call site for `aadhaar_number`, direction of flow, 
# ==============================================================================
def test_case_gov_022():
    """Test scenario for GOV-022: aadhaar_number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    aadhaar_number = "active_sample_value_for_aadhaar_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "aadhaar_number": aadhaar_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-023] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `passport_no` through an API boundary when identifier encrypte
# Evidence: Verify the request/response schema and call site for `passport_no`, direction of flow, end
# ==============================================================================
def test_case_gov_023():
    """Test scenario for GOV-023: passport_no"""
    # ACTIVE TEST CASE: Represents identifiable user data
    passport_no = "active_sample_value_for_passport_no"
    payload = {
        "user_id": "USR_99214_TEST",
        "passport_no": passport_no,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-024] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `driving_license` through an API boundary when identifier spli
# Evidence: Verify the request/response schema and call site for `driving_license`, direction of flow,
# ==============================================================================
def test_case_gov_024():
    """Test scenario for GOV-024: driving_license"""
    # ACTIVE TEST CASE: Represents identifiable user data
    driving_license = "active_sample_value_for_driving_license"
    payload = {
        "user_id": "USR_99214_TEST",
        "driving_license": driving_license,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-025] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `voter_id` through an API boundary when identifier nested in K
# Evidence: Verify the request/response schema and call site for `voter_id`, direction of flow, endpoi
# ==============================================================================
def test_case_gov_025():
    """Test scenario for GOV-025: voter_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    voter_id = "active_sample_value_for_voter_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "voter_id": voter_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-026] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `government_id` through an API boundary when identifier passed
# Evidence: Verify the request/response schema and call site for `government_id`, direction of flow, e
# ==============================================================================
def test_case_gov_026():
    """Test scenario for GOV-026: government_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    government_id = "active_sample_value_for_government_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "government_id": government_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-027] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `tax_id` through an API boundary when identifier extracted fro
# Evidence: Verify the request/response schema and call site for `tax_id`, direction of flow, endpoint
# ==============================================================================
def test_case_gov_027():
    """Test scenario for GOV-027: tax_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    tax_id = "active_sample_value_for_tax_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "tax_id": tax_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-028] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `identity_document.number` through an API boundary when identi
# Evidence: Verify the request/response schema and call site for `identity_document.number`, direction
# ==============================================================================
def test_case_gov_028():
    """Test scenario for GOV-028: identity_document.number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    identity_document_number = "active_sample_value_for_identity_document_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "identity_document_number": identity_document_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-029] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `kyc.document_id` through an API boundary when identifier appe
# Evidence: Verify the request/response schema and call site for `kyc.document_id`, direction of flow,
# ==============================================================================
def test_case_gov_029():
    """Test scenario for GOV-029: kyc.document_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    kyc_document_id = "active_sample_value_for_kyc_document_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "kyc_document_id": kyc_document_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-030] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `national_identifier` through an API boundary when random stri
# Evidence: Verify the request/response schema and call site for `national_identifier`, direction of f
# ==============================================================================
def test_case_gov_030():
    """Test scenario for GOV-030: national_identifier"""
    # ACTIVE TEST CASE: Represents identifiable user data
    national_identifier = "active_sample_value_for_national_identifier"
    payload = {
        "user_id": "USR_99214_TEST",
        "national_identifier": national_identifier,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-031] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `pan_number` when format-valid identifier in a user
# Evidence: Show the source value, transformation or derivation applied to `pan_number`, and resulting
# ==============================================================================
def test_case_gov_031():
    """Test scenario for GOV-031: pan_number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    pan_number = "active_sample_value_for_pan_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "pan_number": pan_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-032] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `aadhaar_number` when masked identifier with only f
# Evidence: Show the source value, transformation or derivation applied to `aadhaar_number`, and resul
# ==============================================================================
def test_case_gov_032():
    """Test scenario for GOV-032: aadhaar_number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    aadhaar_number = "active_sample_value_for_aadhaar_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "aadhaar_number": aadhaar_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-033] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `passport_no` when identifier encrypted before data
# Evidence: Show the source value, transformation or derivation applied to `passport_no`, and resultin
# ==============================================================================
def test_case_gov_033():
    """Test scenario for GOV-033: passport_no"""
    # ACTIVE TEST CASE: Represents identifiable user data
    passport_no = "active_sample_value_for_passport_no"
    payload = {
        "user_id": "USR_99214_TEST",
        "passport_no": passport_no,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-034] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `driving_license` when identifier split across adja
# Evidence: Show the source value, transformation or derivation applied to `driving_license`, and resu
# ==============================================================================
def test_case_gov_034():
    """Test scenario for GOV-034: driving_license"""
    # ACTIVE TEST CASE: Represents identifiable user data
    driving_license = "active_sample_value_for_driving_license"
    payload = {
        "user_id": "USR_99214_TEST",
        "driving_license": driving_license,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-035] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `voter_id` when identifier nested in KYC JSON; foll
# Evidence: Show the source value, transformation or derivation applied to `voter_id`, and resulting s
# ==============================================================================
def test_case_gov_035():
    """Test scenario for GOV-035: voter_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    voter_id = "active_sample_value_for_voter_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "voter_id": voter_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-036] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `government_id` when identifier passed to a verific
# Evidence: Show the source value, transformation or derivation applied to `government_id`, and result
# ==============================================================================
def test_case_gov_036():
    """Test scenario for GOV-036: government_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    government_id = "active_sample_value_for_government_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "government_id": government_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-037] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `tax_id` when identifier extracted from an uploaded
# Evidence: Show the source value, transformation or derivation applied to `tax_id`, and resulting sin
# ==============================================================================
def test_case_gov_037():
    """Test scenario for GOV-037: tax_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    tax_id = "active_sample_value_for_tax_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "tax_id": tax_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-038] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `identity_document.number` when identifier referenc
# Evidence: Show the source value, transformation or derivation applied to `identity_document.number`,
# ==============================================================================
def test_case_gov_038():
    """Test scenario for GOV-038: identity_document.number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    identity_document_number = "active_sample_value_for_identity_document_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "identity_document_number": identity_document_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-039] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `kyc.document_id` when identifier appears in a migr
# Evidence: Show the source value, transformation or derivation applied to `kyc.document_id`, and resu
# ==============================================================================
def test_case_gov_039():
    """Test scenario for GOV-039: kyc.document_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    kyc_document_id = "active_sample_value_for_kyc_document_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "kyc_document_id": kyc_document_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-040] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `national_identifier` when random string that coinc
# Evidence: Show the source value, transformation or derivation applied to `national_identifier`, and 
# ==============================================================================
def test_case_gov_040():
    """Test scenario for GOV-040: national_identifier"""
    # ACTIVE TEST CASE: Represents identifiable user data
    national_identifier = "active_sample_value_for_national_identifier"
    payload = {
        "user_id": "USR_99214_TEST",
        "national_identifier": national_identifier,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-041] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `pan_number` when format-valid iden
# Evidence: Identify the exact `pan_number` write/read operation and target (table, document, cache, f
# ==============================================================================
def test_case_gov_041():
    """Test scenario for GOV-041: pan_number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    pan_number = "active_sample_value_for_pan_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "pan_number": pan_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-042] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `aadhaar_number` when masked identi
# Evidence: Identify the exact `aadhaar_number` write/read operation and target (table, document, cach
# ==============================================================================
def test_case_gov_042():
    """Test scenario for GOV-042: aadhaar_number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    aadhaar_number = "active_sample_value_for_aadhaar_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "aadhaar_number": aadhaar_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-043] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `passport_no` when identifier encry
# Evidence: Identify the exact `passport_no` write/read operation and target (table, document, cache, 
# ==============================================================================
def test_case_gov_043():
    """Test scenario for GOV-043: passport_no"""
    # ACTIVE TEST CASE: Represents identifiable user data
    passport_no = "active_sample_value_for_passport_no"
    payload = {
        "user_id": "USR_99214_TEST",
        "passport_no": passport_no,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-044] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `driving_license` when identifier s
# Evidence: Identify the exact `driving_license` write/read operation and target (table, document, cac
# ==============================================================================
def test_case_gov_044():
    """Test scenario for GOV-044: driving_license"""
    # ACTIVE TEST CASE: Represents identifiable user data
    driving_license = "active_sample_value_for_driving_license"
    payload = {
        "user_id": "USR_99214_TEST",
        "driving_license": driving_license,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-045] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `voter_id` when identifier nested i
# Evidence: Identify the exact `voter_id` write/read operation and target (table, document, cache, fil
# ==============================================================================
def test_case_gov_045():
    """Test scenario for GOV-045: voter_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    voter_id = "active_sample_value_for_voter_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "voter_id": voter_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-046] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `government_id` when identifier pas
# Evidence: Identify the exact `government_id` write/read operation and target (table, document, cache
# ==============================================================================
def test_case_gov_046():
    """Test scenario for GOV-046: government_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    government_id = "active_sample_value_for_government_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "government_id": government_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-047] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `tax_id` when identifier extracted 
# Evidence: Identify the exact `tax_id` write/read operation and target (table, document, cache, file,
# ==============================================================================
def test_case_gov_047():
    """Test scenario for GOV-047: tax_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    tax_id = "active_sample_value_for_tax_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "tax_id": tax_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-048] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `identity_document.number` when ide
# Evidence: Identify the exact `identity_document.number` write/read operation and target (table, docu
# ==============================================================================
def test_case_gov_048():
    """Test scenario for GOV-048: identity_document.number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    identity_document_number = "active_sample_value_for_identity_document_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "identity_document_number": identity_document_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-049] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `kyc.document_id` when identifier a
# Evidence: Identify the exact `kyc.document_id` write/read operation and target (table, document, cac
# ==============================================================================
def test_case_gov_049():
    """Test scenario for GOV-049: kyc.document_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    kyc_document_id = "active_sample_value_for_kyc_document_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "kyc_document_id": kyc_document_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-050] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `national_identifier` when random s
# Evidence: Identify the exact `national_identifier` write/read operation and target (table, document,
# ==============================================================================
def test_case_gov_050():
    """Test scenario for GOV-050: national_identifier"""
    # ACTIVE TEST CASE: Represents identifiable user data
    national_identifier = "active_sample_value_for_national_identifier"
    payload = {
        "user_id": "USR_99214_TEST",
        "national_identifier": national_identifier,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-051] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `pan_number` becomes identifiable or linkable when format-va
# Evidence: Record `pan_number`'s join key/foreign key, related table or service, and the code path th
# ==============================================================================
def test_case_gov_051():
    """Test scenario for GOV-051: pan_number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    pan_number = "active_sample_value_for_pan_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "pan_number": pan_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-052] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `aadhaar_number` becomes identifiable or linkable when maske
# Evidence: Record `aadhaar_number`'s join key/foreign key, related table or service, and the code pat
# ==============================================================================
def test_case_gov_052():
    """Test scenario for GOV-052: aadhaar_number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    aadhaar_number = "active_sample_value_for_aadhaar_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "aadhaar_number": aadhaar_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-053] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `passport_no` becomes identifiable or linkable when identifi
# Evidence: Record `passport_no`'s join key/foreign key, related table or service, and the code path t
# ==============================================================================
def test_case_gov_053():
    """Test scenario for GOV-053: passport_no"""
    # ACTIVE TEST CASE: Represents identifiable user data
    passport_no = "active_sample_value_for_passport_no"
    payload = {
        "user_id": "USR_99214_TEST",
        "passport_no": passport_no,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-054] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `driving_license` becomes identifiable or linkable when iden
# Evidence: Record `driving_license`'s join key/foreign key, related table or service, and the code pa
# ==============================================================================
def test_case_gov_054():
    """Test scenario for GOV-054: driving_license"""
    # ACTIVE TEST CASE: Represents identifiable user data
    driving_license = "active_sample_value_for_driving_license"
    payload = {
        "user_id": "USR_99214_TEST",
        "driving_license": driving_license,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-055] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `voter_id` becomes identifiable or linkable when identifier 
# Evidence: Record `voter_id`'s join key/foreign key, related table or service, and the code path that
# ==============================================================================
def test_case_gov_055():
    """Test scenario for GOV-055: voter_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    voter_id = "active_sample_value_for_voter_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "voter_id": voter_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-056] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `government_id` becomes identifiable or linkable when identi
# Evidence: Record `government_id`'s join key/foreign key, related table or service, and the code path
# ==============================================================================
def test_case_gov_056():
    """Test scenario for GOV-056: government_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    government_id = "active_sample_value_for_government_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "government_id": government_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-057] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `tax_id` becomes identifiable or linkable when identifier ex
# Evidence: Record `tax_id`'s join key/foreign key, related table or service, and the code path that l
# ==============================================================================
def test_case_gov_057():
    """Test scenario for GOV-057: tax_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    tax_id = "active_sample_value_for_tax_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "tax_id": tax_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-058] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `identity_document.number` becomes identifiable or linkable 
# Evidence: Record `identity_document.number`'s join key/foreign key, related table or service, and th
# ==============================================================================
def test_case_gov_058():
    """Test scenario for GOV-058: identity_document.number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    identity_document_number = "active_sample_value_for_identity_document_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "identity_document_number": identity_document_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-059] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `kyc.document_id` becomes identifiable or linkable when iden
# Evidence: Record `kyc.document_id`'s join key/foreign key, related table or service, and the code pa
# ==============================================================================
def test_case_gov_059():
    """Test scenario for GOV-059: kyc.document_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    kyc_document_id = "active_sample_value_for_kyc_document_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "kyc_document_id": kyc_document_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-060] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `national_identifier` becomes identifiable or linkable when 
# Evidence: Record `national_identifier`'s join key/foreign key, related table or service, and the cod
# ==============================================================================
def test_case_gov_060():
    """Test scenario for GOV-060: national_identifier"""
    # ACTIVE TEST CASE: Represents identifiable user data
    national_identifier = "active_sample_value_for_national_identifier"
    payload = {
        "user_id": "USR_99214_TEST",
        "national_identifier": national_identifier,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-061] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `pan_number` to a third-party boundary when format-valid identif
# Evidence: Verify the payload field `pan_number`, outbound call site, destination/vendor, and whether
# ==============================================================================
def test_case_gov_061():
    """Test scenario for GOV-061: pan_number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    pan_number = "active_sample_value_for_pan_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "pan_number": pan_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-062] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `aadhaar_number` to a third-party boundary when masked identifie
# Evidence: Verify the payload field `aadhaar_number`, outbound call site, destination/vendor, and whe
# ==============================================================================
def test_case_gov_062():
    """Test scenario for GOV-062: aadhaar_number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    aadhaar_number = "active_sample_value_for_aadhaar_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "aadhaar_number": aadhaar_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-063] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `passport_no` to a third-party boundary when identifier encrypte
# Evidence: Verify the payload field `passport_no`, outbound call site, destination/vendor, and whethe
# ==============================================================================
def test_case_gov_063():
    """Test scenario for GOV-063: passport_no"""
    # ACTIVE TEST CASE: Represents identifiable user data
    passport_no = "active_sample_value_for_passport_no"
    payload = {
        "user_id": "USR_99214_TEST",
        "passport_no": passport_no,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-064] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `driving_license` to a third-party boundary when identifier spli
# Evidence: Verify the payload field `driving_license`, outbound call site, destination/vendor, and wh
# ==============================================================================
def test_case_gov_064():
    """Test scenario for GOV-064: driving_license"""
    # ACTIVE TEST CASE: Represents identifiable user data
    driving_license = "active_sample_value_for_driving_license"
    payload = {
        "user_id": "USR_99214_TEST",
        "driving_license": driving_license,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-065] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `voter_id` to a third-party boundary when identifier nested in K
# Evidence: Verify the payload field `voter_id`, outbound call site, destination/vendor, and whether t
# ==============================================================================
def test_case_gov_065():
    """Test scenario for GOV-065: voter_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    voter_id = "active_sample_value_for_voter_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "voter_id": voter_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-066] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `government_id` to a third-party boundary when identifier passed
# Evidence: Verify the payload field `government_id`, outbound call site, destination/vendor, and whet
# ==============================================================================
def test_case_gov_066():
    """Test scenario for GOV-066: government_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    government_id = "active_sample_value_for_government_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "government_id": government_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-067] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `tax_id` to a third-party boundary when identifier extracted fro
# Evidence: Verify the payload field `tax_id`, outbound call site, destination/vendor, and whether the
# ==============================================================================
def test_case_gov_067():
    """Test scenario for GOV-067: tax_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    tax_id = "active_sample_value_for_tax_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "tax_id": tax_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-068] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `identity_document.number` to a third-party boundary when identi
# Evidence: Verify the payload field `identity_document.number`, outbound call site, destination/vendo
# ==============================================================================
def test_case_gov_068():
    """Test scenario for GOV-068: identity_document.number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    identity_document_number = "active_sample_value_for_identity_document_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "identity_document_number": identity_document_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-069] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `kyc.document_id` to a third-party boundary when identifier appe
# Evidence: Verify the payload field `kyc.document_id`, outbound call site, destination/vendor, and wh
# ==============================================================================
def test_case_gov_069():
    """Test scenario for GOV-069: kyc.document_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    kyc_document_id = "active_sample_value_for_kyc_document_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "kyc_document_id": kyc_document_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-070] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `national_identifier` to a third-party boundary when random stri
# Evidence: Verify the payload field `national_identifier`, outbound call site, destination/vendor, an
# ==============================================================================
def test_case_gov_070():
    """Test scenario for GOV-070: national_identifier"""
    # ACTIVE TEST CASE: Represents identifiable user data
    national_identifier = "active_sample_value_for_national_identifier"
    payload = {
        "user_id": "USR_99214_TEST",
        "national_identifier": national_identifier,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-071] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `pan_number` when format-valid identifier i
# Evidence: Record the observed representation and protection/transform function for `pan_number`; dis
# ==============================================================================
def test_case_gov_071():
    """Test scenario for GOV-071: pan_number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    pan_number = "active_sample_value_for_pan_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "pan_number": pan_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-072] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `aadhaar_number` when masked identifier wit
# Evidence: Record the observed representation and protection/transform function for `aadhaar_number`;
# ==============================================================================
def test_case_gov_072():
    """Test scenario for GOV-072: aadhaar_number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    aadhaar_number = "active_sample_value_for_aadhaar_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "aadhaar_number": aadhaar_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-073] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `passport_no` when identifier encrypted bef
# Evidence: Record the observed representation and protection/transform function for `passport_no`; di
# ==============================================================================
def test_case_gov_073():
    """Test scenario for GOV-073: passport_no"""
    # ACTIVE TEST CASE: Represents identifiable user data
    passport_no = "active_sample_value_for_passport_no"
    payload = {
        "user_id": "USR_99214_TEST",
        "passport_no": passport_no,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-074] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `driving_license` when identifier split acr
# Evidence: Record the observed representation and protection/transform function for `driving_license`
# ==============================================================================
def test_case_gov_074():
    """Test scenario for GOV-074: driving_license"""
    # ACTIVE TEST CASE: Represents identifiable user data
    driving_license = "active_sample_value_for_driving_license"
    payload = {
        "user_id": "USR_99214_TEST",
        "driving_license": driving_license,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-075] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `voter_id` when identifier nested in KYC JS
# Evidence: Record the observed representation and protection/transform function for `voter_id`; disti
# ==============================================================================
def test_case_gov_075():
    """Test scenario for GOV-075: voter_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    voter_id = "active_sample_value_for_voter_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "voter_id": voter_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-076] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `government_id` when identifier passed to a
# Evidence: Record the observed representation and protection/transform function for `government_id`; 
# ==============================================================================
def test_case_gov_076():
    """Test scenario for GOV-076: government_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    government_id = "active_sample_value_for_government_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "government_id": government_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-077] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `tax_id` when identifier extracted from an 
# Evidence: Record the observed representation and protection/transform function for `tax_id`; disting
# ==============================================================================
def test_case_gov_077():
    """Test scenario for GOV-077: tax_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    tax_id = "active_sample_value_for_tax_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "tax_id": tax_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-078] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `identity_document.number` when identifier 
# Evidence: Record the observed representation and protection/transform function for `identity_documen
# ==============================================================================
def test_case_gov_078():
    """Test scenario for GOV-078: identity_document.number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    identity_document_number = "active_sample_value_for_identity_document_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "identity_document_number": identity_document_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-079] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `kyc.document_id` when identifier appears i
# Evidence: Record the observed representation and protection/transform function for `kyc.document_id`
# ==============================================================================
def test_case_gov_079():
    """Test scenario for GOV-079: kyc.document_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    kyc_document_id = "active_sample_value_for_kyc_document_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "kyc_document_id": kyc_document_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-080] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `national_identifier` when random string th
# Evidence: Record the observed representation and protection/transform function for `national_identif
# ==============================================================================
def test_case_gov_080():
    """Test scenario for GOV-080: national_identifier"""
    # ACTIVE TEST CASE: Represents identifiable user data
    national_identifier = "active_sample_value_for_national_identifier"
    payload = {
        "user_id": "USR_99214_TEST",
        "national_identifier": national_identifier,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-081] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `PAN mentioned in instructi
# Evidence: Verify that the only evidence is `PAN mentioned in instructions only` and that no populate
# ==============================================================================
def test_case_gov_081():
    """Test scenario for GOV-081: PAN mentioned in instructions only"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_PAN_mentioned_in_instructions_only = "MOCK_NON_PII_LITERAL_PAN_MENTIONED_IN_INSTRUCTIONS_ONLY"
    unrelated_system_config = {
        "config_key": "PAN mentioned in instructions only",
        "is_pii": False,
        "value": dummy_PAN_mentioned_in_instructions_only
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: GOV-082] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `Aadhaar in a help-page exa
# Evidence: Verify that the only evidence is `Aadhaar in a help-page example` and that no populated, u
# ==============================================================================
def test_case_gov_082():
    """Test scenario for GOV-082: Aadhaar in a help-page example"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_Aadhaar_in_a_help_page_example = "MOCK_NON_PII_LITERAL_AADHAAR_IN_A_HELP_PAGE_EXAMPLE"
    unrelated_system_config = {
        "config_key": "Aadhaar in a help-page example",
        "is_pii": False,
        "value": dummy_Aadhaar_in_a_help_page_example
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: GOV-083] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `passport mentioned in docu
# Evidence: Verify that the only evidence is `passport mentioned in documentation` and that no populat
# ==============================================================================
def test_case_gov_083():
    """Test scenario for GOV-083: passport mentioned in documentation"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_passport_mentioned_in_documentation = "MOCK_NON_PII_LITERAL_PASSPORT_MENTIONED_IN_DOCUMENTATION"
    unrelated_system_config = {
        "config_key": "passport mentioned in documentation",
        "is_pii": False,
        "value": dummy_passport_mentioned_in_documentation
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: GOV-084] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `'pan' inside an unrelated 
# Evidence: Verify that the only evidence is `'pan' inside an unrelated identifier` and that no popula
# ==============================================================================
def test_case_gov_084():
    """Test scenario for GOV-084: 'pan' inside an unrelated identifier"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy__pan__inside_an_unrelated_identifier = "MOCK_NON_PII_LITERAL__PAN__INSIDE_AN_UNRELATED_IDENTIFIER"
    unrelated_system_config = {
        "config_key": "'pan' inside an unrelated identifier",
        "is_pii": False,
        "value": dummy__pan__inside_an_unrelated_identifier
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: GOV-085] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `invalid or malformed ID st
# Evidence: Verify that the only evidence is `invalid or malformed ID string` and that no populated, u
# ==============================================================================
def test_case_gov_085():
    """Test scenario for GOV-085: invalid or malformed ID string"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_invalid_or_malformed_ID_string = "MOCK_NON_PII_LITERAL_INVALID_OR_MALFORMED_ID_STRING"
    unrelated_system_config = {
        "config_key": "invalid or malformed ID string",
        "is_pii": False,
        "value": dummy_invalid_or_malformed_ID_string
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: GOV-086] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `synthetic test identifier`
# Evidence: Verify that the only evidence is `synthetic test identifier` and that no populated, user-l
# ==============================================================================
def test_case_gov_086():
    """Test scenario for GOV-086: synthetic test identifier"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_synthetic_test_identifier = "MOCK_NON_PII_LITERAL_SYNTHETIC_TEST_IDENTIFIER"
    unrelated_system_config = {
        "config_key": "synthetic test identifier",
        "is_pii": False,
        "value": dummy_synthetic_test_identifier
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: GOV-087] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `government-ID field never 
# Evidence: Verify that the only evidence is `government-ID field never populated` and that no populat
# ==============================================================================
def test_case_gov_087():
    """Test scenario for GOV-087: government-ID field never populated"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_government_ID_field_never_populated = "MOCK_NON_PII_LITERAL_GOVERNMENT_ID_FIELD_NEVER_POPULATED"
    unrelated_system_config = {
        "config_key": "government-ID field never populated",
        "is_pii": False,
        "value": dummy_government_ID_field_never_populated
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: GOV-088] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `branch code mistaken for a
# Evidence: Verify that the only evidence is `branch code mistaken for a personal ID` and that no popu
# ==============================================================================
def test_case_gov_088():
    """Test scenario for GOV-088: branch code mistaken for a personal ID"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_branch_code_mistaken_for_a_personal_ID = "MOCK_NON_PII_LITERAL_BRANCH_CODE_MISTAKEN_FOR_A_PERSONAL_ID"
    unrelated_system_config = {
        "config_key": "branch code mistaken for a personal ID",
        "is_pii": False,
        "value": dummy_branch_code_mistaken_for_a_personal_ID
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: GOV-089] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `unrelated token containing
# Evidence: Verify that the only evidence is `unrelated token containing ID letters` and that no popul
# ==============================================================================
def test_case_gov_089():
    """Test scenario for GOV-089: unrelated token containing ID letters"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_unrelated_token_containing_ID_letters = "MOCK_NON_PII_LITERAL_UNRELATED_TOKEN_CONTAINING_ID_LETTERS"
    unrelated_system_config = {
        "config_key": "unrelated token containing ID letters",
        "is_pii": False,
        "value": dummy_unrelated_token_containing_ID_letters
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: GOV-090] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `regex definition with no a
# Evidence: Verify that the only evidence is `regex definition with no actual ID value` and that no po
# ==============================================================================
def test_case_gov_090():
    """Test scenario for GOV-090: regex definition with no actual ID value"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_regex_definition_with_no_actual_ID_value = "MOCK_NON_PII_LITERAL_REGEX_DEFINITION_WITH_NO_ACTUAL_ID_VALUE"
    unrelated_system_config = {
        "config_key": "regex definition with no actual ID value",
        "is_pii": False,
        "value": dummy_regex_definition_with_no_actual_ID_value
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: GOV-091] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `pan_number`: f
# Evidence: Record the exact `pan_number` source location, available type/context, missing runtime or 
# ==============================================================================
def test_case_gov_091():
    """Test scenario for GOV-091: pan_number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    pan_number = "active_sample_value_for_pan_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "pan_number": pan_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-092] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `aadhaar_number
# Evidence: Record the exact `aadhaar_number` source location, available type/context, missing runtime
# ==============================================================================
def test_case_gov_092():
    """Test scenario for GOV-092: aadhaar_number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    aadhaar_number = "active_sample_value_for_aadhaar_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "aadhaar_number": aadhaar_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-093] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `passport_no`: 
# Evidence: Record the exact `passport_no` source location, available type/context, missing runtime or
# ==============================================================================
def test_case_gov_093():
    """Test scenario for GOV-093: passport_no"""
    # ACTIVE TEST CASE: Represents identifiable user data
    passport_no = "active_sample_value_for_passport_no"
    payload = {
        "user_id": "USR_99214_TEST",
        "passport_no": passport_no,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-094] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `driving_licens
# Evidence: Record the exact `driving_license` source location, available type/context, missing runtim
# ==============================================================================
def test_case_gov_094():
    """Test scenario for GOV-094: driving_license"""
    # ACTIVE TEST CASE: Represents identifiable user data
    driving_license = "active_sample_value_for_driving_license"
    payload = {
        "user_id": "USR_99214_TEST",
        "driving_license": driving_license,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-095] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `voter_id`: ide
# Evidence: Record the exact `voter_id` source location, available type/context, missing runtime or li
# ==============================================================================
def test_case_gov_095():
    """Test scenario for GOV-095: voter_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    voter_id = "active_sample_value_for_voter_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "voter_id": voter_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-096] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `government_id`
# Evidence: Record the exact `government_id` source location, available type/context, missing runtime 
# ==============================================================================
def test_case_gov_096():
    """Test scenario for GOV-096: government_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    government_id = "active_sample_value_for_government_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "government_id": government_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-097] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `tax_id`: ident
# Evidence: Record the exact `tax_id` source location, available type/context, missing runtime or link
# ==============================================================================
def test_case_gov_097():
    """Test scenario for GOV-097: tax_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    tax_id = "active_sample_value_for_tax_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "tax_id": tax_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-098] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `identity_docum
# Evidence: Record the exact `identity_document.number` source location, available type/context, missi
# ==============================================================================
def test_case_gov_098():
    """Test scenario for GOV-098: identity_document.number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    identity_document_number = "active_sample_value_for_identity_document_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "identity_document_number": identity_document_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-099] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `kyc.document_i
# Evidence: Record the exact `kyc.document_id` source location, available type/context, missing runtim
# ==============================================================================
def test_case_gov_099():
    """Test scenario for GOV-099: kyc.document_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    kyc_document_id = "active_sample_value_for_kyc_document_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "kyc_document_id": kyc_document_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: GOV-100] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `national_ident
# Evidence: Record the exact `national_identifier` source location, available type/context, missing ru
# ==============================================================================
def test_case_gov_100():
    """Test scenario for GOV-100: national_identifier"""
    # ACTIVE TEST CASE: Represents identifiable user data
    national_identifier = "active_sample_value_for_national_identifier"
    payload = {
        "user_id": "USR_99214_TEST",
        "national_identifier": national_identifier,
        "is_active_pii": True
    }
    return payload
