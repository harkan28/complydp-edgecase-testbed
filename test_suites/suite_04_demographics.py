"""
COMPLYDP EDGE-CASE TEST SUITE: DEMOGRAPHIC INFORMATION (DEM)
Contains all 100 test scenarios (DEM-001 to DEM-100).
Includes Positive PII cases, API flows, Masked cases, and Negative Control Traps.
"""

import re
import json
import hashlib
from typing import Dict, Any, List, Optional

# ==============================================================================
# [TEST_ID: DEM-001] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `date_of_birth` in the repository schema or source code, incl
# Evidence: Verify the exact `date_of_birth` declaration, its type/validation/usage, and whether it is
# ==============================================================================
def test_case_dem_001():
    """Test scenario for DEM-001: date_of_birth"""
    # ACTIVE TEST CASE: Represents identifiable user data
    date_of_birth = "active_sample_value_for_date_of_birth"
    payload = {
        "user_id": "USR_99214_TEST",
        "date_of_birth": date_of_birth,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-002] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `dob` in the repository schema or source code, including date
# Evidence: Verify the exact `dob` declaration, its type/validation/usage, and whether it is linked to
# ==============================================================================
def test_case_dem_002():
    """Test scenario for DEM-002: dob"""
    # ACTIVE TEST CASE: Represents identifiable user data
    dob = "active_sample_value_for_dob"
    payload = {
        "user_id": "USR_99214_TEST",
        "dob": dob,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-003] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `birthDate` in the repository schema or source code, includin
# Evidence: Verify the exact `birthDate` declaration, its type/validation/usage, and whether it is lin
# ==============================================================================
def test_case_dem_003():
    """Test scenario for DEM-003: birthDate"""
    # ACTIVE TEST CASE: Represents identifiable user data
    birthDate = "active_sample_value_for_birthDate"
    payload = {
        "user_id": "USR_99214_TEST",
        "birthDate": birthDate,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-004] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `age` in the repository schema or source code, including birt
# Evidence: Verify the exact `age` declaration, its type/validation/usage, and whether it is linked to
# ==============================================================================
def test_case_dem_004():
    """Test scenario for DEM-004: age"""
    # ACTIVE TEST CASE: Represents identifiable user data
    age = "active_sample_value_for_age"
    payload = {
        "user_id": "USR_99214_TEST",
        "age": age,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-005] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `gender` in the repository schema or source code, including d
# Evidence: Verify the exact `gender` declaration, its type/validation/usage, and whether it is linked
# ==============================================================================
def test_case_dem_005():
    """Test scenario for DEM-005: gender"""
    # ACTIVE TEST CASE: Represents identifiable user data
    gender = "active_sample_value_for_gender"
    payload = {
        "user_id": "USR_99214_TEST",
        "gender": gender,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-006] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `birth_year` in the repository schema or source code, includi
# Evidence: Verify the exact `birth_year` declaration, its type/validation/usage, and whether it is li
# ==============================================================================
def test_case_dem_006():
    """Test scenario for DEM-006: birth_year"""
    # ACTIVE TEST CASE: Represents identifiable user data
    birth_year = "active_sample_value_for_birth_year"
    payload = {
        "user_id": "USR_99214_TEST",
        "birth_year": birth_year,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-007] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `demographic_profile` in the repository schema or source code
# Evidence: Verify the exact `demographic_profile` declaration, its type/validation/usage, and whether
# ==============================================================================
def test_case_dem_007():
    """Test scenario for DEM-007: demographic_profile"""
    # ACTIVE TEST CASE: Represents identifiable user data
    demographic_profile = "active_sample_value_for_demographic_profile"
    payload = {
        "user_id": "USR_99214_TEST",
        "demographic_profile": demographic_profile,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-008] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `user_age` in the repository schema or source code, including
# Evidence: Verify the exact `user_age` declaration, its type/validation/usage, and whether it is link
# ==============================================================================
def test_case_dem_008():
    """Test scenario for DEM-008: user_age"""
    # ACTIVE TEST CASE: Represents identifiable user data
    user_age = "active_sample_value_for_user_age"
    payload = {
        "user_id": "USR_99214_TEST",
        "user_age": user_age,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-009] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `profile.demographics` in the repository schema or source cod
# Evidence: Verify the exact `profile.demographics` declaration, its type/validation/usage, and whethe
# ==============================================================================
def test_case_dem_009():
    """Test scenario for DEM-009: profile.demographics"""
    # ACTIVE TEST CASE: Represents identifiable user data
    profile_demographics = "active_sample_value_for_profile_demographics"
    payload = {
        "user_id": "USR_99214_TEST",
        "profile_demographics": profile_demographics,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-010] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `dateOfBirth` in the repository schema or source code, includ
# Evidence: Verify the exact `dateOfBirth` declaration, its type/validation/usage, and whether it is l
# ==============================================================================
def test_case_dem_010():
    """Test scenario for DEM-010: dateOfBirth"""
    # ACTIVE TEST CASE: Represents identifiable user data
    dateOfBirth = "active_sample_value_for_dateOfBirth"
    payload = {
        "user_id": "USR_99214_TEST",
        "dateOfBirth": dateOfBirth,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-011] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `date_of_birth` when date stored as epoch timestamp; inspe
# Evidence: Capture the full JSON/object path for `date_of_birth`, the parent record or user key, and 
# ==============================================================================
def test_case_dem_011():
    """Test scenario for DEM-011: date_of_birth"""
    # ACTIVE TEST CASE: Represents identifiable user data
    date_of_birth = "active_sample_value_for_date_of_birth"
    payload = {
        "user_id": "USR_99214_TEST",
        "date_of_birth": date_of_birth,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-012] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `dob` when date stored in a locale-specific format; inspec
# Evidence: Capture the full JSON/object path for `dob`, the parent record or user key, and the code t
# ==============================================================================
def test_case_dem_012():
    """Test scenario for DEM-012: dob"""
    # ACTIVE TEST CASE: Represents identifiable user data
    dob = "active_sample_value_for_dob"
    payload = {
        "user_id": "USR_99214_TEST",
        "dob": dob,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-013] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `birthDate` when age range rather than exact age; inspect 
# Evidence: Capture the full JSON/object path for `birthDate`, the parent record or user key, and the 
# ==============================================================================
def test_case_dem_013():
    """Test scenario for DEM-013: birthDate"""
    # ACTIVE TEST CASE: Represents identifiable user data
    birthDate = "active_sample_value_for_birthDate"
    payload = {
        "user_id": "USR_99214_TEST",
        "birthDate": birthDate,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-014] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `age` when birth year only; inspect nested object paths, a
# Evidence: Capture the full JSON/object path for `age`, the parent record or user key, and the code t
# ==============================================================================
def test_case_dem_014():
    """Test scenario for DEM-014: age"""
    # ACTIVE TEST CASE: Represents identifiable user data
    age = "active_sample_value_for_age"
    payload = {
        "user_id": "USR_99214_TEST",
        "age": age,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-015] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `gender` when date of birth nested in profile JSON; inspec
# Evidence: Capture the full JSON/object path for `gender`, the parent record or user key, and the cod
# ==============================================================================
def test_case_dem_015():
    """Test scenario for DEM-015: gender"""
    # ACTIVE TEST CASE: Represents identifiable user data
    gender = "active_sample_value_for_gender"
    payload = {
        "user_id": "USR_99214_TEST",
        "gender": gender,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-016] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `birth_year` when age calculated from date of birth; inspe
# Evidence: Capture the full JSON/object path for `birth_year`, the parent record or user key, and the
# ==============================================================================
def test_case_dem_016():
    """Test scenario for DEM-016: birth_year"""
    # ACTIVE TEST CASE: Represents identifiable user data
    birth_year = "active_sample_value_for_birth_year"
    payload = {
        "user_id": "USR_99214_TEST",
        "birth_year": birth_year,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-017] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `demographic_profile` when demographic field joined to use
# Evidence: Capture the full JSON/object path for `demographic_profile`, the parent record or user key
# ==============================================================================
def test_case_dem_017():
    """Test scenario for DEM-017: demographic_profile"""
    # ACTIVE TEST CASE: Represents identifiable user data
    demographic_profile = "active_sample_value_for_demographic_profile"
    payload = {
        "user_id": "USR_99214_TEST",
        "demographic_profile": demographic_profile,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-018] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `user_age` when demographic value returned by API; inspect
# Evidence: Capture the full JSON/object path for `user_age`, the parent record or user key, and the c
# ==============================================================================
def test_case_dem_018():
    """Test scenario for DEM-018: user_age"""
    # ACTIVE TEST CASE: Represents identifiable user data
    user_age = "active_sample_value_for_user_age"
    payload = {
        "user_id": "USR_99214_TEST",
        "user_age": user_age,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-019] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `profile.demographics` when gender represented as enum; in
# Evidence: Capture the full JSON/object path for `profile.demographics`, the parent record or user ke
# ==============================================================================
def test_case_dem_019():
    """Test scenario for DEM-019: profile.demographics"""
    # ACTIVE TEST CASE: Represents identifiable user data
    profile_demographics = "active_sample_value_for_profile_demographics"
    payload = {
        "user_id": "USR_99214_TEST",
        "profile_demographics": profile_demographics,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-020] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `dateOfBirth` when demographic attribute inferred from ano
# Evidence: Capture the full JSON/object path for `dateOfBirth`, the parent record or user key, and th
# ==============================================================================
def test_case_dem_020():
    """Test scenario for DEM-020: dateOfBirth"""
    # ACTIVE TEST CASE: Represents identifiable user data
    dateOfBirth = "active_sample_value_for_dateOfBirth"
    payload = {
        "user_id": "USR_99214_TEST",
        "dateOfBirth": dateOfBirth,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-021] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `date_of_birth` through an API boundary when date stored as ep
# Evidence: Verify the request/response schema and call site for `date_of_birth`, direction of flow, e
# ==============================================================================
def test_case_dem_021():
    """Test scenario for DEM-021: date_of_birth"""
    # ACTIVE TEST CASE: Represents identifiable user data
    date_of_birth = "active_sample_value_for_date_of_birth"
    payload = {
        "user_id": "USR_99214_TEST",
        "date_of_birth": date_of_birth,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-022] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `dob` through an API boundary when date stored in a locale-spe
# Evidence: Verify the request/response schema and call site for `dob`, direction of flow, endpoint/ve
# ==============================================================================
def test_case_dem_022():
    """Test scenario for DEM-022: dob"""
    # ACTIVE TEST CASE: Represents identifiable user data
    dob = "active_sample_value_for_dob"
    payload = {
        "user_id": "USR_99214_TEST",
        "dob": dob,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-023] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `birthDate` through an API boundary when age range rather than
# Evidence: Verify the request/response schema and call site for `birthDate`, direction of flow, endpo
# ==============================================================================
def test_case_dem_023():
    """Test scenario for DEM-023: birthDate"""
    # ACTIVE TEST CASE: Represents identifiable user data
    birthDate = "active_sample_value_for_birthDate"
    payload = {
        "user_id": "USR_99214_TEST",
        "birthDate": birthDate,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-024] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `age` through an API boundary when birth year only; identify w
# Evidence: Verify the request/response schema and call site for `age`, direction of flow, endpoint/ve
# ==============================================================================
def test_case_dem_024():
    """Test scenario for DEM-024: age"""
    # ACTIVE TEST CASE: Represents identifiable user data
    age = "active_sample_value_for_age"
    payload = {
        "user_id": "USR_99214_TEST",
        "age": age,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-025] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `gender` through an API boundary when date of birth nested in 
# Evidence: Verify the request/response schema and call site for `gender`, direction of flow, endpoint
# ==============================================================================
def test_case_dem_025():
    """Test scenario for DEM-025: gender"""
    # ACTIVE TEST CASE: Represents identifiable user data
    gender = "active_sample_value_for_gender"
    payload = {
        "user_id": "USR_99214_TEST",
        "gender": gender,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-026] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `birth_year` through an API boundary when age calculated from 
# Evidence: Verify the request/response schema and call site for `birth_year`, direction of flow, endp
# ==============================================================================
def test_case_dem_026():
    """Test scenario for DEM-026: birth_year"""
    # ACTIVE TEST CASE: Represents identifiable user data
    birth_year = "active_sample_value_for_birth_year"
    payload = {
        "user_id": "USR_99214_TEST",
        "birth_year": birth_year,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-027] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `demographic_profile` through an API boundary when demographic
# Evidence: Verify the request/response schema and call site for `demographic_profile`, direction of f
# ==============================================================================
def test_case_dem_027():
    """Test scenario for DEM-027: demographic_profile"""
    # ACTIVE TEST CASE: Represents identifiable user data
    demographic_profile = "active_sample_value_for_demographic_profile"
    payload = {
        "user_id": "USR_99214_TEST",
        "demographic_profile": demographic_profile,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-028] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `user_age` through an API boundary when demographic value retu
# Evidence: Verify the request/response schema and call site for `user_age`, direction of flow, endpoi
# ==============================================================================
def test_case_dem_028():
    """Test scenario for DEM-028: user_age"""
    # ACTIVE TEST CASE: Represents identifiable user data
    user_age = "active_sample_value_for_user_age"
    payload = {
        "user_id": "USR_99214_TEST",
        "user_age": user_age,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-029] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `profile.demographics` through an API boundary when gender rep
# Evidence: Verify the request/response schema and call site for `profile.demographics`, direction of 
# ==============================================================================
def test_case_dem_029():
    """Test scenario for DEM-029: profile.demographics"""
    # ACTIVE TEST CASE: Represents identifiable user data
    profile_demographics = "active_sample_value_for_profile_demographics"
    payload = {
        "user_id": "USR_99214_TEST",
        "profile_demographics": profile_demographics,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-030] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `dateOfBirth` through an API boundary when demographic attribu
# Evidence: Verify the request/response schema and call site for `dateOfBirth`, direction of flow, end
# ==============================================================================
def test_case_dem_030():
    """Test scenario for DEM-030: dateOfBirth"""
    # ACTIVE TEST CASE: Represents identifiable user data
    dateOfBirth = "active_sample_value_for_dateOfBirth"
    payload = {
        "user_id": "USR_99214_TEST",
        "dateOfBirth": dateOfBirth,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-031] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `date_of_birth` when date stored as epoch timestamp
# Evidence: Show the source value, transformation or derivation applied to `date_of_birth`, and result
# ==============================================================================
def test_case_dem_031():
    """Test scenario for DEM-031: date_of_birth"""
    # ACTIVE TEST CASE: Represents identifiable user data
    date_of_birth = "active_sample_value_for_date_of_birth"
    payload = {
        "user_id": "USR_99214_TEST",
        "date_of_birth": date_of_birth,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-032] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `dob` when date stored in a locale-specific format;
# Evidence: Show the source value, transformation or derivation applied to `dob`, and resulting sink o
# ==============================================================================
def test_case_dem_032():
    """Test scenario for DEM-032: dob"""
    # ACTIVE TEST CASE: Represents identifiable user data
    dob = "active_sample_value_for_dob"
    payload = {
        "user_id": "USR_99214_TEST",
        "dob": dob,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-033] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `birthDate` when age range rather than exact age; f
# Evidence: Show the source value, transformation or derivation applied to `birthDate`, and resulting 
# ==============================================================================
def test_case_dem_033():
    """Test scenario for DEM-033: birthDate"""
    # ACTIVE TEST CASE: Represents identifiable user data
    birthDate = "active_sample_value_for_birthDate"
    payload = {
        "user_id": "USR_99214_TEST",
        "birthDate": birthDate,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-034] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `age` when birth year only; follow assignments, par
# Evidence: Show the source value, transformation or derivation applied to `age`, and resulting sink o
# ==============================================================================
def test_case_dem_034():
    """Test scenario for DEM-034: age"""
    # ACTIVE TEST CASE: Represents identifiable user data
    age = "active_sample_value_for_age"
    payload = {
        "user_id": "USR_99214_TEST",
        "age": age,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-035] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `gender` when date of birth nested in profile JSON;
# Evidence: Show the source value, transformation or derivation applied to `gender`, and resulting sin
# ==============================================================================
def test_case_dem_035():
    """Test scenario for DEM-035: gender"""
    # ACTIVE TEST CASE: Represents identifiable user data
    gender = "active_sample_value_for_gender"
    payload = {
        "user_id": "USR_99214_TEST",
        "gender": gender,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-036] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `birth_year` when age calculated from date of birth
# Evidence: Show the source value, transformation or derivation applied to `birth_year`, and resulting
# ==============================================================================
def test_case_dem_036():
    """Test scenario for DEM-036: birth_year"""
    # ACTIVE TEST CASE: Represents identifiable user data
    birth_year = "active_sample_value_for_birth_year"
    payload = {
        "user_id": "USR_99214_TEST",
        "birth_year": birth_year,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-037] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `demographic_profile` when demographic field joined
# Evidence: Show the source value, transformation or derivation applied to `demographic_profile`, and 
# ==============================================================================
def test_case_dem_037():
    """Test scenario for DEM-037: demographic_profile"""
    # ACTIVE TEST CASE: Represents identifiable user data
    demographic_profile = "active_sample_value_for_demographic_profile"
    payload = {
        "user_id": "USR_99214_TEST",
        "demographic_profile": demographic_profile,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-038] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `user_age` when demographic value returned by API; 
# Evidence: Show the source value, transformation or derivation applied to `user_age`, and resulting s
# ==============================================================================
def test_case_dem_038():
    """Test scenario for DEM-038: user_age"""
    # ACTIVE TEST CASE: Represents identifiable user data
    user_age = "active_sample_value_for_user_age"
    payload = {
        "user_id": "USR_99214_TEST",
        "user_age": user_age,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-039] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `profile.demographics` when gender represented as e
# Evidence: Show the source value, transformation or derivation applied to `profile.demographics`, and
# ==============================================================================
def test_case_dem_039():
    """Test scenario for DEM-039: profile.demographics"""
    # ACTIVE TEST CASE: Represents identifiable user data
    profile_demographics = "active_sample_value_for_profile_demographics"
    payload = {
        "user_id": "USR_99214_TEST",
        "profile_demographics": profile_demographics,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-040] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `dateOfBirth` when demographic attribute inferred f
# Evidence: Show the source value, transformation or derivation applied to `dateOfBirth`, and resultin
# ==============================================================================
def test_case_dem_040():
    """Test scenario for DEM-040: dateOfBirth"""
    # ACTIVE TEST CASE: Represents identifiable user data
    dateOfBirth = "active_sample_value_for_dateOfBirth"
    payload = {
        "user_id": "USR_99214_TEST",
        "dateOfBirth": dateOfBirth,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-041] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `date_of_birth` when date stored as
# Evidence: Identify the exact `date_of_birth` write/read operation and target (table, document, cache
# ==============================================================================
def test_case_dem_041():
    """Test scenario for DEM-041: date_of_birth"""
    # ACTIVE TEST CASE: Represents identifiable user data
    date_of_birth = "active_sample_value_for_date_of_birth"
    payload = {
        "user_id": "USR_99214_TEST",
        "date_of_birth": date_of_birth,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-042] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `dob` when date stored in a locale-
# Evidence: Identify the exact `dob` write/read operation and target (table, document, cache, file, br
# ==============================================================================
def test_case_dem_042():
    """Test scenario for DEM-042: dob"""
    # ACTIVE TEST CASE: Represents identifiable user data
    dob = "active_sample_value_for_dob"
    payload = {
        "user_id": "USR_99214_TEST",
        "dob": dob,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-043] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `birthDate` when age range rather t
# Evidence: Identify the exact `birthDate` write/read operation and target (table, document, cache, fi
# ==============================================================================
def test_case_dem_043():
    """Test scenario for DEM-043: birthDate"""
    # ACTIVE TEST CASE: Represents identifiable user data
    birthDate = "active_sample_value_for_birthDate"
    payload = {
        "user_id": "USR_99214_TEST",
        "birthDate": birthDate,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-044] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `age` when birth year only; disting
# Evidence: Identify the exact `age` write/read operation and target (table, document, cache, file, br
# ==============================================================================
def test_case_dem_044():
    """Test scenario for DEM-044: age"""
    # ACTIVE TEST CASE: Represents identifiable user data
    age = "active_sample_value_for_age"
    payload = {
        "user_id": "USR_99214_TEST",
        "age": age,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-045] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `gender` when date of birth nested 
# Evidence: Identify the exact `gender` write/read operation and target (table, document, cache, file,
# ==============================================================================
def test_case_dem_045():
    """Test scenario for DEM-045: gender"""
    # ACTIVE TEST CASE: Represents identifiable user data
    gender = "active_sample_value_for_gender"
    payload = {
        "user_id": "USR_99214_TEST",
        "gender": gender,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-046] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `birth_year` when age calculated fr
# Evidence: Identify the exact `birth_year` write/read operation and target (table, document, cache, f
# ==============================================================================
def test_case_dem_046():
    """Test scenario for DEM-046: birth_year"""
    # ACTIVE TEST CASE: Represents identifiable user data
    birth_year = "active_sample_value_for_birth_year"
    payload = {
        "user_id": "USR_99214_TEST",
        "birth_year": birth_year,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-047] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `demographic_profile` when demograp
# Evidence: Identify the exact `demographic_profile` write/read operation and target (table, document,
# ==============================================================================
def test_case_dem_047():
    """Test scenario for DEM-047: demographic_profile"""
    # ACTIVE TEST CASE: Represents identifiable user data
    demographic_profile = "active_sample_value_for_demographic_profile"
    payload = {
        "user_id": "USR_99214_TEST",
        "demographic_profile": demographic_profile,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-048] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `user_age` when demographic value r
# Evidence: Identify the exact `user_age` write/read operation and target (table, document, cache, fil
# ==============================================================================
def test_case_dem_048():
    """Test scenario for DEM-048: user_age"""
    # ACTIVE TEST CASE: Represents identifiable user data
    user_age = "active_sample_value_for_user_age"
    payload = {
        "user_id": "USR_99214_TEST",
        "user_age": user_age,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-049] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `profile.demographics` when gender 
# Evidence: Identify the exact `profile.demographics` write/read operation and target (table, document
# ==============================================================================
def test_case_dem_049():
    """Test scenario for DEM-049: profile.demographics"""
    # ACTIVE TEST CASE: Represents identifiable user data
    profile_demographics = "active_sample_value_for_profile_demographics"
    payload = {
        "user_id": "USR_99214_TEST",
        "profile_demographics": profile_demographics,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-050] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `dateOfBirth` when demographic attr
# Evidence: Identify the exact `dateOfBirth` write/read operation and target (table, document, cache, 
# ==============================================================================
def test_case_dem_050():
    """Test scenario for DEM-050: dateOfBirth"""
    # ACTIVE TEST CASE: Represents identifiable user data
    dateOfBirth = "active_sample_value_for_dateOfBirth"
    payload = {
        "user_id": "USR_99214_TEST",
        "dateOfBirth": dateOfBirth,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-051] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `date_of_birth` becomes identifiable or linkable when date s
# Evidence: Record `date_of_birth`'s join key/foreign key, related table or service, and the code path
# ==============================================================================
def test_case_dem_051():
    """Test scenario for DEM-051: date_of_birth"""
    # ACTIVE TEST CASE: Represents identifiable user data
    date_of_birth = "active_sample_value_for_date_of_birth"
    payload = {
        "user_id": "USR_99214_TEST",
        "date_of_birth": date_of_birth,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-052] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `dob` becomes identifiable or linkable when date stored in a
# Evidence: Record `dob`'s join key/foreign key, related table or service, and the code path that link
# ==============================================================================
def test_case_dem_052():
    """Test scenario for DEM-052: dob"""
    # ACTIVE TEST CASE: Represents identifiable user data
    dob = "active_sample_value_for_dob"
    payload = {
        "user_id": "USR_99214_TEST",
        "dob": dob,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-053] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `birthDate` becomes identifiable or linkable when age range 
# Evidence: Record `birthDate`'s join key/foreign key, related table or service, and the code path tha
# ==============================================================================
def test_case_dem_053():
    """Test scenario for DEM-053: birthDate"""
    # ACTIVE TEST CASE: Represents identifiable user data
    birthDate = "active_sample_value_for_birthDate"
    payload = {
        "user_id": "USR_99214_TEST",
        "birthDate": birthDate,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-054] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `age` becomes identifiable or linkable when birth year only;
# Evidence: Record `age`'s join key/foreign key, related table or service, and the code path that link
# ==============================================================================
def test_case_dem_054():
    """Test scenario for DEM-054: age"""
    # ACTIVE TEST CASE: Represents identifiable user data
    age = "active_sample_value_for_age"
    payload = {
        "user_id": "USR_99214_TEST",
        "age": age,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-055] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `gender` becomes identifiable or linkable when date of birth
# Evidence: Record `gender`'s join key/foreign key, related table or service, and the code path that l
# ==============================================================================
def test_case_dem_055():
    """Test scenario for DEM-055: gender"""
    # ACTIVE TEST CASE: Represents identifiable user data
    gender = "active_sample_value_for_gender"
    payload = {
        "user_id": "USR_99214_TEST",
        "gender": gender,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-056] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `birth_year` becomes identifiable or linkable when age calcu
# Evidence: Record `birth_year`'s join key/foreign key, related table or service, and the code path th
# ==============================================================================
def test_case_dem_056():
    """Test scenario for DEM-056: birth_year"""
    # ACTIVE TEST CASE: Represents identifiable user data
    birth_year = "active_sample_value_for_birth_year"
    payload = {
        "user_id": "USR_99214_TEST",
        "birth_year": birth_year,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-057] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `demographic_profile` becomes identifiable or linkable when 
# Evidence: Record `demographic_profile`'s join key/foreign key, related table or service, and the cod
# ==============================================================================
def test_case_dem_057():
    """Test scenario for DEM-057: demographic_profile"""
    # ACTIVE TEST CASE: Represents identifiable user data
    demographic_profile = "active_sample_value_for_demographic_profile"
    payload = {
        "user_id": "USR_99214_TEST",
        "demographic_profile": demographic_profile,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-058] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `user_age` becomes identifiable or linkable when demographic
# Evidence: Record `user_age`'s join key/foreign key, related table or service, and the code path that
# ==============================================================================
def test_case_dem_058():
    """Test scenario for DEM-058: user_age"""
    # ACTIVE TEST CASE: Represents identifiable user data
    user_age = "active_sample_value_for_user_age"
    payload = {
        "user_id": "USR_99214_TEST",
        "user_age": user_age,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-059] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `profile.demographics` becomes identifiable or linkable when
# Evidence: Record `profile.demographics`'s join key/foreign key, related table or service, and the co
# ==============================================================================
def test_case_dem_059():
    """Test scenario for DEM-059: profile.demographics"""
    # ACTIVE TEST CASE: Represents identifiable user data
    profile_demographics = "active_sample_value_for_profile_demographics"
    payload = {
        "user_id": "USR_99214_TEST",
        "profile_demographics": profile_demographics,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-060] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `dateOfBirth` becomes identifiable or linkable when demograp
# Evidence: Record `dateOfBirth`'s join key/foreign key, related table or service, and the code path t
# ==============================================================================
def test_case_dem_060():
    """Test scenario for DEM-060: dateOfBirth"""
    # ACTIVE TEST CASE: Represents identifiable user data
    dateOfBirth = "active_sample_value_for_dateOfBirth"
    payload = {
        "user_id": "USR_99214_TEST",
        "dateOfBirth": dateOfBirth,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-061] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `date_of_birth` to a third-party boundary when date stored as ep
# Evidence: Verify the payload field `date_of_birth`, outbound call site, destination/vendor, and whet
# ==============================================================================
def test_case_dem_061():
    """Test scenario for DEM-061: date_of_birth"""
    # ACTIVE TEST CASE: Represents identifiable user data
    date_of_birth = "active_sample_value_for_date_of_birth"
    payload = {
        "user_id": "USR_99214_TEST",
        "date_of_birth": date_of_birth,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-062] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `dob` to a third-party boundary when date stored in a locale-spe
# Evidence: Verify the payload field `dob`, outbound call site, destination/vendor, and whether the va
# ==============================================================================
def test_case_dem_062():
    """Test scenario for DEM-062: dob"""
    # ACTIVE TEST CASE: Represents identifiable user data
    dob = "active_sample_value_for_dob"
    payload = {
        "user_id": "USR_99214_TEST",
        "dob": dob,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-063] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `birthDate` to a third-party boundary when age range rather than
# Evidence: Verify the payload field `birthDate`, outbound call site, destination/vendor, and whether 
# ==============================================================================
def test_case_dem_063():
    """Test scenario for DEM-063: birthDate"""
    # ACTIVE TEST CASE: Represents identifiable user data
    birthDate = "active_sample_value_for_birthDate"
    payload = {
        "user_id": "USR_99214_TEST",
        "birthDate": birthDate,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-064] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `age` to a third-party boundary when birth year only; inspect SD
# Evidence: Verify the payload field `age`, outbound call site, destination/vendor, and whether the va
# ==============================================================================
def test_case_dem_064():
    """Test scenario for DEM-064: age"""
    # ACTIVE TEST CASE: Represents identifiable user data
    age = "active_sample_value_for_age"
    payload = {
        "user_id": "USR_99214_TEST",
        "age": age,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-065] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `gender` to a third-party boundary when date of birth nested in 
# Evidence: Verify the payload field `gender`, outbound call site, destination/vendor, and whether the
# ==============================================================================
def test_case_dem_065():
    """Test scenario for DEM-065: gender"""
    # ACTIVE TEST CASE: Represents identifiable user data
    gender = "active_sample_value_for_gender"
    payload = {
        "user_id": "USR_99214_TEST",
        "gender": gender,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-066] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `birth_year` to a third-party boundary when age calculated from 
# Evidence: Verify the payload field `birth_year`, outbound call site, destination/vendor, and whether
# ==============================================================================
def test_case_dem_066():
    """Test scenario for DEM-066: birth_year"""
    # ACTIVE TEST CASE: Represents identifiable user data
    birth_year = "active_sample_value_for_birth_year"
    payload = {
        "user_id": "USR_99214_TEST",
        "birth_year": birth_year,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-067] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `demographic_profile` to a third-party boundary when demographic
# Evidence: Verify the payload field `demographic_profile`, outbound call site, destination/vendor, an
# ==============================================================================
def test_case_dem_067():
    """Test scenario for DEM-067: demographic_profile"""
    # ACTIVE TEST CASE: Represents identifiable user data
    demographic_profile = "active_sample_value_for_demographic_profile"
    payload = {
        "user_id": "USR_99214_TEST",
        "demographic_profile": demographic_profile,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-068] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `user_age` to a third-party boundary when demographic value retu
# Evidence: Verify the payload field `user_age`, outbound call site, destination/vendor, and whether t
# ==============================================================================
def test_case_dem_068():
    """Test scenario for DEM-068: user_age"""
    # ACTIVE TEST CASE: Represents identifiable user data
    user_age = "active_sample_value_for_user_age"
    payload = {
        "user_id": "USR_99214_TEST",
        "user_age": user_age,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-069] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `profile.demographics` to a third-party boundary when gender rep
# Evidence: Verify the payload field `profile.demographics`, outbound call site, destination/vendor, a
# ==============================================================================
def test_case_dem_069():
    """Test scenario for DEM-069: profile.demographics"""
    # ACTIVE TEST CASE: Represents identifiable user data
    profile_demographics = "active_sample_value_for_profile_demographics"
    payload = {
        "user_id": "USR_99214_TEST",
        "profile_demographics": profile_demographics,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-070] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `dateOfBirth` to a third-party boundary when demographic attribu
# Evidence: Verify the payload field `dateOfBirth`, outbound call site, destination/vendor, and whethe
# ==============================================================================
def test_case_dem_070():
    """Test scenario for DEM-070: dateOfBirth"""
    # ACTIVE TEST CASE: Represents identifiable user data
    dateOfBirth = "active_sample_value_for_dateOfBirth"
    payload = {
        "user_id": "USR_99214_TEST",
        "dateOfBirth": dateOfBirth,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-071] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `date_of_birth` when date stored as epoch t
# Evidence: Record the observed representation and protection/transform function for `date_of_birth`; 
# ==============================================================================
def test_case_dem_071():
    """Test scenario for DEM-071: date_of_birth"""
    # ACTIVE TEST CASE: Represents identifiable user data
    date_of_birth = "active_sample_value_for_date_of_birth"
    payload = {
        "user_id": "USR_99214_TEST",
        "date_of_birth": date_of_birth,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-072] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `dob` when date stored in a locale-specific
# Evidence: Record the observed representation and protection/transform function for `dob`; distinguis
# ==============================================================================
def test_case_dem_072():
    """Test scenario for DEM-072: dob"""
    # ACTIVE TEST CASE: Represents identifiable user data
    dob = "active_sample_value_for_dob"
    payload = {
        "user_id": "USR_99214_TEST",
        "dob": dob,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-073] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `birthDate` when age range rather than exac
# Evidence: Record the observed representation and protection/transform function for `birthDate`; dist
# ==============================================================================
def test_case_dem_073():
    """Test scenario for DEM-073: birthDate"""
    # ACTIVE TEST CASE: Represents identifiable user data
    birthDate = "active_sample_value_for_birthDate"
    payload = {
        "user_id": "USR_99214_TEST",
        "birthDate": birthDate,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-074] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `age` when birth year only; determine wheth
# Evidence: Record the observed representation and protection/transform function for `age`; distinguis
# ==============================================================================
def test_case_dem_074():
    """Test scenario for DEM-074: age"""
    # ACTIVE TEST CASE: Represents identifiable user data
    age = "active_sample_value_for_age"
    payload = {
        "user_id": "USR_99214_TEST",
        "age": age,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-075] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `gender` when date of birth nested in profi
# Evidence: Record the observed representation and protection/transform function for `gender`; disting
# ==============================================================================
def test_case_dem_075():
    """Test scenario for DEM-075: gender"""
    # ACTIVE TEST CASE: Represents identifiable user data
    gender = "active_sample_value_for_gender"
    payload = {
        "user_id": "USR_99214_TEST",
        "gender": gender,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-076] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `birth_year` when age calculated from date 
# Evidence: Record the observed representation and protection/transform function for `birth_year`; dis
# ==============================================================================
def test_case_dem_076():
    """Test scenario for DEM-076: birth_year"""
    # ACTIVE TEST CASE: Represents identifiable user data
    birth_year = "active_sample_value_for_birth_year"
    payload = {
        "user_id": "USR_99214_TEST",
        "birth_year": birth_year,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-077] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `demographic_profile` when demographic fiel
# Evidence: Record the observed representation and protection/transform function for `demographic_prof
# ==============================================================================
def test_case_dem_077():
    """Test scenario for DEM-077: demographic_profile"""
    # ACTIVE TEST CASE: Represents identifiable user data
    demographic_profile = "active_sample_value_for_demographic_profile"
    payload = {
        "user_id": "USR_99214_TEST",
        "demographic_profile": demographic_profile,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-078] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `user_age` when demographic value returned 
# Evidence: Record the observed representation and protection/transform function for `user_age`; disti
# ==============================================================================
def test_case_dem_078():
    """Test scenario for DEM-078: user_age"""
    # ACTIVE TEST CASE: Represents identifiable user data
    user_age = "active_sample_value_for_user_age"
    payload = {
        "user_id": "USR_99214_TEST",
        "user_age": user_age,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-079] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `profile.demographics` when gender represen
# Evidence: Record the observed representation and protection/transform function for `profile.demograp
# ==============================================================================
def test_case_dem_079():
    """Test scenario for DEM-079: profile.demographics"""
    # ACTIVE TEST CASE: Represents identifiable user data
    profile_demographics = "active_sample_value_for_profile_demographics"
    payload = {
        "user_id": "USR_99214_TEST",
        "profile_demographics": profile_demographics,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-080] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `dateOfBirth` when demographic attribute in
# Evidence: Record the observed representation and protection/transform function for `dateOfBirth`; di
# ==============================================================================
def test_case_dem_080():
    """Test scenario for DEM-080: dateOfBirth"""
    # ACTIVE TEST CASE: Represents identifiable user data
    dateOfBirth = "active_sample_value_for_dateOfBirth"
    payload = {
        "user_id": "USR_99214_TEST",
        "dateOfBirth": dateOfBirth,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-081] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `cache_age variable` appear
# Evidence: Verify that the only evidence is `cache_age variable` and that no populated, user-linked `
# ==============================================================================
def test_case_dem_081():
    """Test scenario for DEM-081: cache_age variable"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_cache_age_variable = "MOCK_NON_PII_LITERAL_CACHE_AGE_VARIABLE"
    unrelated_system_config = {
        "config_key": "cache_age variable",
        "is_pii": False,
        "value": dummy_cache_age_variable
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: DEM-082] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `token_age or file_age` app
# Evidence: Verify that the only evidence is `token_age or file_age` and that no populated, user-linke
# ==============================================================================
def test_case_dem_082():
    """Test scenario for DEM-082: token_age or file_age"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_token_age_or_file_age = "MOCK_NON_PII_LITERAL_TOKEN_AGE_OR_FILE_AGE"
    unrelated_system_config = {
        "config_key": "token_age or file_age",
        "is_pii": False,
        "value": dummy_token_age_or_file_age
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: DEM-083] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `system gender setting` app
# Evidence: Verify that the only evidence is `system gender setting` and that no populated, user-linke
# ==============================================================================
def test_case_dem_083():
    """Test scenario for DEM-083: system gender setting"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_system_gender_setting = "MOCK_NON_PII_LITERAL_SYSTEM_GENDER_SETTING"
    unrelated_system_config = {
        "config_key": "system gender setting",
        "is_pii": False,
        "value": dummy_system_gender_setting
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: DEM-084] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `aggregate demographic stat
# Evidence: Verify that the only evidence is `aggregate demographic statistic` and that no populated, 
# ==============================================================================
def test_case_dem_084():
    """Test scenario for DEM-084: aggregate demographic statistic"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_aggregate_demographic_statistic = "MOCK_NON_PII_LITERAL_AGGREGATE_DEMOGRAPHIC_STATISTIC"
    unrelated_system_config = {
        "config_key": "aggregate demographic statistic",
        "is_pii": False,
        "value": dummy_aggregate_demographic_statistic
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: DEM-085] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `historical article birth y
# Evidence: Verify that the only evidence is `historical article birth year` and that no populated, us
# ==============================================================================
def test_case_dem_085():
    """Test scenario for DEM-085: historical article birth year"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_historical_article_birth_year = "MOCK_NON_PII_LITERAL_HISTORICAL_ARTICLE_BIRTH_YEAR"
    unrelated_system_config = {
        "config_key": "historical article birth year",
        "is_pii": False,
        "value": dummy_historical_article_birth_year
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: DEM-086] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `placeholder date` appears 
# Evidence: Verify that the only evidence is `placeholder date` and that no populated, user-linked `bi
# ==============================================================================
def test_case_dem_086():
    """Test scenario for DEM-086: placeholder date"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_placeholder_date = "MOCK_NON_PII_LITERAL_PLACEHOLDER_DATE"
    unrelated_system_config = {
        "config_key": "placeholder date",
        "is_pii": False,
        "value": dummy_placeholder_date
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: DEM-087] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `age field never populated`
# Evidence: Verify that the only evidence is `age field never populated` and that no populated, user-l
# ==============================================================================
def test_case_dem_087():
    """Test scenario for DEM-087: age field never populated"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_age_field_never_populated = "MOCK_NON_PII_LITERAL_AGE_FIELD_NEVER_POPULATED"
    unrelated_system_config = {
        "config_key": "age field never populated",
        "is_pii": False,
        "value": dummy_age_field_never_populated
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: DEM-088] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `unrelated variable named d
# Evidence: Verify that the only evidence is `unrelated variable named dob` and that no populated, use
# ==============================================================================
def test_case_dem_088():
    """Test scenario for DEM-088: unrelated variable named dob"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_unrelated_variable_named_dob = "MOCK_NON_PII_LITERAL_UNRELATED_VARIABLE_NAMED_DOB"
    unrelated_system_config = {
        "config_key": "unrelated variable named dob",
        "is_pii": False,
        "value": dummy_unrelated_variable_named_dob
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: DEM-089] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `UI setting rather than use
# Evidence: Verify that the only evidence is `UI setting rather than user attribute` and that no popul
# ==============================================================================
def test_case_dem_089():
    """Test scenario for DEM-089: UI setting rather than user attribute"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_UI_setting_rather_than_user_attribute = "MOCK_NON_PII_LITERAL_UI_SETTING_RATHER_THAN_USER_ATTRIBUTE"
    unrelated_system_config = {
        "config_key": "UI setting rather than user attribute",
        "is_pii": False,
        "value": dummy_UI_setting_rather_than_user_attribute
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: DEM-090] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `demographic term in docume
# Evidence: Verify that the only evidence is `demographic term in documentation only` and that no popu
# ==============================================================================
def test_case_dem_090():
    """Test scenario for DEM-090: demographic term in documentation only"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_demographic_term_in_documentation_only = "MOCK_NON_PII_LITERAL_DEMOGRAPHIC_TERM_IN_DOCUMENTATION_ONLY"
    unrelated_system_config = {
        "config_key": "demographic term in documentation only",
        "is_pii": False,
        "value": dummy_demographic_term_in_documentation_only
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: DEM-091] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `date_of_birth`
# Evidence: Record the exact `date_of_birth` source location, available type/context, missing runtime 
# ==============================================================================
def test_case_dem_091():
    """Test scenario for DEM-091: date_of_birth"""
    # ACTIVE TEST CASE: Represents identifiable user data
    date_of_birth = "active_sample_value_for_date_of_birth"
    payload = {
        "user_id": "USR_99214_TEST",
        "date_of_birth": date_of_birth,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-092] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `dob`: date sto
# Evidence: Record the exact `dob` source location, available type/context, missing runtime or linkage
# ==============================================================================
def test_case_dem_092():
    """Test scenario for DEM-092: dob"""
    # ACTIVE TEST CASE: Represents identifiable user data
    dob = "active_sample_value_for_dob"
    payload = {
        "user_id": "USR_99214_TEST",
        "dob": dob,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-093] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `birthDate`: ag
# Evidence: Record the exact `birthDate` source location, available type/context, missing runtime or l
# ==============================================================================
def test_case_dem_093():
    """Test scenario for DEM-093: birthDate"""
    # ACTIVE TEST CASE: Represents identifiable user data
    birthDate = "active_sample_value_for_birthDate"
    payload = {
        "user_id": "USR_99214_TEST",
        "birthDate": birthDate,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-094] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `age`: birth ye
# Evidence: Record the exact `age` source location, available type/context, missing runtime or linkage
# ==============================================================================
def test_case_dem_094():
    """Test scenario for DEM-094: age"""
    # ACTIVE TEST CASE: Represents identifiable user data
    age = "active_sample_value_for_age"
    payload = {
        "user_id": "USR_99214_TEST",
        "age": age,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-095] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `gender`: date 
# Evidence: Record the exact `gender` source location, available type/context, missing runtime or link
# ==============================================================================
def test_case_dem_095():
    """Test scenario for DEM-095: gender"""
    # ACTIVE TEST CASE: Represents identifiable user data
    gender = "active_sample_value_for_gender"
    payload = {
        "user_id": "USR_99214_TEST",
        "gender": gender,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-096] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `birth_year`: a
# Evidence: Record the exact `birth_year` source location, available type/context, missing runtime or 
# ==============================================================================
def test_case_dem_096():
    """Test scenario for DEM-096: birth_year"""
    # ACTIVE TEST CASE: Represents identifiable user data
    birth_year = "active_sample_value_for_birth_year"
    payload = {
        "user_id": "USR_99214_TEST",
        "birth_year": birth_year,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-097] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `demographic_pr
# Evidence: Record the exact `demographic_profile` source location, available type/context, missing ru
# ==============================================================================
def test_case_dem_097():
    """Test scenario for DEM-097: demographic_profile"""
    # ACTIVE TEST CASE: Represents identifiable user data
    demographic_profile = "active_sample_value_for_demographic_profile"
    payload = {
        "user_id": "USR_99214_TEST",
        "demographic_profile": demographic_profile,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-098] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `user_age`: dem
# Evidence: Record the exact `user_age` source location, available type/context, missing runtime or li
# ==============================================================================
def test_case_dem_098():
    """Test scenario for DEM-098: user_age"""
    # ACTIVE TEST CASE: Represents identifiable user data
    user_age = "active_sample_value_for_user_age"
    payload = {
        "user_id": "USR_99214_TEST",
        "user_age": user_age,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-099] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `profile.demogr
# Evidence: Record the exact `profile.demographics` source location, available type/context, missing r
# ==============================================================================
def test_case_dem_099():
    """Test scenario for DEM-099: profile.demographics"""
    # ACTIVE TEST CASE: Represents identifiable user data
    profile_demographics = "active_sample_value_for_profile_demographics"
    payload = {
        "user_id": "USR_99214_TEST",
        "profile_demographics": profile_demographics,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DEM-100] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `dateOfBirth`: 
# Evidence: Record the exact `dateOfBirth` source location, available type/context, missing runtime or
# ==============================================================================
def test_case_dem_100():
    """Test scenario for DEM-100: dateOfBirth"""
    # ACTIVE TEST CASE: Represents identifiable user data
    dateOfBirth = "active_sample_value_for_dateOfBirth"
    payload = {
        "user_id": "USR_99214_TEST",
        "dateOfBirth": dateOfBirth,
        "is_active_pii": True
    }
    return payload
