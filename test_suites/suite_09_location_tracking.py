"""
COMPLYDP EDGE-CASE TEST SUITE: LOCATION INFORMATION (LOC)
Contains all 100 test scenarios (LOC-001 to LOC-100).
Includes Positive PII cases, API flows, Masked cases, and Negative Control Traps.
"""

import re
import json
import hashlib
from typing import Dict, Any, List, Optional

# ==============================================================================
# [TEST_ID: LOC-001] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `latitude` in the repository schema or source code, including
# Evidence: Verify the exact `latitude` declaration, its type/validation/usage, and whether it is link
# ==============================================================================
def test_case_loc_001():
    """Test scenario for LOC-001: latitude"""
    # ACTIVE TEST CASE: Represents identifiable user data
    latitude = "active_sample_value_for_latitude"
    payload = {
        "user_id": "USR_99214_TEST",
        "latitude": latitude,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-002] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `longitude` in the repository schema or source code, includin
# Evidence: Verify the exact `longitude` declaration, its type/validation/usage, and whether it is lin
# ==============================================================================
def test_case_loc_002():
    """Test scenario for LOC-002: longitude"""
    # ACTIVE TEST CASE: Represents identifiable user data
    longitude = "active_sample_value_for_longitude"
    payload = {
        "user_id": "USR_99214_TEST",
        "longitude": longitude,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-003] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `gps_coordinates` in the repository schema or source code, in
# Evidence: Verify the exact `gps_coordinates` declaration, its type/validation/usage, and whether it 
# ==============================================================================
def test_case_loc_003():
    """Test scenario for LOC-003: gps_coordinates"""
    # ACTIVE TEST CASE: Represents identifiable user data
    gps_coordinates = "active_sample_value_for_gps_coordinates"
    payload = {
        "user_id": "USR_99214_TEST",
        "gps_coordinates": gps_coordinates,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-004] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `home_address` in the repository schema or source code, inclu
# Evidence: Verify the exact `home_address` declaration, its type/validation/usage, and whether it is 
# ==============================================================================
def test_case_loc_004():
    """Test scenario for LOC-004: home_address"""
    # ACTIVE TEST CASE: Represents identifiable user data
    home_address = "active_sample_value_for_home_address"
    payload = {
        "user_id": "USR_99214_TEST",
        "home_address": home_address,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-005] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `work_address` in the repository schema or source code, inclu
# Evidence: Verify the exact `work_address` declaration, its type/validation/usage, and whether it is 
# ==============================================================================
def test_case_loc_005():
    """Test scenario for LOC-005: work_address"""
    # ACTIVE TEST CASE: Represents identifiable user data
    work_address = "active_sample_value_for_work_address"
    payload = {
        "user_id": "USR_99214_TEST",
        "work_address": work_address,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-006] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `location_history` in the repository schema or source code, i
# Evidence: Verify the exact `location_history` declaration, its type/validation/usage, and whether it
# ==============================================================================
def test_case_loc_006():
    """Test scenario for LOC-006: location_history"""
    # ACTIVE TEST CASE: Represents identifiable user data
    location_history = "active_sample_value_for_location_history"
    payload = {
        "user_id": "USR_99214_TEST",
        "location_history": location_history,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-007] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `geohash` in the repository schema or source code, including 
# Evidence: Verify the exact `geohash` declaration, its type/validation/usage, and whether it is linke
# ==============================================================================
def test_case_loc_007():
    """Test scenario for LOC-007: geohash"""
    # ACTIVE TEST CASE: Represents identifiable user data
    geohash = "active_sample_value_for_geohash"
    payload = {
        "user_id": "USR_99214_TEST",
        "geohash": geohash,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-008] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `current_location` in the repository schema or source code, i
# Evidence: Verify the exact `current_location` declaration, its type/validation/usage, and whether it
# ==============================================================================
def test_case_loc_008():
    """Test scenario for LOC-008: current_location"""
    # ACTIVE TEST CASE: Represents identifiable user data
    current_location = "active_sample_value_for_current_location"
    payload = {
        "user_id": "USR_99214_TEST",
        "current_location": current_location,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-009] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `geo_location` in the repository schema or source code, inclu
# Evidence: Verify the exact `geo_location` declaration, its type/validation/usage, and whether it is 
# ==============================================================================
def test_case_loc_009():
    """Test scenario for LOC-009: geo_location"""
    # ACTIVE TEST CASE: Represents identifiable user data
    geo_location = "active_sample_value_for_geo_location"
    payload = {
        "user_id": "USR_99214_TEST",
        "geo_location": geo_location,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-010] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `user_coordinates` in the repository schema or source code, i
# Evidence: Verify the exact `user_coordinates` declaration, its type/validation/usage, and whether it
# ==============================================================================
def test_case_loc_010():
    """Test scenario for LOC-010: user_coordinates"""
    # ACTIVE TEST CASE: Represents identifiable user data
    user_coordinates = "active_sample_value_for_user_coordinates"
    payload = {
        "user_id": "USR_99214_TEST",
        "user_coordinates": user_coordinates,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-011] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `latitude` when latitude/longitude coordinate pair with va
# Evidence: Capture the full JSON/object path for `latitude`, the parent record or user key, and the c
# ==============================================================================
def test_case_loc_011():
    """Test scenario for LOC-011: latitude"""
    # ACTIVE TEST CASE: Represents identifiable user data
    latitude = "active_sample_value_for_latitude"
    payload = {
        "user_id": "USR_99214_TEST",
        "latitude": latitude,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-012] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `longitude` when GPS coordinates at high versus coarse pre
# Evidence: Capture the full JSON/object path for `longitude`, the parent record or user key, and the 
# ==============================================================================
def test_case_loc_012():
    """Test scenario for LOC-012: longitude"""
    # ACTIVE TEST CASE: Represents identifiable user data
    longitude = "active_sample_value_for_longitude"
    payload = {
        "user_id": "USR_99214_TEST",
        "longitude": longitude,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-013] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `gps_coordinates` when coordinates encoded as a geohash; i
# Evidence: Capture the full JSON/object path for `gps_coordinates`, the parent record or user key, an
# ==============================================================================
def test_case_loc_013():
    """Test scenario for LOC-013: gps_coordinates"""
    # ACTIVE TEST CASE: Represents identifiable user data
    gps_coordinates = "active_sample_value_for_gps_coordinates"
    payload = {
        "user_id": "USR_99214_TEST",
        "gps_coordinates": gps_coordinates,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-014] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `home_address` when location history across timestamped ev
# Evidence: Capture the full JSON/object path for `home_address`, the parent record or user key, and t
# ==============================================================================
def test_case_loc_014():
    """Test scenario for LOC-014: home_address"""
    # ACTIVE TEST CASE: Represents identifiable user data
    home_address = "active_sample_value_for_home_address"
    payload = {
        "user_id": "USR_99214_TEST",
        "home_address": home_address,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-015] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `work_address` when home/work location nested in a profile
# Evidence: Capture the full JSON/object path for `work_address`, the parent record or user key, and t
# ==============================================================================
def test_case_loc_015():
    """Test scenario for LOC-015: work_address"""
    # ACTIVE TEST CASE: Represents identifiable user data
    work_address = "active_sample_value_for_work_address"
    payload = {
        "user_id": "USR_99214_TEST",
        "work_address": work_address,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-016] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `location_history` when location obtained through a device
# Evidence: Capture the full JSON/object path for `location_history`, the parent record or user key, a
# ==============================================================================
def test_case_loc_016():
    """Test scenario for LOC-016: location_history"""
    # ACTIVE TEST CASE: Represents identifiable user data
    location_history = "active_sample_value_for_location_history"
    payload = {
        "user_id": "USR_99214_TEST",
        "location_history": location_history,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-017] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `geohash` when location inferred from IP address; inspect 
# Evidence: Capture the full JSON/object path for `geohash`, the parent record or user key, and the co
# ==============================================================================
def test_case_loc_017():
    """Test scenario for LOC-017: geohash"""
    # ACTIVE TEST CASE: Represents identifiable user data
    geohash = "active_sample_value_for_geohash"
    payload = {
        "user_id": "USR_99214_TEST",
        "geohash": geohash,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-018] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `current_location` when coordinates stored as strings or d
# Evidence: Capture the full JSON/object path for `current_location`, the parent record or user key, a
# ==============================================================================
def test_case_loc_018():
    """Test scenario for LOC-018: current_location"""
    # ACTIVE TEST CASE: Represents identifiable user data
    current_location = "active_sample_value_for_current_location"
    payload = {
        "user_id": "USR_99214_TEST",
        "current_location": current_location,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-019] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `geo_location` when coordinates encoded in a URL parameter
# Evidence: Capture the full JSON/object path for `geo_location`, the parent record or user key, and t
# ==============================================================================
def test_case_loc_019():
    """Test scenario for LOC-019: geo_location"""
    # ACTIVE TEST CASE: Represents identifiable user data
    geo_location = "active_sample_value_for_geo_location"
    payload = {
        "user_id": "USR_99214_TEST",
        "geo_location": geo_location,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-020] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `user_coordinates` when location events joined to a user I
# Evidence: Capture the full JSON/object path for `user_coordinates`, the parent record or user key, a
# ==============================================================================
def test_case_loc_020():
    """Test scenario for LOC-020: user_coordinates"""
    # ACTIVE TEST CASE: Represents identifiable user data
    user_coordinates = "active_sample_value_for_user_coordinates"
    payload = {
        "user_id": "USR_99214_TEST",
        "user_coordinates": user_coordinates,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-021] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `latitude` through an API boundary when latitude/longitude coo
# Evidence: Verify the request/response schema and call site for `latitude`, direction of flow, endpoi
# ==============================================================================
def test_case_loc_021():
    """Test scenario for LOC-021: latitude"""
    # ACTIVE TEST CASE: Represents identifiable user data
    latitude = "active_sample_value_for_latitude"
    payload = {
        "user_id": "USR_99214_TEST",
        "latitude": latitude,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-022] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `longitude` through an API boundary when GPS coordinates at hi
# Evidence: Verify the request/response schema and call site for `longitude`, direction of flow, endpo
# ==============================================================================
def test_case_loc_022():
    """Test scenario for LOC-022: longitude"""
    # ACTIVE TEST CASE: Represents identifiable user data
    longitude = "active_sample_value_for_longitude"
    payload = {
        "user_id": "USR_99214_TEST",
        "longitude": longitude,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-023] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `gps_coordinates` through an API boundary when coordinates enc
# Evidence: Verify the request/response schema and call site for `gps_coordinates`, direction of flow,
# ==============================================================================
def test_case_loc_023():
    """Test scenario for LOC-023: gps_coordinates"""
    # ACTIVE TEST CASE: Represents identifiable user data
    gps_coordinates = "active_sample_value_for_gps_coordinates"
    payload = {
        "user_id": "USR_99214_TEST",
        "gps_coordinates": gps_coordinates,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-024] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `home_address` through an API boundary when location history a
# Evidence: Verify the request/response schema and call site for `home_address`, direction of flow, en
# ==============================================================================
def test_case_loc_024():
    """Test scenario for LOC-024: home_address"""
    # ACTIVE TEST CASE: Represents identifiable user data
    home_address = "active_sample_value_for_home_address"
    payload = {
        "user_id": "USR_99214_TEST",
        "home_address": home_address,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-025] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `work_address` through an API boundary when home/work location
# Evidence: Verify the request/response schema and call site for `work_address`, direction of flow, en
# ==============================================================================
def test_case_loc_025():
    """Test scenario for LOC-025: work_address"""
    # ACTIVE TEST CASE: Represents identifiable user data
    work_address = "active_sample_value_for_work_address"
    payload = {
        "user_id": "USR_99214_TEST",
        "work_address": work_address,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-026] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `location_history` through an API boundary when location obtai
# Evidence: Verify the request/response schema and call site for `location_history`, direction of flow
# ==============================================================================
def test_case_loc_026():
    """Test scenario for LOC-026: location_history"""
    # ACTIVE TEST CASE: Represents identifiable user data
    location_history = "active_sample_value_for_location_history"
    payload = {
        "user_id": "USR_99214_TEST",
        "location_history": location_history,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-027] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `geohash` through an API boundary when location inferred from 
# Evidence: Verify the request/response schema and call site for `geohash`, direction of flow, endpoin
# ==============================================================================
def test_case_loc_027():
    """Test scenario for LOC-027: geohash"""
    # ACTIVE TEST CASE: Represents identifiable user data
    geohash = "active_sample_value_for_geohash"
    payload = {
        "user_id": "USR_99214_TEST",
        "geohash": geohash,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-028] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `current_location` through an API boundary when coordinates st
# Evidence: Verify the request/response schema and call site for `current_location`, direction of flow
# ==============================================================================
def test_case_loc_028():
    """Test scenario for LOC-028: current_location"""
    # ACTIVE TEST CASE: Represents identifiable user data
    current_location = "active_sample_value_for_current_location"
    payload = {
        "user_id": "USR_99214_TEST",
        "current_location": current_location,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-029] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `geo_location` through an API boundary when coordinates encode
# Evidence: Verify the request/response schema and call site for `geo_location`, direction of flow, en
# ==============================================================================
def test_case_loc_029():
    """Test scenario for LOC-029: geo_location"""
    # ACTIVE TEST CASE: Represents identifiable user data
    geo_location = "active_sample_value_for_geo_location"
    payload = {
        "user_id": "USR_99214_TEST",
        "geo_location": geo_location,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-030] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `user_coordinates` through an API boundary when location event
# Evidence: Verify the request/response schema and call site for `user_coordinates`, direction of flow
# ==============================================================================
def test_case_loc_030():
    """Test scenario for LOC-030: user_coordinates"""
    # ACTIVE TEST CASE: Represents identifiable user data
    user_coordinates = "active_sample_value_for_user_coordinates"
    payload = {
        "user_id": "USR_99214_TEST",
        "user_coordinates": user_coordinates,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-031] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `latitude` when latitude/longitude coordinate pair 
# Evidence: Show the source value, transformation or derivation applied to `latitude`, and resulting s
# ==============================================================================
def test_case_loc_031():
    """Test scenario for LOC-031: latitude"""
    # ACTIVE TEST CASE: Represents identifiable user data
    latitude = "active_sample_value_for_latitude"
    payload = {
        "user_id": "USR_99214_TEST",
        "latitude": latitude,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-032] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `longitude` when GPS coordinates at high versus coa
# Evidence: Show the source value, transformation or derivation applied to `longitude`, and resulting 
# ==============================================================================
def test_case_loc_032():
    """Test scenario for LOC-032: longitude"""
    # ACTIVE TEST CASE: Represents identifiable user data
    longitude = "active_sample_value_for_longitude"
    payload = {
        "user_id": "USR_99214_TEST",
        "longitude": longitude,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-033] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `gps_coordinates` when coordinates encoded as a geo
# Evidence: Show the source value, transformation or derivation applied to `gps_coordinates`, and resu
# ==============================================================================
def test_case_loc_033():
    """Test scenario for LOC-033: gps_coordinates"""
    # ACTIVE TEST CASE: Represents identifiable user data
    gps_coordinates = "active_sample_value_for_gps_coordinates"
    payload = {
        "user_id": "USR_99214_TEST",
        "gps_coordinates": gps_coordinates,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-034] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `home_address` when location history across timesta
# Evidence: Show the source value, transformation or derivation applied to `home_address`, and resulti
# ==============================================================================
def test_case_loc_034():
    """Test scenario for LOC-034: home_address"""
    # ACTIVE TEST CASE: Represents identifiable user data
    home_address = "active_sample_value_for_home_address"
    payload = {
        "user_id": "USR_99214_TEST",
        "home_address": home_address,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-035] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `work_address` when home/work location nested in a 
# Evidence: Show the source value, transformation or derivation applied to `work_address`, and resulti
# ==============================================================================
def test_case_loc_035():
    """Test scenario for LOC-035: work_address"""
    # ACTIVE TEST CASE: Represents identifiable user data
    work_address = "active_sample_value_for_work_address"
    payload = {
        "user_id": "USR_99214_TEST",
        "work_address": work_address,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-036] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `location_history` when location obtained through a
# Evidence: Show the source value, transformation or derivation applied to `location_history`, and res
# ==============================================================================
def test_case_loc_036():
    """Test scenario for LOC-036: location_history"""
    # ACTIVE TEST CASE: Represents identifiable user data
    location_history = "active_sample_value_for_location_history"
    payload = {
        "user_id": "USR_99214_TEST",
        "location_history": location_history,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-037] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `geohash` when location inferred from IP address; f
# Evidence: Show the source value, transformation or derivation applied to `geohash`, and resulting si
# ==============================================================================
def test_case_loc_037():
    """Test scenario for LOC-037: geohash"""
    # ACTIVE TEST CASE: Represents identifiable user data
    geohash = "active_sample_value_for_geohash"
    payload = {
        "user_id": "USR_99214_TEST",
        "geohash": geohash,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-038] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `current_location` when coordinates stored as strin
# Evidence: Show the source value, transformation or derivation applied to `current_location`, and res
# ==============================================================================
def test_case_loc_038():
    """Test scenario for LOC-038: current_location"""
    # ACTIVE TEST CASE: Represents identifiable user data
    current_location = "active_sample_value_for_current_location"
    payload = {
        "user_id": "USR_99214_TEST",
        "current_location": current_location,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-039] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `geo_location` when coordinates encoded in a URL pa
# Evidence: Show the source value, transformation or derivation applied to `geo_location`, and resulti
# ==============================================================================
def test_case_loc_039():
    """Test scenario for LOC-039: geo_location"""
    # ACTIVE TEST CASE: Represents identifiable user data
    geo_location = "active_sample_value_for_geo_location"
    payload = {
        "user_id": "USR_99214_TEST",
        "geo_location": geo_location,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-040] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `user_coordinates` when location events joined to a
# Evidence: Show the source value, transformation or derivation applied to `user_coordinates`, and res
# ==============================================================================
def test_case_loc_040():
    """Test scenario for LOC-040: user_coordinates"""
    # ACTIVE TEST CASE: Represents identifiable user data
    user_coordinates = "active_sample_value_for_user_coordinates"
    payload = {
        "user_id": "USR_99214_TEST",
        "user_coordinates": user_coordinates,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-041] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `latitude` when latitude/longitude 
# Evidence: Identify the exact `latitude` write/read operation and target (table, document, cache, fil
# ==============================================================================
def test_case_loc_041():
    """Test scenario for LOC-041: latitude"""
    # ACTIVE TEST CASE: Represents identifiable user data
    latitude = "active_sample_value_for_latitude"
    payload = {
        "user_id": "USR_99214_TEST",
        "latitude": latitude,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-042] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `longitude` when GPS coordinates at
# Evidence: Identify the exact `longitude` write/read operation and target (table, document, cache, fi
# ==============================================================================
def test_case_loc_042():
    """Test scenario for LOC-042: longitude"""
    # ACTIVE TEST CASE: Represents identifiable user data
    longitude = "active_sample_value_for_longitude"
    payload = {
        "user_id": "USR_99214_TEST",
        "longitude": longitude,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-043] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `gps_coordinates` when coordinates 
# Evidence: Identify the exact `gps_coordinates` write/read operation and target (table, document, cac
# ==============================================================================
def test_case_loc_043():
    """Test scenario for LOC-043: gps_coordinates"""
    # ACTIVE TEST CASE: Represents identifiable user data
    gps_coordinates = "active_sample_value_for_gps_coordinates"
    payload = {
        "user_id": "USR_99214_TEST",
        "gps_coordinates": gps_coordinates,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-044] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `home_address` when location histor
# Evidence: Identify the exact `home_address` write/read operation and target (table, document, cache,
# ==============================================================================
def test_case_loc_044():
    """Test scenario for LOC-044: home_address"""
    # ACTIVE TEST CASE: Represents identifiable user data
    home_address = "active_sample_value_for_home_address"
    payload = {
        "user_id": "USR_99214_TEST",
        "home_address": home_address,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-045] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `work_address` when home/work locat
# Evidence: Identify the exact `work_address` write/read operation and target (table, document, cache,
# ==============================================================================
def test_case_loc_045():
    """Test scenario for LOC-045: work_address"""
    # ACTIVE TEST CASE: Represents identifiable user data
    work_address = "active_sample_value_for_work_address"
    payload = {
        "user_id": "USR_99214_TEST",
        "work_address": work_address,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-046] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `location_history` when location ob
# Evidence: Identify the exact `location_history` write/read operation and target (table, document, ca
# ==============================================================================
def test_case_loc_046():
    """Test scenario for LOC-046: location_history"""
    # ACTIVE TEST CASE: Represents identifiable user data
    location_history = "active_sample_value_for_location_history"
    payload = {
        "user_id": "USR_99214_TEST",
        "location_history": location_history,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-047] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `geohash` when location inferred fr
# Evidence: Identify the exact `geohash` write/read operation and target (table, document, cache, file
# ==============================================================================
def test_case_loc_047():
    """Test scenario for LOC-047: geohash"""
    # ACTIVE TEST CASE: Represents identifiable user data
    geohash = "active_sample_value_for_geohash"
    payload = {
        "user_id": "USR_99214_TEST",
        "geohash": geohash,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-048] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `current_location` when coordinates
# Evidence: Identify the exact `current_location` write/read operation and target (table, document, ca
# ==============================================================================
def test_case_loc_048():
    """Test scenario for LOC-048: current_location"""
    # ACTIVE TEST CASE: Represents identifiable user data
    current_location = "active_sample_value_for_current_location"
    payload = {
        "user_id": "USR_99214_TEST",
        "current_location": current_location,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-049] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `geo_location` when coordinates enc
# Evidence: Identify the exact `geo_location` write/read operation and target (table, document, cache,
# ==============================================================================
def test_case_loc_049():
    """Test scenario for LOC-049: geo_location"""
    # ACTIVE TEST CASE: Represents identifiable user data
    geo_location = "active_sample_value_for_geo_location"
    payload = {
        "user_id": "USR_99214_TEST",
        "geo_location": geo_location,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-050] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `user_coordinates` when location ev
# Evidence: Identify the exact `user_coordinates` write/read operation and target (table, document, ca
# ==============================================================================
def test_case_loc_050():
    """Test scenario for LOC-050: user_coordinates"""
    # ACTIVE TEST CASE: Represents identifiable user data
    user_coordinates = "active_sample_value_for_user_coordinates"
    payload = {
        "user_id": "USR_99214_TEST",
        "user_coordinates": user_coordinates,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-051] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `latitude` becomes identifiable or linkable when latitude/lo
# Evidence: Record `latitude`'s join key/foreign key, related table or service, and the code path that
# ==============================================================================
def test_case_loc_051():
    """Test scenario for LOC-051: latitude"""
    # ACTIVE TEST CASE: Represents identifiable user data
    latitude = "active_sample_value_for_latitude"
    payload = {
        "user_id": "USR_99214_TEST",
        "latitude": latitude,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-052] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `longitude` becomes identifiable or linkable when GPS coordi
# Evidence: Record `longitude`'s join key/foreign key, related table or service, and the code path tha
# ==============================================================================
def test_case_loc_052():
    """Test scenario for LOC-052: longitude"""
    # ACTIVE TEST CASE: Represents identifiable user data
    longitude = "active_sample_value_for_longitude"
    payload = {
        "user_id": "USR_99214_TEST",
        "longitude": longitude,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-053] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `gps_coordinates` becomes identifiable or linkable when coor
# Evidence: Record `gps_coordinates`'s join key/foreign key, related table or service, and the code pa
# ==============================================================================
def test_case_loc_053():
    """Test scenario for LOC-053: gps_coordinates"""
    # ACTIVE TEST CASE: Represents identifiable user data
    gps_coordinates = "active_sample_value_for_gps_coordinates"
    payload = {
        "user_id": "USR_99214_TEST",
        "gps_coordinates": gps_coordinates,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-054] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `home_address` becomes identifiable or linkable when locatio
# Evidence: Record `home_address`'s join key/foreign key, related table or service, and the code path 
# ==============================================================================
def test_case_loc_054():
    """Test scenario for LOC-054: home_address"""
    # ACTIVE TEST CASE: Represents identifiable user data
    home_address = "active_sample_value_for_home_address"
    payload = {
        "user_id": "USR_99214_TEST",
        "home_address": home_address,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-055] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `work_address` becomes identifiable or linkable when home/wo
# Evidence: Record `work_address`'s join key/foreign key, related table or service, and the code path 
# ==============================================================================
def test_case_loc_055():
    """Test scenario for LOC-055: work_address"""
    # ACTIVE TEST CASE: Represents identifiable user data
    work_address = "active_sample_value_for_work_address"
    payload = {
        "user_id": "USR_99214_TEST",
        "work_address": work_address,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-056] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `location_history` becomes identifiable or linkable when loc
# Evidence: Record `location_history`'s join key/foreign key, related table or service, and the code p
# ==============================================================================
def test_case_loc_056():
    """Test scenario for LOC-056: location_history"""
    # ACTIVE TEST CASE: Represents identifiable user data
    location_history = "active_sample_value_for_location_history"
    payload = {
        "user_id": "USR_99214_TEST",
        "location_history": location_history,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-057] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `geohash` becomes identifiable or linkable when location inf
# Evidence: Record `geohash`'s join key/foreign key, related table or service, and the code path that 
# ==============================================================================
def test_case_loc_057():
    """Test scenario for LOC-057: geohash"""
    # ACTIVE TEST CASE: Represents identifiable user data
    geohash = "active_sample_value_for_geohash"
    payload = {
        "user_id": "USR_99214_TEST",
        "geohash": geohash,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-058] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `current_location` becomes identifiable or linkable when coo
# Evidence: Record `current_location`'s join key/foreign key, related table or service, and the code p
# ==============================================================================
def test_case_loc_058():
    """Test scenario for LOC-058: current_location"""
    # ACTIVE TEST CASE: Represents identifiable user data
    current_location = "active_sample_value_for_current_location"
    payload = {
        "user_id": "USR_99214_TEST",
        "current_location": current_location,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-059] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `geo_location` becomes identifiable or linkable when coordin
# Evidence: Record `geo_location`'s join key/foreign key, related table or service, and the code path 
# ==============================================================================
def test_case_loc_059():
    """Test scenario for LOC-059: geo_location"""
    # ACTIVE TEST CASE: Represents identifiable user data
    geo_location = "active_sample_value_for_geo_location"
    payload = {
        "user_id": "USR_99214_TEST",
        "geo_location": geo_location,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-060] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `user_coordinates` becomes identifiable or linkable when loc
# Evidence: Record `user_coordinates`'s join key/foreign key, related table or service, and the code p
# ==============================================================================
def test_case_loc_060():
    """Test scenario for LOC-060: user_coordinates"""
    # ACTIVE TEST CASE: Represents identifiable user data
    user_coordinates = "active_sample_value_for_user_coordinates"
    payload = {
        "user_id": "USR_99214_TEST",
        "user_coordinates": user_coordinates,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-061] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `latitude` to a third-party boundary when latitude/longitude coo
# Evidence: Verify the payload field `latitude`, outbound call site, destination/vendor, and whether t
# ==============================================================================
def test_case_loc_061():
    """Test scenario for LOC-061: latitude"""
    # ACTIVE TEST CASE: Represents identifiable user data
    latitude = "active_sample_value_for_latitude"
    payload = {
        "user_id": "USR_99214_TEST",
        "latitude": latitude,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-062] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `longitude` to a third-party boundary when GPS coordinates at hi
# Evidence: Verify the payload field `longitude`, outbound call site, destination/vendor, and whether 
# ==============================================================================
def test_case_loc_062():
    """Test scenario for LOC-062: longitude"""
    # ACTIVE TEST CASE: Represents identifiable user data
    longitude = "active_sample_value_for_longitude"
    payload = {
        "user_id": "USR_99214_TEST",
        "longitude": longitude,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-063] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `gps_coordinates` to a third-party boundary when coordinates enc
# Evidence: Verify the payload field `gps_coordinates`, outbound call site, destination/vendor, and wh
# ==============================================================================
def test_case_loc_063():
    """Test scenario for LOC-063: gps_coordinates"""
    # ACTIVE TEST CASE: Represents identifiable user data
    gps_coordinates = "active_sample_value_for_gps_coordinates"
    payload = {
        "user_id": "USR_99214_TEST",
        "gps_coordinates": gps_coordinates,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-064] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `home_address` to a third-party boundary when location history a
# Evidence: Verify the payload field `home_address`, outbound call site, destination/vendor, and wheth
# ==============================================================================
def test_case_loc_064():
    """Test scenario for LOC-064: home_address"""
    # ACTIVE TEST CASE: Represents identifiable user data
    home_address = "active_sample_value_for_home_address"
    payload = {
        "user_id": "USR_99214_TEST",
        "home_address": home_address,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-065] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `work_address` to a third-party boundary when home/work location
# Evidence: Verify the payload field `work_address`, outbound call site, destination/vendor, and wheth
# ==============================================================================
def test_case_loc_065():
    """Test scenario for LOC-065: work_address"""
    # ACTIVE TEST CASE: Represents identifiable user data
    work_address = "active_sample_value_for_work_address"
    payload = {
        "user_id": "USR_99214_TEST",
        "work_address": work_address,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-066] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `location_history` to a third-party boundary when location obtai
# Evidence: Verify the payload field `location_history`, outbound call site, destination/vendor, and w
# ==============================================================================
def test_case_loc_066():
    """Test scenario for LOC-066: location_history"""
    # ACTIVE TEST CASE: Represents identifiable user data
    location_history = "active_sample_value_for_location_history"
    payload = {
        "user_id": "USR_99214_TEST",
        "location_history": location_history,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-067] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `geohash` to a third-party boundary when location inferred from 
# Evidence: Verify the payload field `geohash`, outbound call site, destination/vendor, and whether th
# ==============================================================================
def test_case_loc_067():
    """Test scenario for LOC-067: geohash"""
    # ACTIVE TEST CASE: Represents identifiable user data
    geohash = "active_sample_value_for_geohash"
    payload = {
        "user_id": "USR_99214_TEST",
        "geohash": geohash,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-068] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `current_location` to a third-party boundary when coordinates st
# Evidence: Verify the payload field `current_location`, outbound call site, destination/vendor, and w
# ==============================================================================
def test_case_loc_068():
    """Test scenario for LOC-068: current_location"""
    # ACTIVE TEST CASE: Represents identifiable user data
    current_location = "active_sample_value_for_current_location"
    payload = {
        "user_id": "USR_99214_TEST",
        "current_location": current_location,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-069] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `geo_location` to a third-party boundary when coordinates encode
# Evidence: Verify the payload field `geo_location`, outbound call site, destination/vendor, and wheth
# ==============================================================================
def test_case_loc_069():
    """Test scenario for LOC-069: geo_location"""
    # ACTIVE TEST CASE: Represents identifiable user data
    geo_location = "active_sample_value_for_geo_location"
    payload = {
        "user_id": "USR_99214_TEST",
        "geo_location": geo_location,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-070] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `user_coordinates` to a third-party boundary when location event
# Evidence: Verify the payload field `user_coordinates`, outbound call site, destination/vendor, and w
# ==============================================================================
def test_case_loc_070():
    """Test scenario for LOC-070: user_coordinates"""
    # ACTIVE TEST CASE: Represents identifiable user data
    user_coordinates = "active_sample_value_for_user_coordinates"
    payload = {
        "user_id": "USR_99214_TEST",
        "user_coordinates": user_coordinates,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-071] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `latitude` when latitude/longitude coordina
# Evidence: Record the observed representation and protection/transform function for `latitude`; disti
# ==============================================================================
def test_case_loc_071():
    """Test scenario for LOC-071: latitude"""
    # ACTIVE TEST CASE: Represents identifiable user data
    latitude = "active_sample_value_for_latitude"
    payload = {
        "user_id": "USR_99214_TEST",
        "latitude": latitude,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-072] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `longitude` when GPS coordinates at high ve
# Evidence: Record the observed representation and protection/transform function for `longitude`; dist
# ==============================================================================
def test_case_loc_072():
    """Test scenario for LOC-072: longitude"""
    # ACTIVE TEST CASE: Represents identifiable user data
    longitude = "active_sample_value_for_longitude"
    payload = {
        "user_id": "USR_99214_TEST",
        "longitude": longitude,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-073] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `gps_coordinates` when coordinates encoded 
# Evidence: Record the observed representation and protection/transform function for `gps_coordinates`
# ==============================================================================
def test_case_loc_073():
    """Test scenario for LOC-073: gps_coordinates"""
    # ACTIVE TEST CASE: Represents identifiable user data
    gps_coordinates = "active_sample_value_for_gps_coordinates"
    payload = {
        "user_id": "USR_99214_TEST",
        "gps_coordinates": gps_coordinates,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-074] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `home_address` when location history across
# Evidence: Record the observed representation and protection/transform function for `home_address`; d
# ==============================================================================
def test_case_loc_074():
    """Test scenario for LOC-074: home_address"""
    # ACTIVE TEST CASE: Represents identifiable user data
    home_address = "active_sample_value_for_home_address"
    payload = {
        "user_id": "USR_99214_TEST",
        "home_address": home_address,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-075] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `work_address` when home/work location nest
# Evidence: Record the observed representation and protection/transform function for `work_address`; d
# ==============================================================================
def test_case_loc_075():
    """Test scenario for LOC-075: work_address"""
    # ACTIVE TEST CASE: Represents identifiable user data
    work_address = "active_sample_value_for_work_address"
    payload = {
        "user_id": "USR_99214_TEST",
        "work_address": work_address,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-076] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `location_history` when location obtained t
# Evidence: Record the observed representation and protection/transform function for `location_history
# ==============================================================================
def test_case_loc_076():
    """Test scenario for LOC-076: location_history"""
    # ACTIVE TEST CASE: Represents identifiable user data
    location_history = "active_sample_value_for_location_history"
    payload = {
        "user_id": "USR_99214_TEST",
        "location_history": location_history,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-077] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `geohash` when location inferred from IP ad
# Evidence: Record the observed representation and protection/transform function for `geohash`; distin
# ==============================================================================
def test_case_loc_077():
    """Test scenario for LOC-077: geohash"""
    # ACTIVE TEST CASE: Represents identifiable user data
    geohash = "active_sample_value_for_geohash"
    payload = {
        "user_id": "USR_99214_TEST",
        "geohash": geohash,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-078] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `current_location` when coordinates stored 
# Evidence: Record the observed representation and protection/transform function for `current_location
# ==============================================================================
def test_case_loc_078():
    """Test scenario for LOC-078: current_location"""
    # ACTIVE TEST CASE: Represents identifiable user data
    current_location = "active_sample_value_for_current_location"
    payload = {
        "user_id": "USR_99214_TEST",
        "current_location": current_location,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-079] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `geo_location` when coordinates encoded in 
# Evidence: Record the observed representation and protection/transform function for `geo_location`; d
# ==============================================================================
def test_case_loc_079():
    """Test scenario for LOC-079: geo_location"""
    # ACTIVE TEST CASE: Represents identifiable user data
    geo_location = "active_sample_value_for_geo_location"
    payload = {
        "user_id": "USR_99214_TEST",
        "geo_location": geo_location,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-080] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `user_coordinates` when location events joi
# Evidence: Record the observed representation and protection/transform function for `user_coordinates
# ==============================================================================
def test_case_loc_080():
    """Test scenario for LOC-080: user_coordinates"""
    # ACTIVE TEST CASE: Represents identifiable user data
    user_coordinates = "active_sample_value_for_user_coordinates"
    payload = {
        "user_id": "USR_99214_TEST",
        "user_coordinates": user_coordinates,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-081] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `map-centre coordinates` ap
# Evidence: Verify that the only evidence is `map-centre coordinates` and that no populated, user-link
# ==============================================================================
def test_case_loc_081():
    """Test scenario for LOC-081: map-centre coordinates"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_map_centre_coordinates = "MOCK_NON_PII_LITERAL_MAP_CENTRE_COORDINATES"
    unrelated_system_config = {
        "config_key": "map-centre coordinates",
        "is_pii": False,
        "value": dummy_map_centre_coordinates
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: LOC-082] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `public office address` app
# Evidence: Verify that the only evidence is `public office address` and that no populated, user-linke
# ==============================================================================
def test_case_loc_082():
    """Test scenario for LOC-082: public office address"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_public_office_address = "MOCK_NON_PII_LITERAL_PUBLIC_OFFICE_ADDRESS"
    unrelated_system_config = {
        "config_key": "public office address",
        "is_pii": False,
        "value": dummy_public_office_address
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: LOC-083] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `latitude used in a math ex
# Evidence: Verify that the only evidence is `latitude used in a math example` and that no populated, 
# ==============================================================================
def test_case_loc_083():
    """Test scenario for LOC-083: latitude used in a math example"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_latitude_used_in_a_math_example = "MOCK_NON_PII_LITERAL_LATITUDE_USED_IN_A_MATH_EXAMPLE"
    unrelated_system_config = {
        "config_key": "latitude used in a math example",
        "is_pii": False,
        "value": dummy_latitude_used_in_a_math_example
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: LOC-084] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `static store location` app
# Evidence: Verify that the only evidence is `static store location` and that no populated, user-linke
# ==============================================================================
def test_case_loc_084():
    """Test scenario for LOC-084: static store location"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_static_store_location = "MOCK_NON_PII_LITERAL_STATIC_STORE_LOCATION"
    unrelated_system_config = {
        "config_key": "static store location",
        "is_pii": False,
        "value": dummy_static_store_location
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: LOC-085] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `fake GPS fixture` appears 
# Evidence: Verify that the only evidence is `fake GPS fixture` and that no populated, user-linked `wo
# ==============================================================================
def test_case_loc_085():
    """Test scenario for LOC-085: fake GPS fixture"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_fake_GPS_fixture = "MOCK_NON_PII_LITERAL_FAKE_GPS_FIXTURE"
    unrelated_system_config = {
        "config_key": "fake GPS fixture",
        "is_pii": False,
        "value": dummy_fake_GPS_fixture
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: LOC-086] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `aggregate city-level stati
# Evidence: Verify that the only evidence is `aggregate city-level statistic` and that no populated, u
# ==============================================================================
def test_case_loc_086():
    """Test scenario for LOC-086: aggregate city-level statistic"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_aggregate_city_level_statistic = "MOCK_NON_PII_LITERAL_AGGREGATE_CITY_LEVEL_STATISTIC"
    unrelated_system_config = {
        "config_key": "aggregate city-level statistic",
        "is_pii": False,
        "value": dummy_aggregate_city_level_statistic
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: LOC-087] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `permission declared but ge
# Evidence: Verify that the only evidence is `permission declared but geolocation never invoked` and t
# ==============================================================================
def test_case_loc_087():
    """Test scenario for LOC-087: permission declared but geolocation never invoked"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_permission_declared_but_geolocation_never_invoked = "MOCK_NON_PII_LITERAL_PERMISSION_DECLARED_BUT_GEOLOCATION_NEVER_INVOKED"
    unrelated_system_config = {
        "config_key": "permission declared but geolocation never invoked",
        "is_pii": False,
        "value": dummy_permission_declared_but_geolocation_never_invoked
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: LOC-088] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `empty coordinate pair` app
# Evidence: Verify that the only evidence is `empty coordinate pair` and that no populated, user-linke
# ==============================================================================
def test_case_loc_088():
    """Test scenario for LOC-088: empty coordinate pair"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_empty_coordinate_pair = "MOCK_NON_PII_LITERAL_EMPTY_COORDINATE_PAIR"
    unrelated_system_config = {
        "config_key": "empty coordinate pair",
        "is_pii": False,
        "value": dummy_empty_coordinate_pair
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: LOC-089] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `location label with no val
# Evidence: Verify that the only evidence is `location label with no value` and that no populated, use
# ==============================================================================
def test_case_loc_089():
    """Test scenario for LOC-089: location label with no value"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_location_label_with_no_value = "MOCK_NON_PII_LITERAL_LOCATION_LABEL_WITH_NO_VALUE"
    unrelated_system_config = {
        "config_key": "location label with no value",
        "is_pii": False,
        "value": dummy_location_label_with_no_value
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: LOC-090] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `public landmark coordinate
# Evidence: Verify that the only evidence is `public landmark coordinates` and that no populated, user
# ==============================================================================
def test_case_loc_090():
    """Test scenario for LOC-090: public landmark coordinates"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_public_landmark_coordinates = "MOCK_NON_PII_LITERAL_PUBLIC_LANDMARK_COORDINATES"
    unrelated_system_config = {
        "config_key": "public landmark coordinates",
        "is_pii": False,
        "value": dummy_public_landmark_coordinates
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: LOC-091] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `latitude`: lat
# Evidence: Record the exact `latitude` source location, available type/context, missing runtime or li
# ==============================================================================
def test_case_loc_091():
    """Test scenario for LOC-091: latitude"""
    # ACTIVE TEST CASE: Represents identifiable user data
    latitude = "active_sample_value_for_latitude"
    payload = {
        "user_id": "USR_99214_TEST",
        "latitude": latitude,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-092] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `longitude`: GP
# Evidence: Record the exact `longitude` source location, available type/context, missing runtime or l
# ==============================================================================
def test_case_loc_092():
    """Test scenario for LOC-092: longitude"""
    # ACTIVE TEST CASE: Represents identifiable user data
    longitude = "active_sample_value_for_longitude"
    payload = {
        "user_id": "USR_99214_TEST",
        "longitude": longitude,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-093] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `gps_coordinate
# Evidence: Record the exact `gps_coordinates` source location, available type/context, missing runtim
# ==============================================================================
def test_case_loc_093():
    """Test scenario for LOC-093: gps_coordinates"""
    # ACTIVE TEST CASE: Represents identifiable user data
    gps_coordinates = "active_sample_value_for_gps_coordinates"
    payload = {
        "user_id": "USR_99214_TEST",
        "gps_coordinates": gps_coordinates,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-094] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `home_address`:
# Evidence: Record the exact `home_address` source location, available type/context, missing runtime o
# ==============================================================================
def test_case_loc_094():
    """Test scenario for LOC-094: home_address"""
    # ACTIVE TEST CASE: Represents identifiable user data
    home_address = "active_sample_value_for_home_address"
    payload = {
        "user_id": "USR_99214_TEST",
        "home_address": home_address,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-095] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `work_address`:
# Evidence: Record the exact `work_address` source location, available type/context, missing runtime o
# ==============================================================================
def test_case_loc_095():
    """Test scenario for LOC-095: work_address"""
    # ACTIVE TEST CASE: Represents identifiable user data
    work_address = "active_sample_value_for_work_address"
    payload = {
        "user_id": "USR_99214_TEST",
        "work_address": work_address,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-096] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `location_histo
# Evidence: Record the exact `location_history` source location, available type/context, missing runti
# ==============================================================================
def test_case_loc_096():
    """Test scenario for LOC-096: location_history"""
    # ACTIVE TEST CASE: Represents identifiable user data
    location_history = "active_sample_value_for_location_history"
    payload = {
        "user_id": "USR_99214_TEST",
        "location_history": location_history,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-097] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `geohash`: loca
# Evidence: Record the exact `geohash` source location, available type/context, missing runtime or lin
# ==============================================================================
def test_case_loc_097():
    """Test scenario for LOC-097: geohash"""
    # ACTIVE TEST CASE: Represents identifiable user data
    geohash = "active_sample_value_for_geohash"
    payload = {
        "user_id": "USR_99214_TEST",
        "geohash": geohash,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-098] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `current_locati
# Evidence: Record the exact `current_location` source location, available type/context, missing runti
# ==============================================================================
def test_case_loc_098():
    """Test scenario for LOC-098: current_location"""
    # ACTIVE TEST CASE: Represents identifiable user data
    current_location = "active_sample_value_for_current_location"
    payload = {
        "user_id": "USR_99214_TEST",
        "current_location": current_location,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-099] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `geo_location`:
# Evidence: Record the exact `geo_location` source location, available type/context, missing runtime o
# ==============================================================================
def test_case_loc_099():
    """Test scenario for LOC-099: geo_location"""
    # ACTIVE TEST CASE: Represents identifiable user data
    geo_location = "active_sample_value_for_geo_location"
    payload = {
        "user_id": "USR_99214_TEST",
        "geo_location": geo_location,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: LOC-100] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `user_coordinat
# Evidence: Record the exact `user_coordinates` source location, available type/context, missing runti
# ==============================================================================
def test_case_loc_100():
    """Test scenario for LOC-100: user_coordinates"""
    # ACTIVE TEST CASE: Represents identifiable user data
    user_coordinates = "active_sample_value_for_user_coordinates"
    payload = {
        "user_id": "USR_99214_TEST",
        "user_coordinates": user_coordinates,
        "is_active_pii": True
    }
    return payload
