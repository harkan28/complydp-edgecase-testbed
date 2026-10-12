"""
COMPLYDP EDGE-CASE TEST SUITE: DIGITAL IDENTIFIERS (DIG)
Contains all 100 test scenarios (DIG-001 to DIG-100).
Includes Positive PII cases, API flows, Masked cases, and Negative Control Traps.
"""

import re
import json
import hashlib
from typing import Dict, Any, List, Optional

# ==============================================================================
# [TEST_ID: DIG-001] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `ip_address` in the repository schema or source code, includi
# Evidence: Verify the exact `ip_address` declaration, its type/validation/usage, and whether it is li
# ==============================================================================
def test_case_dig_001():
    """Test scenario for DIG-001: ip_address"""
    # ACTIVE TEST CASE: Represents identifiable user data
    ip_address = "active_sample_value_for_ip_address"
    payload = {
        "user_id": "USR_99214_TEST",
        "ip_address": ip_address,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-002] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `device_id` in the repository schema or source code, includin
# Evidence: Verify the exact `device_id` declaration, its type/validation/usage, and whether it is lin
# ==============================================================================
def test_case_dig_002():
    """Test scenario for DIG-002: device_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    device_id = "active_sample_value_for_device_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "device_id": device_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-003] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `advertising_id` in the repository schema or source code, inc
# Evidence: Verify the exact `advertising_id` declaration, its type/validation/usage, and whether it i
# ==============================================================================
def test_case_dig_003():
    """Test scenario for DIG-003: advertising_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    advertising_id = "active_sample_value_for_advertising_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "advertising_id": advertising_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-004] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `cookie_id` in the repository schema or source code, includin
# Evidence: Verify the exact `cookie_id` declaration, its type/validation/usage, and whether it is lin
# ==============================================================================
def test_case_dig_004():
    """Test scenario for DIG-004: cookie_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    cookie_id = "active_sample_value_for_cookie_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "cookie_id": cookie_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-005] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `session_id` in the repository schema or source code, includi
# Evidence: Verify the exact `session_id` declaration, its type/validation/usage, and whether it is li
# ==============================================================================
def test_case_dig_005():
    """Test scenario for DIG-005: session_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    session_id = "active_sample_value_for_session_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "session_id": session_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-006] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `browser_fingerprint` in the repository schema or source code
# Evidence: Verify the exact `browser_fingerprint` declaration, its type/validation/usage, and whether
# ==============================================================================
def test_case_dig_006():
    """Test scenario for DIG-006: browser_fingerprint"""
    # ACTIVE TEST CASE: Represents identifiable user data
    browser_fingerprint = "active_sample_value_for_browser_fingerprint"
    payload = {
        "user_id": "USR_99214_TEST",
        "browser_fingerprint": browser_fingerprint,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-007] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `client_identifier` in the repository schema or source code, 
# Evidence: Verify the exact `client_identifier` declaration, its type/validation/usage, and whether i
# ==============================================================================
def test_case_dig_007():
    """Test scenario for DIG-007: client_identifier"""
    # ACTIVE TEST CASE: Represents identifiable user data
    client_identifier = "active_sample_value_for_client_identifier"
    payload = {
        "user_id": "USR_99214_TEST",
        "client_identifier": client_identifier,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-008] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `user_agent` in the repository schema or source code, includi
# Evidence: Verify the exact `user_agent` declaration, its type/validation/usage, and whether it is li
# ==============================================================================
def test_case_dig_008():
    """Test scenario for DIG-008: user_agent"""
    # ACTIVE TEST CASE: Represents identifiable user data
    user_agent = "active_sample_value_for_user_agent"
    payload = {
        "user_id": "USR_99214_TEST",
        "user_agent": user_agent,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-009] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `analytics_user_id` in the repository schema or source code, 
# Evidence: Verify the exact `analytics_user_id` declaration, its type/validation/usage, and whether i
# ==============================================================================
def test_case_dig_009():
    """Test scenario for DIG-009: analytics_user_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    analytics_user_id = "active_sample_value_for_analytics_user_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "analytics_user_id": analytics_user_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-010] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `persistent_id` in the repository schema or source code, incl
# Evidence: Verify the exact `persistent_id` declaration, its type/validation/usage, and whether it is
# ==============================================================================
def test_case_dig_010():
    """Test scenario for DIG-010: persistent_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    persistent_id = "active_sample_value_for_persistent_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "persistent_id": persistent_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-011] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `ip_address` when IPv4 address in a user session; inspect 
# Evidence: Capture the full JSON/object path for `ip_address`, the parent record or user key, and the
# ==============================================================================
def test_case_dig_011():
    """Test scenario for DIG-011: ip_address"""
    # ACTIVE TEST CASE: Represents identifiable user data
    ip_address = "active_sample_value_for_ip_address"
    payload = {
        "user_id": "USR_99214_TEST",
        "ip_address": ip_address,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-012] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `device_id` when IPv6 address in proxy headers; inspect ne
# Evidence: Capture the full JSON/object path for `device_id`, the parent record or user key, and the 
# ==============================================================================
def test_case_dig_012():
    """Test scenario for DIG-012: device_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    device_id = "active_sample_value_for_device_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "device_id": device_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-013] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `advertising_id` when device ID regenerated after reset; i
# Evidence: Capture the full JSON/object path for `advertising_id`, the parent record or user key, and
# ==============================================================================
def test_case_dig_013():
    """Test scenario for DIG-013: advertising_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    advertising_id = "active_sample_value_for_advertising_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "advertising_id": advertising_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-014] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `cookie_id` when identifier hashed before transmission; in
# Evidence: Capture the full JSON/object path for `cookie_id`, the parent record or user key, and the 
# ==============================================================================
def test_case_dig_014():
    """Test scenario for DIG-014: cookie_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    cookie_id = "active_sample_value_for_cookie_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "cookie_id": cookie_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-015] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `session_id` when cookie scoped across subdomains; inspect
# Evidence: Capture the full JSON/object path for `session_id`, the parent record or user key, and the
# ==============================================================================
def test_case_dig_015():
    """Test scenario for DIG-015: session_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    session_id = "active_sample_value_for_session_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "session_id": session_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-016] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `browser_fingerprint` when fingerprint assembled from devi
# Evidence: Capture the full JSON/object path for `browser_fingerprint`, the parent record or user key
# ==============================================================================
def test_case_dig_016():
    """Test scenario for DIG-016: browser_fingerprint"""
    # ACTIVE TEST CASE: Represents identifiable user data
    browser_fingerprint = "active_sample_value_for_browser_fingerprint"
    payload = {
        "user_id": "USR_99214_TEST",
        "browser_fingerprint": browser_fingerprint,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-017] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `client_identifier` when identifier persisted in browser s
# Evidence: Capture the full JSON/object path for `client_identifier`, the parent record or user key, 
# ==============================================================================
def test_case_dig_017():
    """Test scenario for DIG-017: client_identifier"""
    # ACTIVE TEST CASE: Represents identifiable user data
    client_identifier = "active_sample_value_for_client_identifier"
    payload = {
        "user_id": "USR_99214_TEST",
        "client_identifier": client_identifier,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-018] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `user_agent` when rotating session identifiers; inspect ne
# Evidence: Capture the full JSON/object path for `user_agent`, the parent record or user key, and the
# ==============================================================================
def test_case_dig_018():
    """Test scenario for DIG-018: user_agent"""
    # ACTIVE TEST CASE: Represents identifiable user data
    user_agent = "active_sample_value_for_user_agent"
    payload = {
        "user_id": "USR_99214_TEST",
        "user_agent": user_agent,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-019] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `analytics_user_id` when identifier URL-encoded in a reque
# Evidence: Capture the full JSON/object path for `analytics_user_id`, the parent record or user key, 
# ==============================================================================
def test_case_dig_019():
    """Test scenario for DIG-019: analytics_user_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    analytics_user_id = "active_sample_value_for_analytics_user_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "analytics_user_id": analytics_user_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-020] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `persistent_id` when identifier joined across datasets; in
# Evidence: Capture the full JSON/object path for `persistent_id`, the parent record or user key, and 
# ==============================================================================
def test_case_dig_020():
    """Test scenario for DIG-020: persistent_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    persistent_id = "active_sample_value_for_persistent_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "persistent_id": persistent_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-021] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `ip_address` through an API boundary when IPv4 address in a us
# Evidence: Verify the request/response schema and call site for `ip_address`, direction of flow, endp
# ==============================================================================
def test_case_dig_021():
    """Test scenario for DIG-021: ip_address"""
    # ACTIVE TEST CASE: Represents identifiable user data
    ip_address = "active_sample_value_for_ip_address"
    payload = {
        "user_id": "USR_99214_TEST",
        "ip_address": ip_address,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-022] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `device_id` through an API boundary when IPv6 address in proxy
# Evidence: Verify the request/response schema and call site for `device_id`, direction of flow, endpo
# ==============================================================================
def test_case_dig_022():
    """Test scenario for DIG-022: device_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    device_id = "active_sample_value_for_device_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "device_id": device_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-023] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `advertising_id` through an API boundary when device ID regene
# Evidence: Verify the request/response schema and call site for `advertising_id`, direction of flow, 
# ==============================================================================
def test_case_dig_023():
    """Test scenario for DIG-023: advertising_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    advertising_id = "active_sample_value_for_advertising_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "advertising_id": advertising_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-024] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `cookie_id` through an API boundary when identifier hashed bef
# Evidence: Verify the request/response schema and call site for `cookie_id`, direction of flow, endpo
# ==============================================================================
def test_case_dig_024():
    """Test scenario for DIG-024: cookie_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    cookie_id = "active_sample_value_for_cookie_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "cookie_id": cookie_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-025] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `session_id` through an API boundary when cookie scoped across
# Evidence: Verify the request/response schema and call site for `session_id`, direction of flow, endp
# ==============================================================================
def test_case_dig_025():
    """Test scenario for DIG-025: session_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    session_id = "active_sample_value_for_session_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "session_id": session_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-026] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `browser_fingerprint` through an API boundary when fingerprint
# Evidence: Verify the request/response schema and call site for `browser_fingerprint`, direction of f
# ==============================================================================
def test_case_dig_026():
    """Test scenario for DIG-026: browser_fingerprint"""
    # ACTIVE TEST CASE: Represents identifiable user data
    browser_fingerprint = "active_sample_value_for_browser_fingerprint"
    payload = {
        "user_id": "USR_99214_TEST",
        "browser_fingerprint": browser_fingerprint,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-027] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `client_identifier` through an API boundary when identifier pe
# Evidence: Verify the request/response schema and call site for `client_identifier`, direction of flo
# ==============================================================================
def test_case_dig_027():
    """Test scenario for DIG-027: client_identifier"""
    # ACTIVE TEST CASE: Represents identifiable user data
    client_identifier = "active_sample_value_for_client_identifier"
    payload = {
        "user_id": "USR_99214_TEST",
        "client_identifier": client_identifier,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-028] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `user_agent` through an API boundary when rotating session ide
# Evidence: Verify the request/response schema and call site for `user_agent`, direction of flow, endp
# ==============================================================================
def test_case_dig_028():
    """Test scenario for DIG-028: user_agent"""
    # ACTIVE TEST CASE: Represents identifiable user data
    user_agent = "active_sample_value_for_user_agent"
    payload = {
        "user_id": "USR_99214_TEST",
        "user_agent": user_agent,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-029] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `analytics_user_id` through an API boundary when identifier UR
# Evidence: Verify the request/response schema and call site for `analytics_user_id`, direction of flo
# ==============================================================================
def test_case_dig_029():
    """Test scenario for DIG-029: analytics_user_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    analytics_user_id = "active_sample_value_for_analytics_user_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "analytics_user_id": analytics_user_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-030] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `persistent_id` through an API boundary when identifier joined
# Evidence: Verify the request/response schema and call site for `persistent_id`, direction of flow, e
# ==============================================================================
def test_case_dig_030():
    """Test scenario for DIG-030: persistent_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    persistent_id = "active_sample_value_for_persistent_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "persistent_id": persistent_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-031] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `ip_address` when IPv4 address in a user session; f
# Evidence: Show the source value, transformation or derivation applied to `ip_address`, and resulting
# ==============================================================================
def test_case_dig_031():
    """Test scenario for DIG-031: ip_address"""
    # ACTIVE TEST CASE: Represents identifiable user data
    ip_address = "active_sample_value_for_ip_address"
    payload = {
        "user_id": "USR_99214_TEST",
        "ip_address": ip_address,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-032] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `device_id` when IPv6 address in proxy headers; fol
# Evidence: Show the source value, transformation or derivation applied to `device_id`, and resulting 
# ==============================================================================
def test_case_dig_032():
    """Test scenario for DIG-032: device_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    device_id = "active_sample_value_for_device_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "device_id": device_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-033] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `advertising_id` when device ID regenerated after r
# Evidence: Show the source value, transformation or derivation applied to `advertising_id`, and resul
# ==============================================================================
def test_case_dig_033():
    """Test scenario for DIG-033: advertising_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    advertising_id = "active_sample_value_for_advertising_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "advertising_id": advertising_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-034] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `cookie_id` when identifier hashed before transmiss
# Evidence: Show the source value, transformation or derivation applied to `cookie_id`, and resulting 
# ==============================================================================
def test_case_dig_034():
    """Test scenario for DIG-034: cookie_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    cookie_id = "active_sample_value_for_cookie_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "cookie_id": cookie_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-035] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `session_id` when cookie scoped across subdomains; 
# Evidence: Show the source value, transformation or derivation applied to `session_id`, and resulting
# ==============================================================================
def test_case_dig_035():
    """Test scenario for DIG-035: session_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    session_id = "active_sample_value_for_session_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "session_id": session_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-036] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `browser_fingerprint` when fingerprint assembled fr
# Evidence: Show the source value, transformation or derivation applied to `browser_fingerprint`, and 
# ==============================================================================
def test_case_dig_036():
    """Test scenario for DIG-036: browser_fingerprint"""
    # ACTIVE TEST CASE: Represents identifiable user data
    browser_fingerprint = "active_sample_value_for_browser_fingerprint"
    payload = {
        "user_id": "USR_99214_TEST",
        "browser_fingerprint": browser_fingerprint,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-037] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `client_identifier` when identifier persisted in br
# Evidence: Show the source value, transformation or derivation applied to `client_identifier`, and re
# ==============================================================================
def test_case_dig_037():
    """Test scenario for DIG-037: client_identifier"""
    # ACTIVE TEST CASE: Represents identifiable user data
    client_identifier = "active_sample_value_for_client_identifier"
    payload = {
        "user_id": "USR_99214_TEST",
        "client_identifier": client_identifier,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-038] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `user_agent` when rotating session identifiers; fol
# Evidence: Show the source value, transformation or derivation applied to `user_agent`, and resulting
# ==============================================================================
def test_case_dig_038():
    """Test scenario for DIG-038: user_agent"""
    # ACTIVE TEST CASE: Represents identifiable user data
    user_agent = "active_sample_value_for_user_agent"
    payload = {
        "user_id": "USR_99214_TEST",
        "user_agent": user_agent,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-039] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `analytics_user_id` when identifier URL-encoded in 
# Evidence: Show the source value, transformation or derivation applied to `analytics_user_id`, and re
# ==============================================================================
def test_case_dig_039():
    """Test scenario for DIG-039: analytics_user_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    analytics_user_id = "active_sample_value_for_analytics_user_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "analytics_user_id": analytics_user_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-040] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `persistent_id` when identifier joined across datas
# Evidence: Show the source value, transformation or derivation applied to `persistent_id`, and result
# ==============================================================================
def test_case_dig_040():
    """Test scenario for DIG-040: persistent_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    persistent_id = "active_sample_value_for_persistent_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "persistent_id": persistent_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-041] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `ip_address` when IPv4 address in a
# Evidence: Identify the exact `ip_address` write/read operation and target (table, document, cache, f
# ==============================================================================
def test_case_dig_041():
    """Test scenario for DIG-041: ip_address"""
    # ACTIVE TEST CASE: Represents identifiable user data
    ip_address = "active_sample_value_for_ip_address"
    payload = {
        "user_id": "USR_99214_TEST",
        "ip_address": ip_address,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-042] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `device_id` when IPv6 address in pr
# Evidence: Identify the exact `device_id` write/read operation and target (table, document, cache, fi
# ==============================================================================
def test_case_dig_042():
    """Test scenario for DIG-042: device_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    device_id = "active_sample_value_for_device_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "device_id": device_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-043] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `advertising_id` when device ID reg
# Evidence: Identify the exact `advertising_id` write/read operation and target (table, document, cach
# ==============================================================================
def test_case_dig_043():
    """Test scenario for DIG-043: advertising_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    advertising_id = "active_sample_value_for_advertising_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "advertising_id": advertising_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-044] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `cookie_id` when identifier hashed 
# Evidence: Identify the exact `cookie_id` write/read operation and target (table, document, cache, fi
# ==============================================================================
def test_case_dig_044():
    """Test scenario for DIG-044: cookie_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    cookie_id = "active_sample_value_for_cookie_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "cookie_id": cookie_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-045] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `session_id` when cookie scoped acr
# Evidence: Identify the exact `session_id` write/read operation and target (table, document, cache, f
# ==============================================================================
def test_case_dig_045():
    """Test scenario for DIG-045: session_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    session_id = "active_sample_value_for_session_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "session_id": session_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-046] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `browser_fingerprint` when fingerpr
# Evidence: Identify the exact `browser_fingerprint` write/read operation and target (table, document,
# ==============================================================================
def test_case_dig_046():
    """Test scenario for DIG-046: browser_fingerprint"""
    # ACTIVE TEST CASE: Represents identifiable user data
    browser_fingerprint = "active_sample_value_for_browser_fingerprint"
    payload = {
        "user_id": "USR_99214_TEST",
        "browser_fingerprint": browser_fingerprint,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-047] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `client_identifier` when identifier
# Evidence: Identify the exact `client_identifier` write/read operation and target (table, document, c
# ==============================================================================
def test_case_dig_047():
    """Test scenario for DIG-047: client_identifier"""
    # ACTIVE TEST CASE: Represents identifiable user data
    client_identifier = "active_sample_value_for_client_identifier"
    payload = {
        "user_id": "USR_99214_TEST",
        "client_identifier": client_identifier,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-048] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `user_agent` when rotating session 
# Evidence: Identify the exact `user_agent` write/read operation and target (table, document, cache, f
# ==============================================================================
def test_case_dig_048():
    """Test scenario for DIG-048: user_agent"""
    # ACTIVE TEST CASE: Represents identifiable user data
    user_agent = "active_sample_value_for_user_agent"
    payload = {
        "user_id": "USR_99214_TEST",
        "user_agent": user_agent,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-049] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `analytics_user_id` when identifier
# Evidence: Identify the exact `analytics_user_id` write/read operation and target (table, document, c
# ==============================================================================
def test_case_dig_049():
    """Test scenario for DIG-049: analytics_user_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    analytics_user_id = "active_sample_value_for_analytics_user_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "analytics_user_id": analytics_user_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-050] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `persistent_id` when identifier joi
# Evidence: Identify the exact `persistent_id` write/read operation and target (table, document, cache
# ==============================================================================
def test_case_dig_050():
    """Test scenario for DIG-050: persistent_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    persistent_id = "active_sample_value_for_persistent_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "persistent_id": persistent_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-051] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `ip_address` becomes identifiable or linkable when IPv4 addr
# Evidence: Record `ip_address`'s join key/foreign key, related table or service, and the code path th
# ==============================================================================
def test_case_dig_051():
    """Test scenario for DIG-051: ip_address"""
    # ACTIVE TEST CASE: Represents identifiable user data
    ip_address = "active_sample_value_for_ip_address"
    payload = {
        "user_id": "USR_99214_TEST",
        "ip_address": ip_address,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-052] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `device_id` becomes identifiable or linkable when IPv6 addre
# Evidence: Record `device_id`'s join key/foreign key, related table or service, and the code path tha
# ==============================================================================
def test_case_dig_052():
    """Test scenario for DIG-052: device_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    device_id = "active_sample_value_for_device_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "device_id": device_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-053] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `advertising_id` becomes identifiable or linkable when devic
# Evidence: Record `advertising_id`'s join key/foreign key, related table or service, and the code pat
# ==============================================================================
def test_case_dig_053():
    """Test scenario for DIG-053: advertising_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    advertising_id = "active_sample_value_for_advertising_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "advertising_id": advertising_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-054] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `cookie_id` becomes identifiable or linkable when identifier
# Evidence: Record `cookie_id`'s join key/foreign key, related table or service, and the code path tha
# ==============================================================================
def test_case_dig_054():
    """Test scenario for DIG-054: cookie_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    cookie_id = "active_sample_value_for_cookie_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "cookie_id": cookie_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-055] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `session_id` becomes identifiable or linkable when cookie sc
# Evidence: Record `session_id`'s join key/foreign key, related table or service, and the code path th
# ==============================================================================
def test_case_dig_055():
    """Test scenario for DIG-055: session_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    session_id = "active_sample_value_for_session_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "session_id": session_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-056] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `browser_fingerprint` becomes identifiable or linkable when 
# Evidence: Record `browser_fingerprint`'s join key/foreign key, related table or service, and the cod
# ==============================================================================
def test_case_dig_056():
    """Test scenario for DIG-056: browser_fingerprint"""
    # ACTIVE TEST CASE: Represents identifiable user data
    browser_fingerprint = "active_sample_value_for_browser_fingerprint"
    payload = {
        "user_id": "USR_99214_TEST",
        "browser_fingerprint": browser_fingerprint,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-057] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `client_identifier` becomes identifiable or linkable when id
# Evidence: Record `client_identifier`'s join key/foreign key, related table or service, and the code 
# ==============================================================================
def test_case_dig_057():
    """Test scenario for DIG-057: client_identifier"""
    # ACTIVE TEST CASE: Represents identifiable user data
    client_identifier = "active_sample_value_for_client_identifier"
    payload = {
        "user_id": "USR_99214_TEST",
        "client_identifier": client_identifier,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-058] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `user_agent` becomes identifiable or linkable when rotating 
# Evidence: Record `user_agent`'s join key/foreign key, related table or service, and the code path th
# ==============================================================================
def test_case_dig_058():
    """Test scenario for DIG-058: user_agent"""
    # ACTIVE TEST CASE: Represents identifiable user data
    user_agent = "active_sample_value_for_user_agent"
    payload = {
        "user_id": "USR_99214_TEST",
        "user_agent": user_agent,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-059] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `analytics_user_id` becomes identifiable or linkable when id
# Evidence: Record `analytics_user_id`'s join key/foreign key, related table or service, and the code 
# ==============================================================================
def test_case_dig_059():
    """Test scenario for DIG-059: analytics_user_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    analytics_user_id = "active_sample_value_for_analytics_user_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "analytics_user_id": analytics_user_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-060] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `persistent_id` becomes identifiable or linkable when identi
# Evidence: Record `persistent_id`'s join key/foreign key, related table or service, and the code path
# ==============================================================================
def test_case_dig_060():
    """Test scenario for DIG-060: persistent_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    persistent_id = "active_sample_value_for_persistent_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "persistent_id": persistent_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-061] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `ip_address` to a third-party boundary when IPv4 address in a us
# Evidence: Verify the payload field `ip_address`, outbound call site, destination/vendor, and whether
# ==============================================================================
def test_case_dig_061():
    """Test scenario for DIG-061: ip_address"""
    # ACTIVE TEST CASE: Represents identifiable user data
    ip_address = "active_sample_value_for_ip_address"
    payload = {
        "user_id": "USR_99214_TEST",
        "ip_address": ip_address,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-062] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `device_id` to a third-party boundary when IPv6 address in proxy
# Evidence: Verify the payload field `device_id`, outbound call site, destination/vendor, and whether 
# ==============================================================================
def test_case_dig_062():
    """Test scenario for DIG-062: device_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    device_id = "active_sample_value_for_device_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "device_id": device_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-063] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `advertising_id` to a third-party boundary when device ID regene
# Evidence: Verify the payload field `advertising_id`, outbound call site, destination/vendor, and whe
# ==============================================================================
def test_case_dig_063():
    """Test scenario for DIG-063: advertising_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    advertising_id = "active_sample_value_for_advertising_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "advertising_id": advertising_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-064] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `cookie_id` to a third-party boundary when identifier hashed bef
# Evidence: Verify the payload field `cookie_id`, outbound call site, destination/vendor, and whether 
# ==============================================================================
def test_case_dig_064():
    """Test scenario for DIG-064: cookie_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    cookie_id = "active_sample_value_for_cookie_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "cookie_id": cookie_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-065] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `session_id` to a third-party boundary when cookie scoped across
# Evidence: Verify the payload field `session_id`, outbound call site, destination/vendor, and whether
# ==============================================================================
def test_case_dig_065():
    """Test scenario for DIG-065: session_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    session_id = "active_sample_value_for_session_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "session_id": session_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-066] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `browser_fingerprint` to a third-party boundary when fingerprint
# Evidence: Verify the payload field `browser_fingerprint`, outbound call site, destination/vendor, an
# ==============================================================================
def test_case_dig_066():
    """Test scenario for DIG-066: browser_fingerprint"""
    # ACTIVE TEST CASE: Represents identifiable user data
    browser_fingerprint = "active_sample_value_for_browser_fingerprint"
    payload = {
        "user_id": "USR_99214_TEST",
        "browser_fingerprint": browser_fingerprint,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-067] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `client_identifier` to a third-party boundary when identifier pe
# Evidence: Verify the payload field `client_identifier`, outbound call site, destination/vendor, and 
# ==============================================================================
def test_case_dig_067():
    """Test scenario for DIG-067: client_identifier"""
    # ACTIVE TEST CASE: Represents identifiable user data
    client_identifier = "active_sample_value_for_client_identifier"
    payload = {
        "user_id": "USR_99214_TEST",
        "client_identifier": client_identifier,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-068] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `user_agent` to a third-party boundary when rotating session ide
# Evidence: Verify the payload field `user_agent`, outbound call site, destination/vendor, and whether
# ==============================================================================
def test_case_dig_068():
    """Test scenario for DIG-068: user_agent"""
    # ACTIVE TEST CASE: Represents identifiable user data
    user_agent = "active_sample_value_for_user_agent"
    payload = {
        "user_id": "USR_99214_TEST",
        "user_agent": user_agent,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-069] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `analytics_user_id` to a third-party boundary when identifier UR
# Evidence: Verify the payload field `analytics_user_id`, outbound call site, destination/vendor, and 
# ==============================================================================
def test_case_dig_069():
    """Test scenario for DIG-069: analytics_user_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    analytics_user_id = "active_sample_value_for_analytics_user_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "analytics_user_id": analytics_user_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-070] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `persistent_id` to a third-party boundary when identifier joined
# Evidence: Verify the payload field `persistent_id`, outbound call site, destination/vendor, and whet
# ==============================================================================
def test_case_dig_070():
    """Test scenario for DIG-070: persistent_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    persistent_id = "active_sample_value_for_persistent_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "persistent_id": persistent_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-071] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `ip_address` when IPv4 address in a user se
# Evidence: Record the observed representation and protection/transform function for `ip_address`; dis
# ==============================================================================
def test_case_dig_071():
    """Test scenario for DIG-071: ip_address"""
    # ACTIVE TEST CASE: Represents identifiable user data
    ip_address = "active_sample_value_for_ip_address"
    payload = {
        "user_id": "USR_99214_TEST",
        "ip_address": ip_address,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-072] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `device_id` when IPv6 address in proxy head
# Evidence: Record the observed representation and protection/transform function for `device_id`; dist
# ==============================================================================
def test_case_dig_072():
    """Test scenario for DIG-072: device_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    device_id = "active_sample_value_for_device_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "device_id": device_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-073] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `advertising_id` when device ID regenerated
# Evidence: Record the observed representation and protection/transform function for `advertising_id`;
# ==============================================================================
def test_case_dig_073():
    """Test scenario for DIG-073: advertising_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    advertising_id = "active_sample_value_for_advertising_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "advertising_id": advertising_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-074] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `cookie_id` when identifier hashed before t
# Evidence: Record the observed representation and protection/transform function for `cookie_id`; dist
# ==============================================================================
def test_case_dig_074():
    """Test scenario for DIG-074: cookie_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    cookie_id = "active_sample_value_for_cookie_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "cookie_id": cookie_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-075] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `session_id` when cookie scoped across subd
# Evidence: Record the observed representation and protection/transform function for `session_id`; dis
# ==============================================================================
def test_case_dig_075():
    """Test scenario for DIG-075: session_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    session_id = "active_sample_value_for_session_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "session_id": session_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-076] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `browser_fingerprint` when fingerprint asse
# Evidence: Record the observed representation and protection/transform function for `browser_fingerpr
# ==============================================================================
def test_case_dig_076():
    """Test scenario for DIG-076: browser_fingerprint"""
    # ACTIVE TEST CASE: Represents identifiable user data
    browser_fingerprint = "active_sample_value_for_browser_fingerprint"
    payload = {
        "user_id": "USR_99214_TEST",
        "browser_fingerprint": browser_fingerprint,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-077] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `client_identifier` when identifier persist
# Evidence: Record the observed representation and protection/transform function for `client_identifie
# ==============================================================================
def test_case_dig_077():
    """Test scenario for DIG-077: client_identifier"""
    # ACTIVE TEST CASE: Represents identifiable user data
    client_identifier = "active_sample_value_for_client_identifier"
    payload = {
        "user_id": "USR_99214_TEST",
        "client_identifier": client_identifier,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-078] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `user_agent` when rotating session identifi
# Evidence: Record the observed representation and protection/transform function for `user_agent`; dis
# ==============================================================================
def test_case_dig_078():
    """Test scenario for DIG-078: user_agent"""
    # ACTIVE TEST CASE: Represents identifiable user data
    user_agent = "active_sample_value_for_user_agent"
    payload = {
        "user_id": "USR_99214_TEST",
        "user_agent": user_agent,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-079] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `analytics_user_id` when identifier URL-enc
# Evidence: Record the observed representation and protection/transform function for `analytics_user_i
# ==============================================================================
def test_case_dig_079():
    """Test scenario for DIG-079: analytics_user_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    analytics_user_id = "active_sample_value_for_analytics_user_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "analytics_user_id": analytics_user_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-080] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `persistent_id` when identifier joined acro
# Evidence: Record the observed representation and protection/transform function for `persistent_id`; 
# ==============================================================================
def test_case_dig_080():
    """Test scenario for DIG-080: persistent_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    persistent_id = "active_sample_value_for_persistent_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "persistent_id": persistent_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-081] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `UUID used for build artifa
# Evidence: Verify that the only evidence is `UUID used for build artifacts` and that no populated, us
# ==============================================================================
def test_case_dig_081():
    """Test scenario for DIG-081: UUID used for build artifacts"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_UUID_used_for_build_artifacts = "MOCK_NON_PII_LITERAL_UUID_USED_FOR_BUILD_ARTIFACTS"
    unrelated_system_config = {
        "config_key": "UUID used for build artifacts",
        "is_pii": False,
        "value": dummy_UUID_used_for_build_artifacts
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: DIG-082] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `localhost IP in documentat
# Evidence: Verify that the only evidence is `localhost IP in documentation` and that no populated, us
# ==============================================================================
def test_case_dig_082():
    """Test scenario for DIG-082: localhost IP in documentation"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_localhost_IP_in_documentation = "MOCK_NON_PII_LITERAL_LOCALHOST_IP_IN_DOCUMENTATION"
    unrelated_system_config = {
        "config_key": "localhost IP in documentation",
        "is_pii": False,
        "value": dummy_localhost_IP_in_documentation
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: DIG-083] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `sample user-agent string` 
# Evidence: Verify that the only evidence is `sample user-agent string` and that no populated, user-li
# ==============================================================================
def test_case_dig_083():
    """Test scenario for DIG-083: sample user-agent string"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_sample_user_agent_string = "MOCK_NON_PII_LITERAL_SAMPLE_USER_AGENT_STRING"
    unrelated_system_config = {
        "config_key": "sample user-agent string",
        "is_pii": False,
        "value": dummy_sample_user_agent_string
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: DIG-084] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `random request correlation
# Evidence: Verify that the only evidence is `random request correlation ID` and that no populated, us
# ==============================================================================
def test_case_dig_084():
    """Test scenario for DIG-084: random request correlation ID"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_random_request_correlation_ID = "MOCK_NON_PII_LITERAL_RANDOM_REQUEST_CORRELATION_ID"
    unrelated_system_config = {
        "config_key": "random request correlation ID",
        "is_pii": False,
        "value": dummy_random_request_correlation_ID
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: DIG-085] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `cookie name without a valu
# Evidence: Verify that the only evidence is `cookie name without a value` and that no populated, user
# ==============================================================================
def test_case_dig_085():
    """Test scenario for DIG-085: cookie name without a value"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_cookie_name_without_a_value = "MOCK_NON_PII_LITERAL_COOKIE_NAME_WITHOUT_A_VALUE"
    unrelated_system_config = {
        "config_key": "cookie name without a value",
        "is_pii": False,
        "value": dummy_cookie_name_without_a_value
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: DIG-086] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `aggregate traffic count` a
# Evidence: Verify that the only evidence is `aggregate traffic count` and that no populated, user-lin
# ==============================================================================
def test_case_dig_086():
    """Test scenario for DIG-086: aggregate traffic count"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_aggregate_traffic_count = "MOCK_NON_PII_LITERAL_AGGREGATE_TRAFFIC_COUNT"
    unrelated_system_config = {
        "config_key": "aggregate traffic count",
        "is_pii": False,
        "value": dummy_aggregate_traffic_count
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: DIG-087] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `static server IP not user-
# Evidence: Verify that the only evidence is `static server IP not user-linked` and that no populated,
# ==============================================================================
def test_case_dig_087():
    """Test scenario for DIG-087: static server IP not user-linked"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_static_server_IP_not_user_linked = "MOCK_NON_PII_LITERAL_STATIC_SERVER_IP_NOT_USER_LINKED"
    unrelated_system_config = {
        "config_key": "static server IP not user-linked",
        "is_pii": False,
        "value": dummy_static_server_IP_not_user_linked
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: DIG-088] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `fake device ID fixture` ap
# Evidence: Verify that the only evidence is `fake device ID fixture` and that no populated, user-link
# ==============================================================================
def test_case_dig_088():
    """Test scenario for DIG-088: fake device ID fixture"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_fake_device_ID_fixture = "MOCK_NON_PII_LITERAL_FAKE_DEVICE_ID_FIXTURE"
    unrelated_system_config = {
        "config_key": "fake device ID fixture",
        "is_pii": False,
        "value": dummy_fake_device_ID_fixture
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: DIG-089] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `session-age variable` appe
# Evidence: Verify that the only evidence is `session-age variable` and that no populated, user-linked
# ==============================================================================
def test_case_dig_089():
    """Test scenario for DIG-089: session-age variable"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_session_age_variable = "MOCK_NON_PII_LITERAL_SESSION_AGE_VARIABLE"
    unrelated_system_config = {
        "config_key": "session-age variable",
        "is_pii": False,
        "value": dummy_session_age_variable
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: DIG-090] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `hashed ID with no evidence
# Evidence: Verify that the only evidence is `hashed ID with no evidence of user linkage` and that no 
# ==============================================================================
def test_case_dig_090():
    """Test scenario for DIG-090: hashed ID with no evidence of user linkage"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_hashed_ID_with_no_evidence_of_user_linkage = "MOCK_NON_PII_LITERAL_HASHED_ID_WITH_NO_EVIDENCE_OF_USER_LINKAGE"
    unrelated_system_config = {
        "config_key": "hashed ID with no evidence of user linkage",
        "is_pii": False,
        "value": dummy_hashed_ID_with_no_evidence_of_user_linkage
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: DIG-091] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `ip_address`: I
# Evidence: Record the exact `ip_address` source location, available type/context, missing runtime or 
# ==============================================================================
def test_case_dig_091():
    """Test scenario for DIG-091: ip_address"""
    # ACTIVE TEST CASE: Represents identifiable user data
    ip_address = "active_sample_value_for_ip_address"
    payload = {
        "user_id": "USR_99214_TEST",
        "ip_address": ip_address,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-092] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `device_id`: IP
# Evidence: Record the exact `device_id` source location, available type/context, missing runtime or l
# ==============================================================================
def test_case_dig_092():
    """Test scenario for DIG-092: device_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    device_id = "active_sample_value_for_device_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "device_id": device_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-093] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `advertising_id
# Evidence: Record the exact `advertising_id` source location, available type/context, missing runtime
# ==============================================================================
def test_case_dig_093():
    """Test scenario for DIG-093: advertising_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    advertising_id = "active_sample_value_for_advertising_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "advertising_id": advertising_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-094] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `cookie_id`: id
# Evidence: Record the exact `cookie_id` source location, available type/context, missing runtime or l
# ==============================================================================
def test_case_dig_094():
    """Test scenario for DIG-094: cookie_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    cookie_id = "active_sample_value_for_cookie_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "cookie_id": cookie_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-095] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `session_id`: c
# Evidence: Record the exact `session_id` source location, available type/context, missing runtime or 
# ==============================================================================
def test_case_dig_095():
    """Test scenario for DIG-095: session_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    session_id = "active_sample_value_for_session_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "session_id": session_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-096] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `browser_finger
# Evidence: Record the exact `browser_fingerprint` source location, available type/context, missing ru
# ==============================================================================
def test_case_dig_096():
    """Test scenario for DIG-096: browser_fingerprint"""
    # ACTIVE TEST CASE: Represents identifiable user data
    browser_fingerprint = "active_sample_value_for_browser_fingerprint"
    payload = {
        "user_id": "USR_99214_TEST",
        "browser_fingerprint": browser_fingerprint,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-097] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `client_identif
# Evidence: Record the exact `client_identifier` source location, available type/context, missing runt
# ==============================================================================
def test_case_dig_097():
    """Test scenario for DIG-097: client_identifier"""
    # ACTIVE TEST CASE: Represents identifiable user data
    client_identifier = "active_sample_value_for_client_identifier"
    payload = {
        "user_id": "USR_99214_TEST",
        "client_identifier": client_identifier,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-098] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `user_agent`: r
# Evidence: Record the exact `user_agent` source location, available type/context, missing runtime or 
# ==============================================================================
def test_case_dig_098():
    """Test scenario for DIG-098: user_agent"""
    # ACTIVE TEST CASE: Represents identifiable user data
    user_agent = "active_sample_value_for_user_agent"
    payload = {
        "user_id": "USR_99214_TEST",
        "user_agent": user_agent,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-099] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `analytics_user
# Evidence: Record the exact `analytics_user_id` source location, available type/context, missing runt
# ==============================================================================
def test_case_dig_099():
    """Test scenario for DIG-099: analytics_user_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    analytics_user_id = "active_sample_value_for_analytics_user_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "analytics_user_id": analytics_user_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: DIG-100] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `persistent_id`
# Evidence: Record the exact `persistent_id` source location, available type/context, missing runtime 
# ==============================================================================
def test_case_dig_100():
    """Test scenario for DIG-100: persistent_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    persistent_id = "active_sample_value_for_persistent_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "persistent_id": persistent_id,
        "is_active_pii": True
    }
    return payload
