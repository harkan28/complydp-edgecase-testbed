"""
COMPLYDP EDGE-CASE TEST SUITE: COMMUNICATIONS INFORMATION (COM)
Contains all 100 test scenarios (COM-001 to COM-100).
Includes Positive PII cases, API flows, Masked cases, and Negative Control Traps.
"""

import re
import json
import hashlib
from typing import Dict, Any, List, Optional

# ==============================================================================
# [TEST_ID: COM-001] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `sms_body` in the repository schema or source code, including
# Evidence: Verify the exact `sms_body` declaration, its type/validation/usage, and whether it is link
# ==============================================================================
def test_case_com_001():
    """Test scenario for COM-001: sms_body"""
    # ACTIVE TEST CASE: Represents identifiable user data
    sms_body = "active_sample_value_for_sms_body"
    payload = {
        "user_id": "USR_99214_TEST",
        "sms_body": sms_body,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-002] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `message_content` in the repository schema or source code, in
# Evidence: Verify the exact `message_content` declaration, its type/validation/usage, and whether it 
# ==============================================================================
def test_case_com_002():
    """Test scenario for COM-002: message_content"""
    # ACTIVE TEST CASE: Represents identifiable user data
    message_content = "active_sample_value_for_message_content"
    payload = {
        "user_id": "USR_99214_TEST",
        "message_content": message_content,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-003] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `call_log` in the repository schema or source code, including
# Evidence: Verify the exact `call_log` declaration, its type/validation/usage, and whether it is link
# ==============================================================================
def test_case_com_003():
    """Test scenario for COM-003: call_log"""
    # ACTIVE TEST CASE: Represents identifiable user data
    call_log = "active_sample_value_for_call_log"
    payload = {
        "user_id": "USR_99214_TEST",
        "call_log": call_log,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-004] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `browsing_history` in the repository schema or source code, i
# Evidence: Verify the exact `browsing_history` declaration, its type/validation/usage, and whether it
# ==============================================================================
def test_case_com_004():
    """Test scenario for COM-004: browsing_history"""
    # ACTIVE TEST CASE: Represents identifiable user data
    browsing_history = "active_sample_value_for_browsing_history"
    payload = {
        "user_id": "USR_99214_TEST",
        "browsing_history": browsing_history,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-005] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `clickstream` in the repository schema or source code, includ
# Evidence: Verify the exact `clickstream` declaration, its type/validation/usage, and whether it is l
# ==============================================================================
def test_case_com_005():
    """Test scenario for COM-005: clickstream"""
    # ACTIVE TEST CASE: Represents identifiable user data
    clickstream = "active_sample_value_for_clickstream"
    payload = {
        "user_id": "USR_99214_TEST",
        "clickstream": clickstream,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-006] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `activity_event` in the repository schema or source code, inc
# Evidence: Verify the exact `activity_event` declaration, its type/validation/usage, and whether it i
# ==============================================================================
def test_case_com_006():
    """Test scenario for COM-006: activity_event"""
    # ACTIVE TEST CASE: Represents identifiable user data
    activity_event = "active_sample_value_for_activity_event"
    payload = {
        "user_id": "USR_99214_TEST",
        "activity_event": activity_event,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-007] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `sender_id` in the repository schema or source code, includin
# Evidence: Verify the exact `sender_id` declaration, its type/validation/usage, and whether it is lin
# ==============================================================================
def test_case_com_007():
    """Test scenario for COM-007: sender_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    sender_id = "active_sample_value_for_sender_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "sender_id": sender_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-008] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `recipient_id` in the repository schema or source code, inclu
# Evidence: Verify the exact `recipient_id` declaration, its type/validation/usage, and whether it is 
# ==============================================================================
def test_case_com_008():
    """Test scenario for COM-008: recipient_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    recipient_id = "active_sample_value_for_recipient_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "recipient_id": recipient_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-009] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `conversation_history` in the repository schema or source cod
# Evidence: Verify the exact `conversation_history` declaration, its type/validation/usage, and whethe
# ==============================================================================
def test_case_com_009():
    """Test scenario for COM-009: conversation_history"""
    # ACTIVE TEST CASE: Represents identifiable user data
    conversation_history = "active_sample_value_for_conversation_history"
    payload = {
        "user_id": "USR_99214_TEST",
        "conversation_history": conversation_history,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-010] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `behaviour_profile` in the repository schema or source code, 
# Evidence: Verify the exact `behaviour_profile` declaration, its type/validation/usage, and whether i
# ==============================================================================
def test_case_com_010():
    """Test scenario for COM-010: behaviour_profile"""
    # ACTIVE TEST CASE: Represents identifiable user data
    behaviour_profile = "active_sample_value_for_behaviour_profile"
    payload = {
        "user_id": "USR_99214_TEST",
        "behaviour_profile": behaviour_profile,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-011] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `sms_body` when SMS parsed but not persisted; inspect nest
# Evidence: Capture the full JSON/object path for `sms_body`, the parent record or user key, and the c
# ==============================================================================
def test_case_com_011():
    """Test scenario for COM-011: sms_body"""
    # ACTIVE TEST CASE: Represents identifiable user data
    sms_body = "active_sample_value_for_sms_body"
    payload = {
        "user_id": "USR_99214_TEST",
        "sms_body": sms_body,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-012] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `message_content` when message body redacted after process
# Evidence: Capture the full JSON/object path for `message_content`, the parent record or user key, an
# ==============================================================================
def test_case_com_012():
    """Test scenario for COM-012: message_content"""
    # ACTIVE TEST CASE: Represents identifiable user data
    message_content = "active_sample_value_for_message_content"
    payload = {
        "user_id": "USR_99214_TEST",
        "message_content": message_content,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-013] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `call_log` when call log stored as timestamped events; ins
# Evidence: Capture the full JSON/object path for `call_log`, the parent record or user key, and the c
# ==============================================================================
def test_case_com_013():
    """Test scenario for COM-013: call_log"""
    # ACTIVE TEST CASE: Represents identifiable user data
    call_log = "active_sample_value_for_call_log"
    payload = {
        "user_id": "USR_99214_TEST",
        "call_log": call_log,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-014] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `browsing_history` when clickstream distributed across eve
# Evidence: Capture the full JSON/object path for `browsing_history`, the parent record or user key, a
# ==============================================================================
def test_case_com_014():
    """Test scenario for COM-014: browsing_history"""
    # ACTIVE TEST CASE: Represents identifiable user data
    browsing_history = "active_sample_value_for_browsing_history"
    payload = {
        "user_id": "USR_99214_TEST",
        "browsing_history": browsing_history,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-015] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `clickstream` when communications encrypted end-to-end; in
# Evidence: Capture the full JSON/object path for `clickstream`, the parent record or user key, and th
# ==============================================================================
def test_case_com_015():
    """Test scenario for COM-015: clickstream"""
    # ACTIVE TEST CASE: Represents identifiable user data
    clickstream = "active_sample_value_for_clickstream"
    payload = {
        "user_id": "USR_99214_TEST",
        "clickstream": clickstream,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-016] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `activity_event` when event payload sent to analytics; ins
# Evidence: Capture the full JSON/object path for `activity_event`, the parent record or user key, and
# ==============================================================================
def test_case_com_016():
    """Test scenario for COM-016: activity_event"""
    # ACTIVE TEST CASE: Represents identifiable user data
    activity_event = "active_sample_value_for_activity_event"
    payload = {
        "user_id": "USR_99214_TEST",
        "activity_event": activity_event,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-017] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `sender_id` when message content appears in exception trac
# Evidence: Capture the full JSON/object path for `sender_id`, the parent record or user key, and the 
# ==============================================================================
def test_case_com_017():
    """Test scenario for COM-017: sender_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    sender_id = "active_sample_value_for_sender_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "sender_id": sender_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-018] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `recipient_id` when behaviour inferred from repeated actio
# Evidence: Capture the full JSON/object path for `recipient_id`, the parent record or user key, and t
# ==============================================================================
def test_case_com_018():
    """Test scenario for COM-018: recipient_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    recipient_id = "active_sample_value_for_recipient_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "recipient_id": recipient_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-019] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `conversation_history` when communications stored in objec
# Evidence: Capture the full JSON/object path for `conversation_history`, the parent record or user ke
# ==============================================================================
def test_case_com_019():
    """Test scenario for COM-019: conversation_history"""
    # ACTIVE TEST CASE: Represents identifiable user data
    conversation_history = "active_sample_value_for_conversation_history"
    payload = {
        "user_id": "USR_99214_TEST",
        "conversation_history": conversation_history,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-020] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `behaviour_profile` when sender and recipient resolved thr
# Evidence: Capture the full JSON/object path for `behaviour_profile`, the parent record or user key, 
# ==============================================================================
def test_case_com_020():
    """Test scenario for COM-020: behaviour_profile"""
    # ACTIVE TEST CASE: Represents identifiable user data
    behaviour_profile = "active_sample_value_for_behaviour_profile"
    payload = {
        "user_id": "USR_99214_TEST",
        "behaviour_profile": behaviour_profile,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-021] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `sms_body` through an API boundary when SMS parsed but not per
# Evidence: Verify the request/response schema and call site for `sms_body`, direction of flow, endpoi
# ==============================================================================
def test_case_com_021():
    """Test scenario for COM-021: sms_body"""
    # ACTIVE TEST CASE: Represents identifiable user data
    sms_body = "active_sample_value_for_sms_body"
    payload = {
        "user_id": "USR_99214_TEST",
        "sms_body": sms_body,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-022] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `message_content` through an API boundary when message body re
# Evidence: Verify the request/response schema and call site for `message_content`, direction of flow,
# ==============================================================================
def test_case_com_022():
    """Test scenario for COM-022: message_content"""
    # ACTIVE TEST CASE: Represents identifiable user data
    message_content = "active_sample_value_for_message_content"
    payload = {
        "user_id": "USR_99214_TEST",
        "message_content": message_content,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-023] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `call_log` through an API boundary when call log stored as tim
# Evidence: Verify the request/response schema and call site for `call_log`, direction of flow, endpoi
# ==============================================================================
def test_case_com_023():
    """Test scenario for COM-023: call_log"""
    # ACTIVE TEST CASE: Represents identifiable user data
    call_log = "active_sample_value_for_call_log"
    payload = {
        "user_id": "USR_99214_TEST",
        "call_log": call_log,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-024] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `browsing_history` through an API boundary when clickstream di
# Evidence: Verify the request/response schema and call site for `browsing_history`, direction of flow
# ==============================================================================
def test_case_com_024():
    """Test scenario for COM-024: browsing_history"""
    # ACTIVE TEST CASE: Represents identifiable user data
    browsing_history = "active_sample_value_for_browsing_history"
    payload = {
        "user_id": "USR_99214_TEST",
        "browsing_history": browsing_history,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-025] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `clickstream` through an API boundary when communications encr
# Evidence: Verify the request/response schema and call site for `clickstream`, direction of flow, end
# ==============================================================================
def test_case_com_025():
    """Test scenario for COM-025: clickstream"""
    # ACTIVE TEST CASE: Represents identifiable user data
    clickstream = "active_sample_value_for_clickstream"
    payload = {
        "user_id": "USR_99214_TEST",
        "clickstream": clickstream,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-026] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `activity_event` through an API boundary when event payload se
# Evidence: Verify the request/response schema and call site for `activity_event`, direction of flow, 
# ==============================================================================
def test_case_com_026():
    """Test scenario for COM-026: activity_event"""
    # ACTIVE TEST CASE: Represents identifiable user data
    activity_event = "active_sample_value_for_activity_event"
    payload = {
        "user_id": "USR_99214_TEST",
        "activity_event": activity_event,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-027] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `sender_id` through an API boundary when message content appea
# Evidence: Verify the request/response schema and call site for `sender_id`, direction of flow, endpo
# ==============================================================================
def test_case_com_027():
    """Test scenario for COM-027: sender_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    sender_id = "active_sample_value_for_sender_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "sender_id": sender_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-028] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `recipient_id` through an API boundary when behaviour inferred
# Evidence: Verify the request/response schema and call site for `recipient_id`, direction of flow, en
# ==============================================================================
def test_case_com_028():
    """Test scenario for COM-028: recipient_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    recipient_id = "active_sample_value_for_recipient_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "recipient_id": recipient_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-029] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `conversation_history` through an API boundary when communicat
# Evidence: Verify the request/response schema and call site for `conversation_history`, direction of 
# ==============================================================================
def test_case_com_029():
    """Test scenario for COM-029: conversation_history"""
    # ACTIVE TEST CASE: Represents identifiable user data
    conversation_history = "active_sample_value_for_conversation_history"
    payload = {
        "user_id": "USR_99214_TEST",
        "conversation_history": conversation_history,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-030] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `behaviour_profile` through an API boundary when sender and re
# Evidence: Verify the request/response schema and call site for `behaviour_profile`, direction of flo
# ==============================================================================
def test_case_com_030():
    """Test scenario for COM-030: behaviour_profile"""
    # ACTIVE TEST CASE: Represents identifiable user data
    behaviour_profile = "active_sample_value_for_behaviour_profile"
    payload = {
        "user_id": "USR_99214_TEST",
        "behaviour_profile": behaviour_profile,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-031] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `sms_body` when SMS parsed but not persisted; follo
# Evidence: Show the source value, transformation or derivation applied to `sms_body`, and resulting s
# ==============================================================================
def test_case_com_031():
    """Test scenario for COM-031: sms_body"""
    # ACTIVE TEST CASE: Represents identifiable user data
    sms_body = "active_sample_value_for_sms_body"
    payload = {
        "user_id": "USR_99214_TEST",
        "sms_body": sms_body,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-032] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `message_content` when message body redacted after 
# Evidence: Show the source value, transformation or derivation applied to `message_content`, and resu
# ==============================================================================
def test_case_com_032():
    """Test scenario for COM-032: message_content"""
    # ACTIVE TEST CASE: Represents identifiable user data
    message_content = "active_sample_value_for_message_content"
    payload = {
        "user_id": "USR_99214_TEST",
        "message_content": message_content,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-033] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `call_log` when call log stored as timestamped even
# Evidence: Show the source value, transformation or derivation applied to `call_log`, and resulting s
# ==============================================================================
def test_case_com_033():
    """Test scenario for COM-033: call_log"""
    # ACTIVE TEST CASE: Represents identifiable user data
    call_log = "active_sample_value_for_call_log"
    payload = {
        "user_id": "USR_99214_TEST",
        "call_log": call_log,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-034] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `browsing_history` when clickstream distributed acr
# Evidence: Show the source value, transformation or derivation applied to `browsing_history`, and res
# ==============================================================================
def test_case_com_034():
    """Test scenario for COM-034: browsing_history"""
    # ACTIVE TEST CASE: Represents identifiable user data
    browsing_history = "active_sample_value_for_browsing_history"
    payload = {
        "user_id": "USR_99214_TEST",
        "browsing_history": browsing_history,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-035] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `clickstream` when communications encrypted end-to-
# Evidence: Show the source value, transformation or derivation applied to `clickstream`, and resultin
# ==============================================================================
def test_case_com_035():
    """Test scenario for COM-035: clickstream"""
    # ACTIVE TEST CASE: Represents identifiable user data
    clickstream = "active_sample_value_for_clickstream"
    payload = {
        "user_id": "USR_99214_TEST",
        "clickstream": clickstream,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-036] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `activity_event` when event payload sent to analyti
# Evidence: Show the source value, transformation or derivation applied to `activity_event`, and resul
# ==============================================================================
def test_case_com_036():
    """Test scenario for COM-036: activity_event"""
    # ACTIVE TEST CASE: Represents identifiable user data
    activity_event = "active_sample_value_for_activity_event"
    payload = {
        "user_id": "USR_99214_TEST",
        "activity_event": activity_event,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-037] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `sender_id` when message content appears in excepti
# Evidence: Show the source value, transformation or derivation applied to `sender_id`, and resulting 
# ==============================================================================
def test_case_com_037():
    """Test scenario for COM-037: sender_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    sender_id = "active_sample_value_for_sender_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "sender_id": sender_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-038] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `recipient_id` when behaviour inferred from repeate
# Evidence: Show the source value, transformation or derivation applied to `recipient_id`, and resulti
# ==============================================================================
def test_case_com_038():
    """Test scenario for COM-038: recipient_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    recipient_id = "active_sample_value_for_recipient_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "recipient_id": recipient_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-039] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `conversation_history` when communications stored i
# Evidence: Show the source value, transformation or derivation applied to `conversation_history`, and
# ==============================================================================
def test_case_com_039():
    """Test scenario for COM-039: conversation_history"""
    # ACTIVE TEST CASE: Represents identifiable user data
    conversation_history = "active_sample_value_for_conversation_history"
    payload = {
        "user_id": "USR_99214_TEST",
        "conversation_history": conversation_history,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-040] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `behaviour_profile` when sender and recipient resol
# Evidence: Show the source value, transformation or derivation applied to `behaviour_profile`, and re
# ==============================================================================
def test_case_com_040():
    """Test scenario for COM-040: behaviour_profile"""
    # ACTIVE TEST CASE: Represents identifiable user data
    behaviour_profile = "active_sample_value_for_behaviour_profile"
    payload = {
        "user_id": "USR_99214_TEST",
        "behaviour_profile": behaviour_profile,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-041] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `sms_body` when SMS parsed but not 
# Evidence: Identify the exact `sms_body` write/read operation and target (table, document, cache, fil
# ==============================================================================
def test_case_com_041():
    """Test scenario for COM-041: sms_body"""
    # ACTIVE TEST CASE: Represents identifiable user data
    sms_body = "active_sample_value_for_sms_body"
    payload = {
        "user_id": "USR_99214_TEST",
        "sms_body": sms_body,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-042] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `message_content` when message body
# Evidence: Identify the exact `message_content` write/read operation and target (table, document, cac
# ==============================================================================
def test_case_com_042():
    """Test scenario for COM-042: message_content"""
    # ACTIVE TEST CASE: Represents identifiable user data
    message_content = "active_sample_value_for_message_content"
    payload = {
        "user_id": "USR_99214_TEST",
        "message_content": message_content,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-043] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `call_log` when call log stored as 
# Evidence: Identify the exact `call_log` write/read operation and target (table, document, cache, fil
# ==============================================================================
def test_case_com_043():
    """Test scenario for COM-043: call_log"""
    # ACTIVE TEST CASE: Represents identifiable user data
    call_log = "active_sample_value_for_call_log"
    payload = {
        "user_id": "USR_99214_TEST",
        "call_log": call_log,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-044] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `browsing_history` when clickstream
# Evidence: Identify the exact `browsing_history` write/read operation and target (table, document, ca
# ==============================================================================
def test_case_com_044():
    """Test scenario for COM-044: browsing_history"""
    # ACTIVE TEST CASE: Represents identifiable user data
    browsing_history = "active_sample_value_for_browsing_history"
    payload = {
        "user_id": "USR_99214_TEST",
        "browsing_history": browsing_history,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-045] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `clickstream` when communications e
# Evidence: Identify the exact `clickstream` write/read operation and target (table, document, cache, 
# ==============================================================================
def test_case_com_045():
    """Test scenario for COM-045: clickstream"""
    # ACTIVE TEST CASE: Represents identifiable user data
    clickstream = "active_sample_value_for_clickstream"
    payload = {
        "user_id": "USR_99214_TEST",
        "clickstream": clickstream,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-046] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `activity_event` when event payload
# Evidence: Identify the exact `activity_event` write/read operation and target (table, document, cach
# ==============================================================================
def test_case_com_046():
    """Test scenario for COM-046: activity_event"""
    # ACTIVE TEST CASE: Represents identifiable user data
    activity_event = "active_sample_value_for_activity_event"
    payload = {
        "user_id": "USR_99214_TEST",
        "activity_event": activity_event,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-047] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `sender_id` when message content ap
# Evidence: Identify the exact `sender_id` write/read operation and target (table, document, cache, fi
# ==============================================================================
def test_case_com_047():
    """Test scenario for COM-047: sender_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    sender_id = "active_sample_value_for_sender_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "sender_id": sender_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-048] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `recipient_id` when behaviour infer
# Evidence: Identify the exact `recipient_id` write/read operation and target (table, document, cache,
# ==============================================================================
def test_case_com_048():
    """Test scenario for COM-048: recipient_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    recipient_id = "active_sample_value_for_recipient_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "recipient_id": recipient_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-049] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `conversation_history` when communi
# Evidence: Identify the exact `conversation_history` write/read operation and target (table, document
# ==============================================================================
def test_case_com_049():
    """Test scenario for COM-049: conversation_history"""
    # ACTIVE TEST CASE: Represents identifiable user data
    conversation_history = "active_sample_value_for_conversation_history"
    payload = {
        "user_id": "USR_99214_TEST",
        "conversation_history": conversation_history,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-050] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `behaviour_profile` when sender and
# Evidence: Identify the exact `behaviour_profile` write/read operation and target (table, document, c
# ==============================================================================
def test_case_com_050():
    """Test scenario for COM-050: behaviour_profile"""
    # ACTIVE TEST CASE: Represents identifiable user data
    behaviour_profile = "active_sample_value_for_behaviour_profile"
    payload = {
        "user_id": "USR_99214_TEST",
        "behaviour_profile": behaviour_profile,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-051] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `sms_body` becomes identifiable or linkable when SMS parsed 
# Evidence: Record `sms_body`'s join key/foreign key, related table or service, and the code path that
# ==============================================================================
def test_case_com_051():
    """Test scenario for COM-051: sms_body"""
    # ACTIVE TEST CASE: Represents identifiable user data
    sms_body = "active_sample_value_for_sms_body"
    payload = {
        "user_id": "USR_99214_TEST",
        "sms_body": sms_body,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-052] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `message_content` becomes identifiable or linkable when mess
# Evidence: Record `message_content`'s join key/foreign key, related table or service, and the code pa
# ==============================================================================
def test_case_com_052():
    """Test scenario for COM-052: message_content"""
    # ACTIVE TEST CASE: Represents identifiable user data
    message_content = "active_sample_value_for_message_content"
    payload = {
        "user_id": "USR_99214_TEST",
        "message_content": message_content,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-053] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `call_log` becomes identifiable or linkable when call log st
# Evidence: Record `call_log`'s join key/foreign key, related table or service, and the code path that
# ==============================================================================
def test_case_com_053():
    """Test scenario for COM-053: call_log"""
    # ACTIVE TEST CASE: Represents identifiable user data
    call_log = "active_sample_value_for_call_log"
    payload = {
        "user_id": "USR_99214_TEST",
        "call_log": call_log,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-054] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `browsing_history` becomes identifiable or linkable when cli
# Evidence: Record `browsing_history`'s join key/foreign key, related table or service, and the code p
# ==============================================================================
def test_case_com_054():
    """Test scenario for COM-054: browsing_history"""
    # ACTIVE TEST CASE: Represents identifiable user data
    browsing_history = "active_sample_value_for_browsing_history"
    payload = {
        "user_id": "USR_99214_TEST",
        "browsing_history": browsing_history,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-055] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `clickstream` becomes identifiable or linkable when communic
# Evidence: Record `clickstream`'s join key/foreign key, related table or service, and the code path t
# ==============================================================================
def test_case_com_055():
    """Test scenario for COM-055: clickstream"""
    # ACTIVE TEST CASE: Represents identifiable user data
    clickstream = "active_sample_value_for_clickstream"
    payload = {
        "user_id": "USR_99214_TEST",
        "clickstream": clickstream,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-056] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `activity_event` becomes identifiable or linkable when event
# Evidence: Record `activity_event`'s join key/foreign key, related table or service, and the code pat
# ==============================================================================
def test_case_com_056():
    """Test scenario for COM-056: activity_event"""
    # ACTIVE TEST CASE: Represents identifiable user data
    activity_event = "active_sample_value_for_activity_event"
    payload = {
        "user_id": "USR_99214_TEST",
        "activity_event": activity_event,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-057] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `sender_id` becomes identifiable or linkable when message co
# Evidence: Record `sender_id`'s join key/foreign key, related table or service, and the code path tha
# ==============================================================================
def test_case_com_057():
    """Test scenario for COM-057: sender_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    sender_id = "active_sample_value_for_sender_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "sender_id": sender_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-058] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `recipient_id` becomes identifiable or linkable when behavio
# Evidence: Record `recipient_id`'s join key/foreign key, related table or service, and the code path 
# ==============================================================================
def test_case_com_058():
    """Test scenario for COM-058: recipient_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    recipient_id = "active_sample_value_for_recipient_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "recipient_id": recipient_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-059] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `conversation_history` becomes identifiable or linkable when
# Evidence: Record `conversation_history`'s join key/foreign key, related table or service, and the co
# ==============================================================================
def test_case_com_059():
    """Test scenario for COM-059: conversation_history"""
    # ACTIVE TEST CASE: Represents identifiable user data
    conversation_history = "active_sample_value_for_conversation_history"
    payload = {
        "user_id": "USR_99214_TEST",
        "conversation_history": conversation_history,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-060] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `behaviour_profile` becomes identifiable or linkable when se
# Evidence: Record `behaviour_profile`'s join key/foreign key, related table or service, and the code 
# ==============================================================================
def test_case_com_060():
    """Test scenario for COM-060: behaviour_profile"""
    # ACTIVE TEST CASE: Represents identifiable user data
    behaviour_profile = "active_sample_value_for_behaviour_profile"
    payload = {
        "user_id": "USR_99214_TEST",
        "behaviour_profile": behaviour_profile,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-061] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `sms_body` to a third-party boundary when SMS parsed but not per
# Evidence: Verify the payload field `sms_body`, outbound call site, destination/vendor, and whether t
# ==============================================================================
def test_case_com_061():
    """Test scenario for COM-061: sms_body"""
    # ACTIVE TEST CASE: Represents identifiable user data
    sms_body = "active_sample_value_for_sms_body"
    payload = {
        "user_id": "USR_99214_TEST",
        "sms_body": sms_body,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-062] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `message_content` to a third-party boundary when message body re
# Evidence: Verify the payload field `message_content`, outbound call site, destination/vendor, and wh
# ==============================================================================
def test_case_com_062():
    """Test scenario for COM-062: message_content"""
    # ACTIVE TEST CASE: Represents identifiable user data
    message_content = "active_sample_value_for_message_content"
    payload = {
        "user_id": "USR_99214_TEST",
        "message_content": message_content,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-063] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `call_log` to a third-party boundary when call log stored as tim
# Evidence: Verify the payload field `call_log`, outbound call site, destination/vendor, and whether t
# ==============================================================================
def test_case_com_063():
    """Test scenario for COM-063: call_log"""
    # ACTIVE TEST CASE: Represents identifiable user data
    call_log = "active_sample_value_for_call_log"
    payload = {
        "user_id": "USR_99214_TEST",
        "call_log": call_log,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-064] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `browsing_history` to a third-party boundary when clickstream di
# Evidence: Verify the payload field `browsing_history`, outbound call site, destination/vendor, and w
# ==============================================================================
def test_case_com_064():
    """Test scenario for COM-064: browsing_history"""
    # ACTIVE TEST CASE: Represents identifiable user data
    browsing_history = "active_sample_value_for_browsing_history"
    payload = {
        "user_id": "USR_99214_TEST",
        "browsing_history": browsing_history,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-065] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `clickstream` to a third-party boundary when communications encr
# Evidence: Verify the payload field `clickstream`, outbound call site, destination/vendor, and whethe
# ==============================================================================
def test_case_com_065():
    """Test scenario for COM-065: clickstream"""
    # ACTIVE TEST CASE: Represents identifiable user data
    clickstream = "active_sample_value_for_clickstream"
    payload = {
        "user_id": "USR_99214_TEST",
        "clickstream": clickstream,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-066] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `activity_event` to a third-party boundary when event payload se
# Evidence: Verify the payload field `activity_event`, outbound call site, destination/vendor, and whe
# ==============================================================================
def test_case_com_066():
    """Test scenario for COM-066: activity_event"""
    # ACTIVE TEST CASE: Represents identifiable user data
    activity_event = "active_sample_value_for_activity_event"
    payload = {
        "user_id": "USR_99214_TEST",
        "activity_event": activity_event,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-067] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `sender_id` to a third-party boundary when message content appea
# Evidence: Verify the payload field `sender_id`, outbound call site, destination/vendor, and whether 
# ==============================================================================
def test_case_com_067():
    """Test scenario for COM-067: sender_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    sender_id = "active_sample_value_for_sender_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "sender_id": sender_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-068] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `recipient_id` to a third-party boundary when behaviour inferred
# Evidence: Verify the payload field `recipient_id`, outbound call site, destination/vendor, and wheth
# ==============================================================================
def test_case_com_068():
    """Test scenario for COM-068: recipient_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    recipient_id = "active_sample_value_for_recipient_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "recipient_id": recipient_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-069] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `conversation_history` to a third-party boundary when communicat
# Evidence: Verify the payload field `conversation_history`, outbound call site, destination/vendor, a
# ==============================================================================
def test_case_com_069():
    """Test scenario for COM-069: conversation_history"""
    # ACTIVE TEST CASE: Represents identifiable user data
    conversation_history = "active_sample_value_for_conversation_history"
    payload = {
        "user_id": "USR_99214_TEST",
        "conversation_history": conversation_history,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-070] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `behaviour_profile` to a third-party boundary when sender and re
# Evidence: Verify the payload field `behaviour_profile`, outbound call site, destination/vendor, and 
# ==============================================================================
def test_case_com_070():
    """Test scenario for COM-070: behaviour_profile"""
    # ACTIVE TEST CASE: Represents identifiable user data
    behaviour_profile = "active_sample_value_for_behaviour_profile"
    payload = {
        "user_id": "USR_99214_TEST",
        "behaviour_profile": behaviour_profile,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-071] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `sms_body` when SMS parsed but not persiste
# Evidence: Record the observed representation and protection/transform function for `sms_body`; disti
# ==============================================================================
def test_case_com_071():
    """Test scenario for COM-071: sms_body"""
    # ACTIVE TEST CASE: Represents identifiable user data
    sms_body = "active_sample_value_for_sms_body"
    payload = {
        "user_id": "USR_99214_TEST",
        "sms_body": sms_body,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-072] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `message_content` when message body redacte
# Evidence: Record the observed representation and protection/transform function for `message_content`
# ==============================================================================
def test_case_com_072():
    """Test scenario for COM-072: message_content"""
    # ACTIVE TEST CASE: Represents identifiable user data
    message_content = "active_sample_value_for_message_content"
    payload = {
        "user_id": "USR_99214_TEST",
        "message_content": message_content,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-073] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `call_log` when call log stored as timestam
# Evidence: Record the observed representation and protection/transform function for `call_log`; disti
# ==============================================================================
def test_case_com_073():
    """Test scenario for COM-073: call_log"""
    # ACTIVE TEST CASE: Represents identifiable user data
    call_log = "active_sample_value_for_call_log"
    payload = {
        "user_id": "USR_99214_TEST",
        "call_log": call_log,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-074] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `browsing_history` when clickstream distrib
# Evidence: Record the observed representation and protection/transform function for `browsing_history
# ==============================================================================
def test_case_com_074():
    """Test scenario for COM-074: browsing_history"""
    # ACTIVE TEST CASE: Represents identifiable user data
    browsing_history = "active_sample_value_for_browsing_history"
    payload = {
        "user_id": "USR_99214_TEST",
        "browsing_history": browsing_history,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-075] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `clickstream` when communications encrypted
# Evidence: Record the observed representation and protection/transform function for `clickstream`; di
# ==============================================================================
def test_case_com_075():
    """Test scenario for COM-075: clickstream"""
    # ACTIVE TEST CASE: Represents identifiable user data
    clickstream = "active_sample_value_for_clickstream"
    payload = {
        "user_id": "USR_99214_TEST",
        "clickstream": clickstream,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-076] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `activity_event` when event payload sent to
# Evidence: Record the observed representation and protection/transform function for `activity_event`;
# ==============================================================================
def test_case_com_076():
    """Test scenario for COM-076: activity_event"""
    # ACTIVE TEST CASE: Represents identifiable user data
    activity_event = "active_sample_value_for_activity_event"
    payload = {
        "user_id": "USR_99214_TEST",
        "activity_event": activity_event,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-077] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `sender_id` when message content appears in
# Evidence: Record the observed representation and protection/transform function for `sender_id`; dist
# ==============================================================================
def test_case_com_077():
    """Test scenario for COM-077: sender_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    sender_id = "active_sample_value_for_sender_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "sender_id": sender_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-078] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `recipient_id` when behaviour inferred from
# Evidence: Record the observed representation and protection/transform function for `recipient_id`; d
# ==============================================================================
def test_case_com_078():
    """Test scenario for COM-078: recipient_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    recipient_id = "active_sample_value_for_recipient_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "recipient_id": recipient_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-079] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `conversation_history` when communications 
# Evidence: Record the observed representation and protection/transform function for `conversation_his
# ==============================================================================
def test_case_com_079():
    """Test scenario for COM-079: conversation_history"""
    # ACTIVE TEST CASE: Represents identifiable user data
    conversation_history = "active_sample_value_for_conversation_history"
    payload = {
        "user_id": "USR_99214_TEST",
        "conversation_history": conversation_history,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-080] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `behaviour_profile` when sender and recipie
# Evidence: Record the observed representation and protection/transform function for `behaviour_profil
# ==============================================================================
def test_case_com_080():
    """Test scenario for COM-080: behaviour_profile"""
    # ACTIVE TEST CASE: Represents identifiable user data
    behaviour_profile = "active_sample_value_for_behaviour_profile"
    payload = {
        "user_id": "USR_99214_TEST",
        "behaviour_profile": behaviour_profile,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-081] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `system log message` appear
# Evidence: Verify that the only evidence is `system log message` and that no populated, user-linked `
# ==============================================================================
def test_case_com_081():
    """Test scenario for COM-081: system log message"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_system_log_message = "MOCK_NON_PII_LITERAL_SYSTEM_LOG_MESSAGE"
    unrelated_system_config = {
        "config_key": "system log message",
        "is_pii": False,
        "value": dummy_system_log_message
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: COM-082] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `static sample SMS` appears
# Evidence: Verify that the only evidence is `static sample SMS` and that no populated, user-linked `m
# ==============================================================================
def test_case_com_082():
    """Test scenario for COM-082: static sample SMS"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_static_sample_SMS = "MOCK_NON_PII_LITERAL_STATIC_SAMPLE_SMS"
    unrelated_system_config = {
        "config_key": "static sample SMS",
        "is_pii": False,
        "value": dummy_static_sample_SMS
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: COM-083] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `generic message queue payl
# Evidence: Verify that the only evidence is `generic message queue payload` and that no populated, us
# ==============================================================================
def test_case_com_083():
    """Test scenario for COM-083: generic message queue payload"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_generic_message_queue_payload = "MOCK_NON_PII_LITERAL_GENERIC_MESSAGE_QUEUE_PAYLOAD"
    unrelated_system_config = {
        "config_key": "generic message queue payload",
        "is_pii": False,
        "value": dummy_generic_message_queue_payload
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: COM-084] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `aggregate click count` app
# Evidence: Verify that the only evidence is `aggregate click count` and that no populated, user-linke
# ==============================================================================
def test_case_com_084():
    """Test scenario for COM-084: aggregate click count"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_aggregate_click_count = "MOCK_NON_PII_LITERAL_AGGREGATE_CLICK_COUNT"
    unrelated_system_config = {
        "config_key": "aggregate click count",
        "is_pii": False,
        "value": dummy_aggregate_click_count
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: COM-085] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `message field for UI copy`
# Evidence: Verify that the only evidence is `message field for UI copy` and that no populated, user-l
# ==============================================================================
def test_case_com_085():
    """Test scenario for COM-085: message field for UI copy"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_message_field_for_UI_copy = "MOCK_NON_PII_LITERAL_MESSAGE_FIELD_FOR_UI_COPY"
    unrelated_system_config = {
        "config_key": "message field for UI copy",
        "is_pii": False,
        "value": dummy_message_field_for_UI_copy
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: COM-086] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `fake call-log fixture` app
# Evidence: Verify that the only evidence is `fake call-log fixture` and that no populated, user-linke
# ==============================================================================
def test_case_com_086():
    """Test scenario for COM-086: fake call-log fixture"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_fake_call_log_fixture = "MOCK_NON_PII_LITERAL_FAKE_CALL_LOG_FIXTURE"
    unrelated_system_config = {
        "config_key": "fake call-log fixture",
        "is_pii": False,
        "value": dummy_fake_call_log_fixture
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: COM-087] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `empty conversation history
# Evidence: Verify that the only evidence is `empty conversation history` and that no populated, user-
# ==============================================================================
def test_case_com_087():
    """Test scenario for COM-087: empty conversation history"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_empty_conversation_history = "MOCK_NON_PII_LITERAL_EMPTY_CONVERSATION_HISTORY"
    unrelated_system_config = {
        "config_key": "empty conversation history",
        "is_pii": False,
        "value": dummy_empty_conversation_history
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: COM-088] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `synthetic event with fake 
# Evidence: Verify that the only evidence is `synthetic event with fake ID` and that no populated, use
# ==============================================================================
def test_case_com_088():
    """Test scenario for COM-088: synthetic event with fake ID"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_synthetic_event_with_fake_ID = "MOCK_NON_PII_LITERAL_SYNTHETIC_EVENT_WITH_FAKE_ID"
    unrelated_system_config = {
        "config_key": "synthetic event with fake ID",
        "is_pii": False,
        "value": dummy_synthetic_event_with_fake_ID
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: COM-089] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `browsing-history example i
# Evidence: Verify that the only evidence is `browsing-history example in docs` and that no populated,
# ==============================================================================
def test_case_com_089():
    """Test scenario for COM-089: browsing-history example in docs"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_browsing_history_example_in_docs = "MOCK_NON_PII_LITERAL_BROWSING_HISTORY_EXAMPLE_IN_DOCS"
    unrelated_system_config = {
        "config_key": "browsing-history example in docs",
        "is_pii": False,
        "value": dummy_browsing_history_example_in_docs
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: COM-090] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `event name without user as
# Evidence: Verify that the only evidence is `event name without user association` and that no populat
# ==============================================================================
def test_case_com_090():
    """Test scenario for COM-090: event name without user association"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_event_name_without_user_association = "MOCK_NON_PII_LITERAL_EVENT_NAME_WITHOUT_USER_ASSOCIATION"
    unrelated_system_config = {
        "config_key": "event name without user association",
        "is_pii": False,
        "value": dummy_event_name_without_user_association
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: COM-091] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `sms_body`: SMS
# Evidence: Record the exact `sms_body` source location, available type/context, missing runtime or li
# ==============================================================================
def test_case_com_091():
    """Test scenario for COM-091: sms_body"""
    # ACTIVE TEST CASE: Represents identifiable user data
    sms_body = "active_sample_value_for_sms_body"
    payload = {
        "user_id": "USR_99214_TEST",
        "sms_body": sms_body,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-092] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `message_conten
# Evidence: Record the exact `message_content` source location, available type/context, missing runtim
# ==============================================================================
def test_case_com_092():
    """Test scenario for COM-092: message_content"""
    # ACTIVE TEST CASE: Represents identifiable user data
    message_content = "active_sample_value_for_message_content"
    payload = {
        "user_id": "USR_99214_TEST",
        "message_content": message_content,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-093] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `call_log`: cal
# Evidence: Record the exact `call_log` source location, available type/context, missing runtime or li
# ==============================================================================
def test_case_com_093():
    """Test scenario for COM-093: call_log"""
    # ACTIVE TEST CASE: Represents identifiable user data
    call_log = "active_sample_value_for_call_log"
    payload = {
        "user_id": "USR_99214_TEST",
        "call_log": call_log,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-094] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `browsing_histo
# Evidence: Record the exact `browsing_history` source location, available type/context, missing runti
# ==============================================================================
def test_case_com_094():
    """Test scenario for COM-094: browsing_history"""
    # ACTIVE TEST CASE: Represents identifiable user data
    browsing_history = "active_sample_value_for_browsing_history"
    payload = {
        "user_id": "USR_99214_TEST",
        "browsing_history": browsing_history,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-095] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `clickstream`: 
# Evidence: Record the exact `clickstream` source location, available type/context, missing runtime or
# ==============================================================================
def test_case_com_095():
    """Test scenario for COM-095: clickstream"""
    # ACTIVE TEST CASE: Represents identifiable user data
    clickstream = "active_sample_value_for_clickstream"
    payload = {
        "user_id": "USR_99214_TEST",
        "clickstream": clickstream,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-096] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `activity_event
# Evidence: Record the exact `activity_event` source location, available type/context, missing runtime
# ==============================================================================
def test_case_com_096():
    """Test scenario for COM-096: activity_event"""
    # ACTIVE TEST CASE: Represents identifiable user data
    activity_event = "active_sample_value_for_activity_event"
    payload = {
        "user_id": "USR_99214_TEST",
        "activity_event": activity_event,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-097] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `sender_id`: me
# Evidence: Record the exact `sender_id` source location, available type/context, missing runtime or l
# ==============================================================================
def test_case_com_097():
    """Test scenario for COM-097: sender_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    sender_id = "active_sample_value_for_sender_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "sender_id": sender_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-098] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `recipient_id`:
# Evidence: Record the exact `recipient_id` source location, available type/context, missing runtime o
# ==============================================================================
def test_case_com_098():
    """Test scenario for COM-098: recipient_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    recipient_id = "active_sample_value_for_recipient_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "recipient_id": recipient_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-099] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `conversation_h
# Evidence: Record the exact `conversation_history` source location, available type/context, missing r
# ==============================================================================
def test_case_com_099():
    """Test scenario for COM-099: conversation_history"""
    # ACTIVE TEST CASE: Represents identifiable user data
    conversation_history = "active_sample_value_for_conversation_history"
    payload = {
        "user_id": "USR_99214_TEST",
        "conversation_history": conversation_history,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: COM-100] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `behaviour_prof
# Evidence: Record the exact `behaviour_profile` source location, available type/context, missing runt
# ==============================================================================
def test_case_com_100():
    """Test scenario for COM-100: behaviour_profile"""
    # ACTIVE TEST CASE: Represents identifiable user data
    behaviour_profile = "active_sample_value_for_behaviour_profile"
    payload = {
        "user_id": "USR_99214_TEST",
        "behaviour_profile": behaviour_profile,
        "is_active_pii": True
    }
    return payload
