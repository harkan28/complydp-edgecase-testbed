"""
COMPLYDP EDGE-CASE TEST SUITE: PAYMENT INFORMATION (PAY)
Contains all 100 test scenarios (PAY-001 to PAY-100).
Includes Positive PII cases, API flows, Masked cases, and Negative Control Traps.
"""

import re
import json
import hashlib
from typing import Dict, Any, List, Optional

# ==============================================================================
# [TEST_ID: PAY-001] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `upi_id` in the repository schema or source code, including U
# Evidence: Verify the exact `upi_id` declaration, its type/validation/usage, and whether it is linked
# ==============================================================================
def test_case_pay_001():
    """Test scenario for PAY-001: upi_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    upi_id = "active_sample_value_for_upi_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "upi_id": upi_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-002] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `bank_account_number` in the repository schema or source code
# Evidence: Verify the exact `bank_account_number` declaration, its type/validation/usage, and whether
# ==============================================================================
def test_case_pay_002():
    """Test scenario for PAY-002: bank_account_number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    bank_account_number = "active_sample_value_for_bank_account_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "bank_account_number": bank_account_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-003] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `ifsc_code` in the repository schema or source code, includin
# Evidence: Verify the exact `ifsc_code` declaration, its type/validation/usage, and whether it is lin
# ==============================================================================
def test_case_pay_003():
    """Test scenario for PAY-003: ifsc_code"""
    # ACTIVE TEST CASE: Represents identifiable user data
    ifsc_code = "active_sample_value_for_ifsc_code"
    payload = {
        "user_id": "USR_99214_TEST",
        "ifsc_code": ifsc_code,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-004] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `cardholder_name` in the repository schema or source code, in
# Evidence: Verify the exact `cardholder_name` declaration, its type/validation/usage, and whether it 
# ==============================================================================
def test_case_pay_004():
    """Test scenario for PAY-004: cardholder_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    cardholder_name = "active_sample_value_for_cardholder_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "cardholder_name": cardholder_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-005] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `payment_token` in the repository schema or source code, incl
# Evidence: Verify the exact `payment_token` declaration, its type/validation/usage, and whether it is
# ==============================================================================
def test_case_pay_005():
    """Test scenario for PAY-005: payment_token"""
    # ACTIVE TEST CASE: Represents identifiable user data
    payment_token = "active_sample_value_for_payment_token"
    payload = {
        "user_id": "USR_99214_TEST",
        "payment_token": payment_token,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-006] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `utr_number` in the repository schema or source code, includi
# Evidence: Verify the exact `utr_number` declaration, its type/validation/usage, and whether it is li
# ==============================================================================
def test_case_pay_006():
    """Test scenario for PAY-006: utr_number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    utr_number = "active_sample_value_for_utr_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "utr_number": utr_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-007] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `transaction_reference` in the repository schema or source co
# Evidence: Verify the exact `transaction_reference` declaration, its type/validation/usage, and wheth
# ==============================================================================
def test_case_pay_007():
    """Test scenario for PAY-007: transaction_reference"""
    # ACTIVE TEST CASE: Represents identifiable user data
    transaction_reference = "active_sample_value_for_transaction_reference"
    payload = {
        "user_id": "USR_99214_TEST",
        "transaction_reference": transaction_reference,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-008] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `beneficiary_account` in the repository schema or source code
# Evidence: Verify the exact `beneficiary_account` declaration, its type/validation/usage, and whether
# ==============================================================================
def test_case_pay_008():
    """Test scenario for PAY-008: beneficiary_account"""
    # ACTIVE TEST CASE: Represents identifiable user data
    beneficiary_account = "active_sample_value_for_beneficiary_account"
    payload = {
        "user_id": "USR_99214_TEST",
        "beneficiary_account": beneficiary_account,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-009] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `payment_method_details` in the repository schema or source c
# Evidence: Verify the exact `payment_method_details` declaration, its type/validation/usage, and whet
# ==============================================================================
def test_case_pay_009():
    """Test scenario for PAY-009: payment_method_details"""
    # ACTIVE TEST CASE: Represents identifiable user data
    payment_method_details = "active_sample_value_for_payment_method_details"
    payload = {
        "user_id": "USR_99214_TEST",
        "payment_method_details": payment_method_details,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-010] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `billing_profile` in the repository schema or source code, in
# Evidence: Verify the exact `billing_profile` declaration, its type/validation/usage, and whether it 
# ==============================================================================
def test_case_pay_010():
    """Test scenario for PAY-010: billing_profile"""
    # ACTIVE TEST CASE: Represents identifiable user data
    billing_profile = "active_sample_value_for_billing_profile"
    payload = {
        "user_id": "USR_99214_TEST",
        "billing_profile": billing_profile,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-011] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `upi_id` when UPI ID with dots or hyphens; inspect nested 
# Evidence: Capture the full JSON/object path for `upi_id`, the parent record or user key, and the cod
# ==============================================================================
def test_case_pay_011():
    """Test scenario for PAY-011: upi_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    upi_id = "active_sample_value_for_upi_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "upi_id": upi_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-012] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `bank_account_number` when account number masked except fi
# Evidence: Capture the full JSON/object path for `bank_account_number`, the parent record or user key
# ==============================================================================
def test_case_pay_012():
    """Test scenario for PAY-012: bank_account_number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    bank_account_number = "active_sample_value_for_bank_account_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "bank_account_number": bank_account_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-013] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `ifsc_code` when IFSC associated with a specific account; 
# Evidence: Capture the full JSON/object path for `ifsc_code`, the parent record or user key, and the 
# ==============================================================================
def test_case_pay_013():
    """Test scenario for PAY-013: ifsc_code"""
    # ACTIVE TEST CASE: Represents identifiable user data
    ifsc_code = "active_sample_value_for_ifsc_code"
    payload = {
        "user_id": "USR_99214_TEST",
        "ifsc_code": ifsc_code,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-014] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `cardholder_name` when payment token distinguished from a 
# Evidence: Capture the full JSON/object path for `cardholder_name`, the parent record or user key, an
# ==============================================================================
def test_case_pay_014():
    """Test scenario for PAY-014: cardholder_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    cardholder_name = "active_sample_value_for_cardholder_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "cardholder_name": cardholder_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-015] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `payment_token` when UTR linked to a user through a join; 
# Evidence: Capture the full JSON/object path for `payment_token`, the parent record or user key, and 
# ==============================================================================
def test_case_pay_015():
    """Test scenario for PAY-015: payment_token"""
    # ACTIVE TEST CASE: Represents identifiable user data
    payment_token = "active_sample_value_for_payment_token"
    payload = {
        "user_id": "USR_99214_TEST",
        "payment_token": payment_token,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-016] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `utr_number` when payment data encrypted at rest; inspect 
# Evidence: Capture the full JSON/object path for `utr_number`, the parent record or user key, and the
# ==============================================================================
def test_case_pay_016():
    """Test scenario for PAY-016: utr_number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    utr_number = "active_sample_value_for_utr_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "utr_number": utr_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-017] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `transaction_reference` when payment payload URL-encoded; 
# Evidence: Capture the full JSON/object path for `transaction_reference`, the parent record or user k
# ==============================================================================
def test_case_pay_017():
    """Test scenario for PAY-017: transaction_reference"""
    # ACTIVE TEST CASE: Represents identifiable user data
    transaction_reference = "active_sample_value_for_transaction_reference"
    payload = {
        "user_id": "USR_99214_TEST",
        "transaction_reference": transaction_reference,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-018] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `beneficiary_account` when bank details used to generate a
# Evidence: Capture the full JSON/object path for `beneficiary_account`, the parent record or user key
# ==============================================================================
def test_case_pay_018():
    """Test scenario for PAY-018: beneficiary_account"""
    # ACTIVE TEST CASE: Represents identifiable user data
    beneficiary_account = "active_sample_value_for_beneficiary_account"
    payload = {
        "user_id": "USR_99214_TEST",
        "beneficiary_account": beneficiary_account,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-019] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `payment_method_details` when gateway returns a token inst
# Evidence: Capture the full JSON/object path for `payment_method_details`, the parent record or user 
# ==============================================================================
def test_case_pay_019():
    """Test scenario for PAY-019: payment_method_details"""
    # ACTIVE TEST CASE: Represents identifiable user data
    payment_method_details = "active_sample_value_for_payment_method_details"
    payload = {
        "user_id": "USR_99214_TEST",
        "payment_method_details": payment_method_details,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-020] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `billing_profile` when payment details included in an anal
# Evidence: Capture the full JSON/object path for `billing_profile`, the parent record or user key, an
# ==============================================================================
def test_case_pay_020():
    """Test scenario for PAY-020: billing_profile"""
    # ACTIVE TEST CASE: Represents identifiable user data
    billing_profile = "active_sample_value_for_billing_profile"
    payload = {
        "user_id": "USR_99214_TEST",
        "billing_profile": billing_profile,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-021] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `upi_id` through an API boundary when UPI ID with dots or hyph
# Evidence: Verify the request/response schema and call site for `upi_id`, direction of flow, endpoint
# ==============================================================================
def test_case_pay_021():
    """Test scenario for PAY-021: upi_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    upi_id = "active_sample_value_for_upi_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "upi_id": upi_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-022] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `bank_account_number` through an API boundary when account num
# Evidence: Verify the request/response schema and call site for `bank_account_number`, direction of f
# ==============================================================================
def test_case_pay_022():
    """Test scenario for PAY-022: bank_account_number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    bank_account_number = "active_sample_value_for_bank_account_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "bank_account_number": bank_account_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-023] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `ifsc_code` through an API boundary when IFSC associated with 
# Evidence: Verify the request/response schema and call site for `ifsc_code`, direction of flow, endpo
# ==============================================================================
def test_case_pay_023():
    """Test scenario for PAY-023: ifsc_code"""
    # ACTIVE TEST CASE: Represents identifiable user data
    ifsc_code = "active_sample_value_for_ifsc_code"
    payload = {
        "user_id": "USR_99214_TEST",
        "ifsc_code": ifsc_code,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-024] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `cardholder_name` through an API boundary when payment token d
# Evidence: Verify the request/response schema and call site for `cardholder_name`, direction of flow,
# ==============================================================================
def test_case_pay_024():
    """Test scenario for PAY-024: cardholder_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    cardholder_name = "active_sample_value_for_cardholder_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "cardholder_name": cardholder_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-025] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `payment_token` through an API boundary when UTR linked to a u
# Evidence: Verify the request/response schema and call site for `payment_token`, direction of flow, e
# ==============================================================================
def test_case_pay_025():
    """Test scenario for PAY-025: payment_token"""
    # ACTIVE TEST CASE: Represents identifiable user data
    payment_token = "active_sample_value_for_payment_token"
    payload = {
        "user_id": "USR_99214_TEST",
        "payment_token": payment_token,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-026] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `utr_number` through an API boundary when payment data encrypt
# Evidence: Verify the request/response schema and call site for `utr_number`, direction of flow, endp
# ==============================================================================
def test_case_pay_026():
    """Test scenario for PAY-026: utr_number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    utr_number = "active_sample_value_for_utr_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "utr_number": utr_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-027] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `transaction_reference` through an API boundary when payment p
# Evidence: Verify the request/response schema and call site for `transaction_reference`, direction of
# ==============================================================================
def test_case_pay_027():
    """Test scenario for PAY-027: transaction_reference"""
    # ACTIVE TEST CASE: Represents identifiable user data
    transaction_reference = "active_sample_value_for_transaction_reference"
    payload = {
        "user_id": "USR_99214_TEST",
        "transaction_reference": transaction_reference,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-028] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `beneficiary_account` through an API boundary when bank detail
# Evidence: Verify the request/response schema and call site for `beneficiary_account`, direction of f
# ==============================================================================
def test_case_pay_028():
    """Test scenario for PAY-028: beneficiary_account"""
    # ACTIVE TEST CASE: Represents identifiable user data
    beneficiary_account = "active_sample_value_for_beneficiary_account"
    payload = {
        "user_id": "USR_99214_TEST",
        "beneficiary_account": beneficiary_account,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-029] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `payment_method_details` through an API boundary when gateway 
# Evidence: Verify the request/response schema and call site for `payment_method_details`, direction o
# ==============================================================================
def test_case_pay_029():
    """Test scenario for PAY-029: payment_method_details"""
    # ACTIVE TEST CASE: Represents identifiable user data
    payment_method_details = "active_sample_value_for_payment_method_details"
    payload = {
        "user_id": "USR_99214_TEST",
        "payment_method_details": payment_method_details,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-030] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `billing_profile` through an API boundary when payment details
# Evidence: Verify the request/response schema and call site for `billing_profile`, direction of flow,
# ==============================================================================
def test_case_pay_030():
    """Test scenario for PAY-030: billing_profile"""
    # ACTIVE TEST CASE: Represents identifiable user data
    billing_profile = "active_sample_value_for_billing_profile"
    payload = {
        "user_id": "USR_99214_TEST",
        "billing_profile": billing_profile,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-031] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `upi_id` when UPI ID with dots or hyphens; follow a
# Evidence: Show the source value, transformation or derivation applied to `upi_id`, and resulting sin
# ==============================================================================
def test_case_pay_031():
    """Test scenario for PAY-031: upi_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    upi_id = "active_sample_value_for_upi_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "upi_id": upi_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-032] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `bank_account_number` when account number masked ex
# Evidence: Show the source value, transformation or derivation applied to `bank_account_number`, and 
# ==============================================================================
def test_case_pay_032():
    """Test scenario for PAY-032: bank_account_number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    bank_account_number = "active_sample_value_for_bank_account_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "bank_account_number": bank_account_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-033] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `ifsc_code` when IFSC associated with a specific ac
# Evidence: Show the source value, transformation or derivation applied to `ifsc_code`, and resulting 
# ==============================================================================
def test_case_pay_033():
    """Test scenario for PAY-033: ifsc_code"""
    # ACTIVE TEST CASE: Represents identifiable user data
    ifsc_code = "active_sample_value_for_ifsc_code"
    payload = {
        "user_id": "USR_99214_TEST",
        "ifsc_code": ifsc_code,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-034] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `cardholder_name` when payment token distinguished 
# Evidence: Show the source value, transformation or derivation applied to `cardholder_name`, and resu
# ==============================================================================
def test_case_pay_034():
    """Test scenario for PAY-034: cardholder_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    cardholder_name = "active_sample_value_for_cardholder_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "cardholder_name": cardholder_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-035] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `payment_token` when UTR linked to a user through a
# Evidence: Show the source value, transformation or derivation applied to `payment_token`, and result
# ==============================================================================
def test_case_pay_035():
    """Test scenario for PAY-035: payment_token"""
    # ACTIVE TEST CASE: Represents identifiable user data
    payment_token = "active_sample_value_for_payment_token"
    payload = {
        "user_id": "USR_99214_TEST",
        "payment_token": payment_token,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-036] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `utr_number` when payment data encrypted at rest; f
# Evidence: Show the source value, transformation or derivation applied to `utr_number`, and resulting
# ==============================================================================
def test_case_pay_036():
    """Test scenario for PAY-036: utr_number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    utr_number = "active_sample_value_for_utr_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "utr_number": utr_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-037] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `transaction_reference` when payment payload URL-en
# Evidence: Show the source value, transformation or derivation applied to `transaction_reference`, an
# ==============================================================================
def test_case_pay_037():
    """Test scenario for PAY-037: transaction_reference"""
    # ACTIVE TEST CASE: Represents identifiable user data
    transaction_reference = "active_sample_value_for_transaction_reference"
    payload = {
        "user_id": "USR_99214_TEST",
        "transaction_reference": transaction_reference,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-038] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `beneficiary_account` when bank details used to gen
# Evidence: Show the source value, transformation or derivation applied to `beneficiary_account`, and 
# ==============================================================================
def test_case_pay_038():
    """Test scenario for PAY-038: beneficiary_account"""
    # ACTIVE TEST CASE: Represents identifiable user data
    beneficiary_account = "active_sample_value_for_beneficiary_account"
    payload = {
        "user_id": "USR_99214_TEST",
        "beneficiary_account": beneficiary_account,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-039] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `payment_method_details` when gateway returns a tok
# Evidence: Show the source value, transformation or derivation applied to `payment_method_details`, a
# ==============================================================================
def test_case_pay_039():
    """Test scenario for PAY-039: payment_method_details"""
    # ACTIVE TEST CASE: Represents identifiable user data
    payment_method_details = "active_sample_value_for_payment_method_details"
    payload = {
        "user_id": "USR_99214_TEST",
        "payment_method_details": payment_method_details,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-040] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `billing_profile` when payment details included in 
# Evidence: Show the source value, transformation or derivation applied to `billing_profile`, and resu
# ==============================================================================
def test_case_pay_040():
    """Test scenario for PAY-040: billing_profile"""
    # ACTIVE TEST CASE: Represents identifiable user data
    billing_profile = "active_sample_value_for_billing_profile"
    payload = {
        "user_id": "USR_99214_TEST",
        "billing_profile": billing_profile,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-041] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `upi_id` when UPI ID with dots or h
# Evidence: Identify the exact `upi_id` write/read operation and target (table, document, cache, file,
# ==============================================================================
def test_case_pay_041():
    """Test scenario for PAY-041: upi_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    upi_id = "active_sample_value_for_upi_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "upi_id": upi_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-042] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `bank_account_number` when account 
# Evidence: Identify the exact `bank_account_number` write/read operation and target (table, document,
# ==============================================================================
def test_case_pay_042():
    """Test scenario for PAY-042: bank_account_number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    bank_account_number = "active_sample_value_for_bank_account_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "bank_account_number": bank_account_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-043] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `ifsc_code` when IFSC associated wi
# Evidence: Identify the exact `ifsc_code` write/read operation and target (table, document, cache, fi
# ==============================================================================
def test_case_pay_043():
    """Test scenario for PAY-043: ifsc_code"""
    # ACTIVE TEST CASE: Represents identifiable user data
    ifsc_code = "active_sample_value_for_ifsc_code"
    payload = {
        "user_id": "USR_99214_TEST",
        "ifsc_code": ifsc_code,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-044] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `cardholder_name` when payment toke
# Evidence: Identify the exact `cardholder_name` write/read operation and target (table, document, cac
# ==============================================================================
def test_case_pay_044():
    """Test scenario for PAY-044: cardholder_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    cardholder_name = "active_sample_value_for_cardholder_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "cardholder_name": cardholder_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-045] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `payment_token` when UTR linked to 
# Evidence: Identify the exact `payment_token` write/read operation and target (table, document, cache
# ==============================================================================
def test_case_pay_045():
    """Test scenario for PAY-045: payment_token"""
    # ACTIVE TEST CASE: Represents identifiable user data
    payment_token = "active_sample_value_for_payment_token"
    payload = {
        "user_id": "USR_99214_TEST",
        "payment_token": payment_token,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-046] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `utr_number` when payment data encr
# Evidence: Identify the exact `utr_number` write/read operation and target (table, document, cache, f
# ==============================================================================
def test_case_pay_046():
    """Test scenario for PAY-046: utr_number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    utr_number = "active_sample_value_for_utr_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "utr_number": utr_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-047] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `transaction_reference` when paymen
# Evidence: Identify the exact `transaction_reference` write/read operation and target (table, documen
# ==============================================================================
def test_case_pay_047():
    """Test scenario for PAY-047: transaction_reference"""
    # ACTIVE TEST CASE: Represents identifiable user data
    transaction_reference = "active_sample_value_for_transaction_reference"
    payload = {
        "user_id": "USR_99214_TEST",
        "transaction_reference": transaction_reference,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-048] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `beneficiary_account` when bank det
# Evidence: Identify the exact `beneficiary_account` write/read operation and target (table, document,
# ==============================================================================
def test_case_pay_048():
    """Test scenario for PAY-048: beneficiary_account"""
    # ACTIVE TEST CASE: Represents identifiable user data
    beneficiary_account = "active_sample_value_for_beneficiary_account"
    payload = {
        "user_id": "USR_99214_TEST",
        "beneficiary_account": beneficiary_account,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-049] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `payment_method_details` when gatew
# Evidence: Identify the exact `payment_method_details` write/read operation and target (table, docume
# ==============================================================================
def test_case_pay_049():
    """Test scenario for PAY-049: payment_method_details"""
    # ACTIVE TEST CASE: Represents identifiable user data
    payment_method_details = "active_sample_value_for_payment_method_details"
    payload = {
        "user_id": "USR_99214_TEST",
        "payment_method_details": payment_method_details,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-050] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `billing_profile` when payment deta
# Evidence: Identify the exact `billing_profile` write/read operation and target (table, document, cac
# ==============================================================================
def test_case_pay_050():
    """Test scenario for PAY-050: billing_profile"""
    # ACTIVE TEST CASE: Represents identifiable user data
    billing_profile = "active_sample_value_for_billing_profile"
    payload = {
        "user_id": "USR_99214_TEST",
        "billing_profile": billing_profile,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-051] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `upi_id` becomes identifiable or linkable when UPI ID with d
# Evidence: Record `upi_id`'s join key/foreign key, related table or service, and the code path that l
# ==============================================================================
def test_case_pay_051():
    """Test scenario for PAY-051: upi_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    upi_id = "active_sample_value_for_upi_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "upi_id": upi_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-052] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `bank_account_number` becomes identifiable or linkable when 
# Evidence: Record `bank_account_number`'s join key/foreign key, related table or service, and the cod
# ==============================================================================
def test_case_pay_052():
    """Test scenario for PAY-052: bank_account_number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    bank_account_number = "active_sample_value_for_bank_account_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "bank_account_number": bank_account_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-053] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `ifsc_code` becomes identifiable or linkable when IFSC assoc
# Evidence: Record `ifsc_code`'s join key/foreign key, related table or service, and the code path tha
# ==============================================================================
def test_case_pay_053():
    """Test scenario for PAY-053: ifsc_code"""
    # ACTIVE TEST CASE: Represents identifiable user data
    ifsc_code = "active_sample_value_for_ifsc_code"
    payload = {
        "user_id": "USR_99214_TEST",
        "ifsc_code": ifsc_code,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-054] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `cardholder_name` becomes identifiable or linkable when paym
# Evidence: Record `cardholder_name`'s join key/foreign key, related table or service, and the code pa
# ==============================================================================
def test_case_pay_054():
    """Test scenario for PAY-054: cardholder_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    cardholder_name = "active_sample_value_for_cardholder_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "cardholder_name": cardholder_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-055] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `payment_token` becomes identifiable or linkable when UTR li
# Evidence: Record `payment_token`'s join key/foreign key, related table or service, and the code path
# ==============================================================================
def test_case_pay_055():
    """Test scenario for PAY-055: payment_token"""
    # ACTIVE TEST CASE: Represents identifiable user data
    payment_token = "active_sample_value_for_payment_token"
    payload = {
        "user_id": "USR_99214_TEST",
        "payment_token": payment_token,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-056] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `utr_number` becomes identifiable or linkable when payment d
# Evidence: Record `utr_number`'s join key/foreign key, related table or service, and the code path th
# ==============================================================================
def test_case_pay_056():
    """Test scenario for PAY-056: utr_number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    utr_number = "active_sample_value_for_utr_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "utr_number": utr_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-057] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `transaction_reference` becomes identifiable or linkable whe
# Evidence: Record `transaction_reference`'s join key/foreign key, related table or service, and the c
# ==============================================================================
def test_case_pay_057():
    """Test scenario for PAY-057: transaction_reference"""
    # ACTIVE TEST CASE: Represents identifiable user data
    transaction_reference = "active_sample_value_for_transaction_reference"
    payload = {
        "user_id": "USR_99214_TEST",
        "transaction_reference": transaction_reference,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-058] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `beneficiary_account` becomes identifiable or linkable when 
# Evidence: Record `beneficiary_account`'s join key/foreign key, related table or service, and the cod
# ==============================================================================
def test_case_pay_058():
    """Test scenario for PAY-058: beneficiary_account"""
    # ACTIVE TEST CASE: Represents identifiable user data
    beneficiary_account = "active_sample_value_for_beneficiary_account"
    payload = {
        "user_id": "USR_99214_TEST",
        "beneficiary_account": beneficiary_account,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-059] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `payment_method_details` becomes identifiable or linkable wh
# Evidence: Record `payment_method_details`'s join key/foreign key, related table or service, and the 
# ==============================================================================
def test_case_pay_059():
    """Test scenario for PAY-059: payment_method_details"""
    # ACTIVE TEST CASE: Represents identifiable user data
    payment_method_details = "active_sample_value_for_payment_method_details"
    payload = {
        "user_id": "USR_99214_TEST",
        "payment_method_details": payment_method_details,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-060] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `billing_profile` becomes identifiable or linkable when paym
# Evidence: Record `billing_profile`'s join key/foreign key, related table or service, and the code pa
# ==============================================================================
def test_case_pay_060():
    """Test scenario for PAY-060: billing_profile"""
    # ACTIVE TEST CASE: Represents identifiable user data
    billing_profile = "active_sample_value_for_billing_profile"
    payload = {
        "user_id": "USR_99214_TEST",
        "billing_profile": billing_profile,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-061] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `upi_id` to a third-party boundary when UPI ID with dots or hyph
# Evidence: Verify the payload field `upi_id`, outbound call site, destination/vendor, and whether the
# ==============================================================================
def test_case_pay_061():
    """Test scenario for PAY-061: upi_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    upi_id = "active_sample_value_for_upi_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "upi_id": upi_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-062] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `bank_account_number` to a third-party boundary when account num
# Evidence: Verify the payload field `bank_account_number`, outbound call site, destination/vendor, an
# ==============================================================================
def test_case_pay_062():
    """Test scenario for PAY-062: bank_account_number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    bank_account_number = "active_sample_value_for_bank_account_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "bank_account_number": bank_account_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-063] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `ifsc_code` to a third-party boundary when IFSC associated with 
# Evidence: Verify the payload field `ifsc_code`, outbound call site, destination/vendor, and whether 
# ==============================================================================
def test_case_pay_063():
    """Test scenario for PAY-063: ifsc_code"""
    # ACTIVE TEST CASE: Represents identifiable user data
    ifsc_code = "active_sample_value_for_ifsc_code"
    payload = {
        "user_id": "USR_99214_TEST",
        "ifsc_code": ifsc_code,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-064] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `cardholder_name` to a third-party boundary when payment token d
# Evidence: Verify the payload field `cardholder_name`, outbound call site, destination/vendor, and wh
# ==============================================================================
def test_case_pay_064():
    """Test scenario for PAY-064: cardholder_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    cardholder_name = "active_sample_value_for_cardholder_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "cardholder_name": cardholder_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-065] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `payment_token` to a third-party boundary when UTR linked to a u
# Evidence: Verify the payload field `payment_token`, outbound call site, destination/vendor, and whet
# ==============================================================================
def test_case_pay_065():
    """Test scenario for PAY-065: payment_token"""
    # ACTIVE TEST CASE: Represents identifiable user data
    payment_token = "active_sample_value_for_payment_token"
    payload = {
        "user_id": "USR_99214_TEST",
        "payment_token": payment_token,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-066] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `utr_number` to a third-party boundary when payment data encrypt
# Evidence: Verify the payload field `utr_number`, outbound call site, destination/vendor, and whether
# ==============================================================================
def test_case_pay_066():
    """Test scenario for PAY-066: utr_number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    utr_number = "active_sample_value_for_utr_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "utr_number": utr_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-067] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `transaction_reference` to a third-party boundary when payment p
# Evidence: Verify the payload field `transaction_reference`, outbound call site, destination/vendor, 
# ==============================================================================
def test_case_pay_067():
    """Test scenario for PAY-067: transaction_reference"""
    # ACTIVE TEST CASE: Represents identifiable user data
    transaction_reference = "active_sample_value_for_transaction_reference"
    payload = {
        "user_id": "USR_99214_TEST",
        "transaction_reference": transaction_reference,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-068] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `beneficiary_account` to a third-party boundary when bank detail
# Evidence: Verify the payload field `beneficiary_account`, outbound call site, destination/vendor, an
# ==============================================================================
def test_case_pay_068():
    """Test scenario for PAY-068: beneficiary_account"""
    # ACTIVE TEST CASE: Represents identifiable user data
    beneficiary_account = "active_sample_value_for_beneficiary_account"
    payload = {
        "user_id": "USR_99214_TEST",
        "beneficiary_account": beneficiary_account,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-069] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `payment_method_details` to a third-party boundary when gateway 
# Evidence: Verify the payload field `payment_method_details`, outbound call site, destination/vendor,
# ==============================================================================
def test_case_pay_069():
    """Test scenario for PAY-069: payment_method_details"""
    # ACTIVE TEST CASE: Represents identifiable user data
    payment_method_details = "active_sample_value_for_payment_method_details"
    payload = {
        "user_id": "USR_99214_TEST",
        "payment_method_details": payment_method_details,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-070] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `billing_profile` to a third-party boundary when payment details
# Evidence: Verify the payload field `billing_profile`, outbound call site, destination/vendor, and wh
# ==============================================================================
def test_case_pay_070():
    """Test scenario for PAY-070: billing_profile"""
    # ACTIVE TEST CASE: Represents identifiable user data
    billing_profile = "active_sample_value_for_billing_profile"
    payload = {
        "user_id": "USR_99214_TEST",
        "billing_profile": billing_profile,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-071] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `upi_id` when UPI ID with dots or hyphens; 
# Evidence: Record the observed representation and protection/transform function for `upi_id`; disting
# ==============================================================================
def test_case_pay_071():
    """Test scenario for PAY-071: upi_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    upi_id = "active_sample_value_for_upi_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "upi_id": upi_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-072] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `bank_account_number` when account number m
# Evidence: Record the observed representation and protection/transform function for `bank_account_num
# ==============================================================================
def test_case_pay_072():
    """Test scenario for PAY-072: bank_account_number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    bank_account_number = "active_sample_value_for_bank_account_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "bank_account_number": bank_account_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-073] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `ifsc_code` when IFSC associated with a spe
# Evidence: Record the observed representation and protection/transform function for `ifsc_code`; dist
# ==============================================================================
def test_case_pay_073():
    """Test scenario for PAY-073: ifsc_code"""
    # ACTIVE TEST CASE: Represents identifiable user data
    ifsc_code = "active_sample_value_for_ifsc_code"
    payload = {
        "user_id": "USR_99214_TEST",
        "ifsc_code": ifsc_code,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-074] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `cardholder_name` when payment token distin
# Evidence: Record the observed representation and protection/transform function for `cardholder_name`
# ==============================================================================
def test_case_pay_074():
    """Test scenario for PAY-074: cardholder_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    cardholder_name = "active_sample_value_for_cardholder_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "cardholder_name": cardholder_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-075] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `payment_token` when UTR linked to a user t
# Evidence: Record the observed representation and protection/transform function for `payment_token`; 
# ==============================================================================
def test_case_pay_075():
    """Test scenario for PAY-075: payment_token"""
    # ACTIVE TEST CASE: Represents identifiable user data
    payment_token = "active_sample_value_for_payment_token"
    payload = {
        "user_id": "USR_99214_TEST",
        "payment_token": payment_token,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-076] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `utr_number` when payment data encrypted at
# Evidence: Record the observed representation and protection/transform function for `utr_number`; dis
# ==============================================================================
def test_case_pay_076():
    """Test scenario for PAY-076: utr_number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    utr_number = "active_sample_value_for_utr_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "utr_number": utr_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-077] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `transaction_reference` when payment payloa
# Evidence: Record the observed representation and protection/transform function for `transaction_refe
# ==============================================================================
def test_case_pay_077():
    """Test scenario for PAY-077: transaction_reference"""
    # ACTIVE TEST CASE: Represents identifiable user data
    transaction_reference = "active_sample_value_for_transaction_reference"
    payload = {
        "user_id": "USR_99214_TEST",
        "transaction_reference": transaction_reference,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-078] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `beneficiary_account` when bank details use
# Evidence: Record the observed representation and protection/transform function for `beneficiary_acco
# ==============================================================================
def test_case_pay_078():
    """Test scenario for PAY-078: beneficiary_account"""
    # ACTIVE TEST CASE: Represents identifiable user data
    beneficiary_account = "active_sample_value_for_beneficiary_account"
    payload = {
        "user_id": "USR_99214_TEST",
        "beneficiary_account": beneficiary_account,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-079] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `payment_method_details` when gateway retur
# Evidence: Record the observed representation and protection/transform function for `payment_method_d
# ==============================================================================
def test_case_pay_079():
    """Test scenario for PAY-079: payment_method_details"""
    # ACTIVE TEST CASE: Represents identifiable user data
    payment_method_details = "active_sample_value_for_payment_method_details"
    payload = {
        "user_id": "USR_99214_TEST",
        "payment_method_details": payment_method_details,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-080] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `billing_profile` when payment details incl
# Evidence: Record the observed representation and protection/transform function for `billing_profile`
# ==============================================================================
def test_case_pay_080():
    """Test scenario for PAY-080: billing_profile"""
    # ACTIVE TEST CASE: Represents identifiable user data
    billing_profile = "active_sample_value_for_billing_profile"
    payload = {
        "user_id": "USR_99214_TEST",
        "billing_profile": billing_profile,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-081] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `UPI keyword without an ID`
# Evidence: Verify that the only evidence is `UPI keyword without an ID` and that no populated, user-l
# ==============================================================================
def test_case_pay_081():
    """Test scenario for PAY-081: UPI keyword without an ID"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_UPI_keyword_without_an_ID = "MOCK_NON_PII_LITERAL_UPI_KEYWORD_WITHOUT_AN_ID"
    unrelated_system_config = {
        "config_key": "UPI keyword without an ID",
        "is_pii": False,
        "value": dummy_UPI_keyword_without_an_ID
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: PAY-082] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `IFSC branch code alone` ap
# Evidence: Verify that the only evidence is `IFSC branch code alone` and that no populated, user-link
# ==============================================================================
def test_case_pay_082():
    """Test scenario for PAY-082: IFSC branch code alone"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_IFSC_branch_code_alone = "MOCK_NON_PII_LITERAL_IFSC_BRANCH_CODE_ALONE"
    unrelated_system_config = {
        "config_key": "IFSC branch code alone",
        "is_pii": False,
        "value": dummy_IFSC_branch_code_alone
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: PAY-083] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `merchant UPI destination n
# Evidence: Verify that the only evidence is `merchant UPI destination not user-linked` and that no po
# ==============================================================================
def test_case_pay_083():
    """Test scenario for PAY-083: merchant UPI destination not user-linked"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_merchant_UPI_destination_not_user_linked = "MOCK_NON_PII_LITERAL_MERCHANT_UPI_DESTINATION_NOT_USER_LINKED"
    unrelated_system_config = {
        "config_key": "merchant UPI destination not user-linked",
        "is_pii": False,
        "value": dummy_merchant_UPI_destination_not_user_linked
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: PAY-084] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `payment label in documenta
# Evidence: Verify that the only evidence is `payment label in documentation` and that no populated, u
# ==============================================================================
def test_case_pay_084():
    """Test scenario for PAY-084: payment label in documentation"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_payment_label_in_documentation = "MOCK_NON_PII_LITERAL_PAYMENT_LABEL_IN_DOCUMENTATION"
    unrelated_system_config = {
        "config_key": "payment label in documentation",
        "is_pii": False,
        "value": dummy_payment_label_in_documentation
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: PAY-085] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `fake transaction fixture` 
# Evidence: Verify that the only evidence is `fake transaction fixture` and that no populated, user-li
# ==============================================================================
def test_case_pay_085():
    """Test scenario for PAY-085: fake transaction fixture"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_fake_transaction_fixture = "MOCK_NON_PII_LITERAL_FAKE_TRANSACTION_FIXTURE"
    unrelated_system_config = {
        "config_key": "fake transaction fixture",
        "is_pii": False,
        "value": dummy_fake_transaction_fixture
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: PAY-086] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `generic non-personal payme
# Evidence: Verify that the only evidence is `generic non-personal payment token` and that no populate
# ==============================================================================
def test_case_pay_086():
    """Test scenario for PAY-086: generic non-personal payment token"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_generic_non_personal_payment_token = "MOCK_NON_PII_LITERAL_GENERIC_NON_PERSONAL_PAYMENT_TOKEN"
    unrelated_system_config = {
        "config_key": "generic non-personal payment token",
        "is_pii": False,
        "value": dummy_generic_non_personal_payment_token
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: PAY-087] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `invalid UPI format` appear
# Evidence: Verify that the only evidence is `invalid UPI format` and that no populated, user-linked `
# ==============================================================================
def test_case_pay_087():
    """Test scenario for PAY-087: invalid UPI format"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_invalid_UPI_format = "MOCK_NON_PII_LITERAL_INVALID_UPI_FORMAT"
    unrelated_system_config = {
        "config_key": "invalid UPI format",
        "is_pii": False,
        "value": dummy_invalid_UPI_format
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: PAY-088] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `empty beneficiary field` a
# Evidence: Verify that the only evidence is `empty beneficiary field` and that no populated, user-lin
# ==============================================================================
def test_case_pay_088():
    """Test scenario for PAY-088: empty beneficiary field"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_empty_beneficiary_field = "MOCK_NON_PII_LITERAL_EMPTY_BENEFICIARY_FIELD"
    unrelated_system_config = {
        "config_key": "empty beneficiary field",
        "is_pii": False,
        "value": dummy_empty_beneficiary_field
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: PAY-089] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `public merchant account de
# Evidence: Verify that the only evidence is `public merchant account details` and that no populated, 
# ==============================================================================
def test_case_pay_089():
    """Test scenario for PAY-089: public merchant account details"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_public_merchant_account_details = "MOCK_NON_PII_LITERAL_PUBLIC_MERCHANT_ACCOUNT_DETAILS"
    unrelated_system_config = {
        "config_key": "public merchant account details",
        "is_pii": False,
        "value": dummy_public_merchant_account_details
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: PAY-090] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `transaction reference with
# Evidence: Verify that the only evidence is `transaction reference with no user linkage` and that no 
# ==============================================================================
def test_case_pay_090():
    """Test scenario for PAY-090: transaction reference with no user linkage"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_transaction_reference_with_no_user_linkage = "MOCK_NON_PII_LITERAL_TRANSACTION_REFERENCE_WITH_NO_USER_LINKAGE"
    unrelated_system_config = {
        "config_key": "transaction reference with no user linkage",
        "is_pii": False,
        "value": dummy_transaction_reference_with_no_user_linkage
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: PAY-091] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `upi_id`: UPI I
# Evidence: Record the exact `upi_id` source location, available type/context, missing runtime or link
# ==============================================================================
def test_case_pay_091():
    """Test scenario for PAY-091: upi_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    upi_id = "active_sample_value_for_upi_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "upi_id": upi_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-092] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `bank_account_n
# Evidence: Record the exact `bank_account_number` source location, available type/context, missing ru
# ==============================================================================
def test_case_pay_092():
    """Test scenario for PAY-092: bank_account_number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    bank_account_number = "active_sample_value_for_bank_account_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "bank_account_number": bank_account_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-093] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `ifsc_code`: IF
# Evidence: Record the exact `ifsc_code` source location, available type/context, missing runtime or l
# ==============================================================================
def test_case_pay_093():
    """Test scenario for PAY-093: ifsc_code"""
    # ACTIVE TEST CASE: Represents identifiable user data
    ifsc_code = "active_sample_value_for_ifsc_code"
    payload = {
        "user_id": "USR_99214_TEST",
        "ifsc_code": ifsc_code,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-094] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `cardholder_nam
# Evidence: Record the exact `cardholder_name` source location, available type/context, missing runtim
# ==============================================================================
def test_case_pay_094():
    """Test scenario for PAY-094: cardholder_name"""
    # ACTIVE TEST CASE: Represents identifiable user data
    cardholder_name = "active_sample_value_for_cardholder_name"
    payload = {
        "user_id": "USR_99214_TEST",
        "cardholder_name": cardholder_name,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-095] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `payment_token`
# Evidence: Record the exact `payment_token` source location, available type/context, missing runtime 
# ==============================================================================
def test_case_pay_095():
    """Test scenario for PAY-095: payment_token"""
    # ACTIVE TEST CASE: Represents identifiable user data
    payment_token = "active_sample_value_for_payment_token"
    payload = {
        "user_id": "USR_99214_TEST",
        "payment_token": payment_token,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-096] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `utr_number`: p
# Evidence: Record the exact `utr_number` source location, available type/context, missing runtime or 
# ==============================================================================
def test_case_pay_096():
    """Test scenario for PAY-096: utr_number"""
    # ACTIVE TEST CASE: Represents identifiable user data
    utr_number = "active_sample_value_for_utr_number"
    payload = {
        "user_id": "USR_99214_TEST",
        "utr_number": utr_number,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-097] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `transaction_re
# Evidence: Record the exact `transaction_reference` source location, available type/context, missing 
# ==============================================================================
def test_case_pay_097():
    """Test scenario for PAY-097: transaction_reference"""
    # ACTIVE TEST CASE: Represents identifiable user data
    transaction_reference = "active_sample_value_for_transaction_reference"
    payload = {
        "user_id": "USR_99214_TEST",
        "transaction_reference": transaction_reference,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-098] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `beneficiary_ac
# Evidence: Record the exact `beneficiary_account` source location, available type/context, missing ru
# ==============================================================================
def test_case_pay_098():
    """Test scenario for PAY-098: beneficiary_account"""
    # ACTIVE TEST CASE: Represents identifiable user data
    beneficiary_account = "active_sample_value_for_beneficiary_account"
    payload = {
        "user_id": "USR_99214_TEST",
        "beneficiary_account": beneficiary_account,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-099] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `payment_method
# Evidence: Record the exact `payment_method_details` source location, available type/context, missing
# ==============================================================================
def test_case_pay_099():
    """Test scenario for PAY-099: payment_method_details"""
    # ACTIVE TEST CASE: Represents identifiable user data
    payment_method_details = "active_sample_value_for_payment_method_details"
    payload = {
        "user_id": "USR_99214_TEST",
        "payment_method_details": payment_method_details,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: PAY-100] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `billing_profil
# Evidence: Record the exact `billing_profile` source location, available type/context, missing runtim
# ==============================================================================
def test_case_pay_100():
    """Test scenario for PAY-100: billing_profile"""
    # ACTIVE TEST CASE: Represents identifiable user data
    billing_profile = "active_sample_value_for_billing_profile"
    payload = {
        "user_id": "USR_99214_TEST",
        "billing_profile": billing_profile,
        "is_active_pii": True
    }
    return payload
