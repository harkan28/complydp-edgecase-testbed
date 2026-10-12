"""
COMPLYDP EDGE-CASE TEST SUITE: EMPLOYMENT INFORMATION (EMP)
Contains all 100 test scenarios (EMP-001 to EMP-100).
Includes Positive PII cases, API flows, Masked cases, and Negative Control Traps.
"""

import re
import json
import hashlib
from typing import Dict, Any, List, Optional

# ==============================================================================
# [TEST_ID: EMP-001] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `employee_id` in the repository schema or source code, includ
# Evidence: Verify the exact `employee_id` declaration, its type/validation/usage, and whether it is l
# ==============================================================================
def test_case_emp_001():
    """Test scenario for EMP-001: employee_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    employee_id = "active_sample_value_for_employee_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "employee_id": employee_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-002] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `salary_record` in the repository schema or source code, incl
# Evidence: Verify the exact `salary_record` declaration, its type/validation/usage, and whether it is
# ==============================================================================
def test_case_emp_002():
    """Test scenario for EMP-002: salary_record"""
    # ACTIVE TEST CASE: Represents identifiable user data
    salary_record = "active_sample_value_for_salary_record"
    payload = {
        "user_id": "USR_99214_TEST",
        "salary_record": salary_record,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-003] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `payroll_details` in the repository schema or source code, in
# Evidence: Verify the exact `payroll_details` declaration, its type/validation/usage, and whether it 
# ==============================================================================
def test_case_emp_003():
    """Test scenario for EMP-003: payroll_details"""
    # ACTIVE TEST CASE: Represents identifiable user data
    payroll_details = "active_sample_value_for_payroll_details"
    payload = {
        "user_id": "USR_99214_TEST",
        "payroll_details": payroll_details,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-004] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `resume` in the repository schema or source code, including p
# Evidence: Verify the exact `resume` declaration, its type/validation/usage, and whether it is linked
# ==============================================================================
def test_case_emp_004():
    """Test scenario for EMP-004: resume"""
    # ACTIVE TEST CASE: Represents identifiable user data
    resume = "active_sample_value_for_resume"
    payload = {
        "user_id": "USR_99214_TEST",
        "resume": resume,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-005] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `employment_history` in the repository schema or source code,
# Evidence: Verify the exact `employment_history` declaration, its type/validation/usage, and whether 
# ==============================================================================
def test_case_emp_005():
    """Test scenario for EMP-005: employment_history"""
    # ACTIVE TEST CASE: Represents identifiable user data
    employment_history = "active_sample_value_for_employment_history"
    payload = {
        "user_id": "USR_99214_TEST",
        "employment_history": employment_history,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-006] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `job_title` in the repository schema or source code, includin
# Evidence: Verify the exact `job_title` declaration, its type/validation/usage, and whether it is lin
# ==============================================================================
def test_case_emp_006():
    """Test scenario for EMP-006: job_title"""
    # ACTIVE TEST CASE: Represents identifiable user data
    job_title = "active_sample_value_for_job_title"
    payload = {
        "user_id": "USR_99214_TEST",
        "job_title": job_title,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-007] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `compensation` in the repository schema or source code, inclu
# Evidence: Verify the exact `compensation` declaration, its type/validation/usage, and whether it is 
# ==============================================================================
def test_case_emp_007():
    """Test scenario for EMP-007: compensation"""
    # ACTIVE TEST CASE: Represents identifiable user data
    compensation = "active_sample_value_for_compensation"
    payload = {
        "user_id": "USR_99214_TEST",
        "compensation": compensation,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-008] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `manager_id` in the repository schema or source code, includi
# Evidence: Verify the exact `manager_id` declaration, its type/validation/usage, and whether it is li
# ==============================================================================
def test_case_emp_008():
    """Test scenario for EMP-008: manager_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    manager_id = "active_sample_value_for_manager_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "manager_id": manager_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-009] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `hr_profile` in the repository schema or source code, includi
# Evidence: Verify the exact `hr_profile` declaration, its type/validation/usage, and whether it is li
# ==============================================================================
def test_case_emp_009():
    """Test scenario for EMP-009: hr_profile"""
    # ACTIVE TEST CASE: Represents identifiable user data
    hr_profile = "active_sample_value_for_hr_profile"
    payload = {
        "user_id": "USR_99214_TEST",
        "hr_profile": hr_profile,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-010] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Schema and field namingCheck `benefits_record` in the repository schema or source code, in
# Evidence: Verify the exact `benefits_record` declaration, its type/validation/usage, and whether it 
# ==============================================================================
def test_case_emp_010():
    """Test scenario for EMP-010: benefits_record"""
    # ACTIVE TEST CASE: Represents identifiable user data
    benefits_record = "active_sample_value_for_benefits_record"
    payload = {
        "user_id": "USR_99214_TEST",
        "benefits_record": benefits_record,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-011] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `employee_id` when salary stored as a range; inspect neste
# Evidence: Capture the full JSON/object path for `employee_id`, the parent record or user key, and th
# ==============================================================================
def test_case_emp_011():
    """Test scenario for EMP-011: employee_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    employee_id = "active_sample_value_for_employee_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "employee_id": employee_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-012] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `salary_record` when employee ID changes across a migratio
# Evidence: Capture the full JSON/object path for `salary_record`, the parent record or user key, and 
# ==============================================================================
def test_case_emp_012():
    """Test scenario for EMP-012: salary_record"""
    # ACTIVE TEST CASE: Represents identifiable user data
    salary_record = "active_sample_value_for_salary_record"
    payload = {
        "user_id": "USR_99214_TEST",
        "salary_record": salary_record,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-013] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `payroll_details` when employment history nested in JSON; 
# Evidence: Capture the full JSON/object path for `payroll_details`, the parent record or user key, an
# ==============================================================================
def test_case_emp_013():
    """Test scenario for EMP-013: payroll_details"""
    # ACTIVE TEST CASE: Represents identifiable user data
    payroll_details = "active_sample_value_for_payroll_details"
    payload = {
        "user_id": "USR_99214_TEST",
        "payroll_details": payroll_details,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-014] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `resume` when payroll data included in a generated report;
# Evidence: Capture the full JSON/object path for `resume`, the parent record or user key, and the cod
# ==============================================================================
def test_case_emp_014():
    """Test scenario for EMP-014: resume"""
    # ACTIVE TEST CASE: Represents identifiable user data
    resume = "active_sample_value_for_resume"
    payload = {
        "user_id": "USR_99214_TEST",
        "resume": resume,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-015] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `employment_history` when HR export sent to a third party;
# Evidence: Capture the full JSON/object path for `employment_history`, the parent record or user key,
# ==============================================================================
def test_case_emp_015():
    """Test scenario for EMP-015: employment_history"""
    # ACTIVE TEST CASE: Represents identifiable user data
    employment_history = "active_sample_value_for_employment_history"
    payload = {
        "user_id": "USR_99214_TEST",
        "employment_history": employment_history,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-016] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `job_title` when employee details included in logs; inspec
# Evidence: Capture the full JSON/object path for `job_title`, the parent record or user key, and the 
# ==============================================================================
def test_case_emp_016():
    """Test scenario for EMP-016: job_title"""
    # ACTIVE TEST CASE: Represents identifiable user data
    job_title = "active_sample_value_for_job_title"
    payload = {
        "user_id": "USR_99214_TEST",
        "job_title": job_title,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-017] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `compensation` when job title inferred from a profile; ins
# Evidence: Capture the full JSON/object path for `compensation`, the parent record or user key, and t
# ==============================================================================
def test_case_emp_017():
    """Test scenario for EMP-017: compensation"""
    # ACTIVE TEST CASE: Represents identifiable user data
    compensation = "active_sample_value_for_compensation"
    payload = {
        "user_id": "USR_99214_TEST",
        "compensation": compensation,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-018] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `manager_id` when employee record encrypted at rest; inspe
# Evidence: Capture the full JSON/object path for `manager_id`, the parent record or user key, and the
# ==============================================================================
def test_case_emp_018():
    """Test scenario for EMP-018: manager_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    manager_id = "active_sample_value_for_manager_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "manager_id": manager_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-019] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `hr_profile` when field exists only in an old migration; i
# Evidence: Capture the full JSON/object path for `hr_profile`, the parent record or user key, and the
# ==============================================================================
def test_case_emp_019():
    """Test scenario for EMP-019: hr_profile"""
    # ACTIVE TEST CASE: Represents identifiable user data
    hr_profile = "active_sample_value_for_hr_profile"
    payload = {
        "user_id": "USR_99214_TEST",
        "hr_profile": hr_profile,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-020] [EXPECTED: DETECT POTENTIAL PII]
# Scenario: Nested and structured dataTrace `benefits_record` when employment data joined across syste
# Evidence: Capture the full JSON/object path for `benefits_record`, the parent record or user key, an
# ==============================================================================
def test_case_emp_020():
    """Test scenario for EMP-020: benefits_record"""
    # ACTIVE TEST CASE: Represents identifiable user data
    benefits_record = "active_sample_value_for_benefits_record"
    payload = {
        "user_id": "USR_99214_TEST",
        "benefits_record": benefits_record,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-021] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `employee_id` through an API boundary when salary stored as a 
# Evidence: Verify the request/response schema and call site for `employee_id`, direction of flow, end
# ==============================================================================
def test_case_emp_021():
    """Test scenario for EMP-021: employee_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    employee_id = "active_sample_value_for_employee_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "employee_id": employee_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-022] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `salary_record` through an API boundary when employee ID chang
# Evidence: Verify the request/response schema and call site for `salary_record`, direction of flow, e
# ==============================================================================
def test_case_emp_022():
    """Test scenario for EMP-022: salary_record"""
    # ACTIVE TEST CASE: Represents identifiable user data
    salary_record = "active_sample_value_for_salary_record"
    payload = {
        "user_id": "USR_99214_TEST",
        "salary_record": salary_record,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-023] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `payroll_details` through an API boundary when employment hist
# Evidence: Verify the request/response schema and call site for `payroll_details`, direction of flow,
# ==============================================================================
def test_case_emp_023():
    """Test scenario for EMP-023: payroll_details"""
    # ACTIVE TEST CASE: Represents identifiable user data
    payroll_details = "active_sample_value_for_payroll_details"
    payload = {
        "user_id": "USR_99214_TEST",
        "payroll_details": payroll_details,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-024] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `resume` through an API boundary when payroll data included in
# Evidence: Verify the request/response schema and call site for `resume`, direction of flow, endpoint
# ==============================================================================
def test_case_emp_024():
    """Test scenario for EMP-024: resume"""
    # ACTIVE TEST CASE: Represents identifiable user data
    resume = "active_sample_value_for_resume"
    payload = {
        "user_id": "USR_99214_TEST",
        "resume": resume,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-025] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `employment_history` through an API boundary when HR export se
# Evidence: Verify the request/response schema and call site for `employment_history`, direction of fl
# ==============================================================================
def test_case_emp_025():
    """Test scenario for EMP-025: employment_history"""
    # ACTIVE TEST CASE: Represents identifiable user data
    employment_history = "active_sample_value_for_employment_history"
    payload = {
        "user_id": "USR_99214_TEST",
        "employment_history": employment_history,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-026] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `job_title` through an API boundary when employee details incl
# Evidence: Verify the request/response schema and call site for `job_title`, direction of flow, endpo
# ==============================================================================
def test_case_emp_026():
    """Test scenario for EMP-026: job_title"""
    # ACTIVE TEST CASE: Represents identifiable user data
    job_title = "active_sample_value_for_job_title"
    payload = {
        "user_id": "USR_99214_TEST",
        "job_title": job_title,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-027] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `compensation` through an API boundary when job title inferred
# Evidence: Verify the request/response schema and call site for `compensation`, direction of flow, en
# ==============================================================================
def test_case_emp_027():
    """Test scenario for EMP-027: compensation"""
    # ACTIVE TEST CASE: Represents identifiable user data
    compensation = "active_sample_value_for_compensation"
    payload = {
        "user_id": "USR_99214_TEST",
        "compensation": compensation,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-028] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `manager_id` through an API boundary when employee record encr
# Evidence: Verify the request/response schema and call site for `manager_id`, direction of flow, endp
# ==============================================================================
def test_case_emp_028():
    """Test scenario for EMP-028: manager_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    manager_id = "active_sample_value_for_manager_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "manager_id": manager_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-029] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `hr_profile` through an API boundary when field exists only in
# Evidence: Verify the request/response schema and call site for `hr_profile`, direction of flow, endp
# ==============================================================================
def test_case_emp_029():
    """Test scenario for EMP-029: hr_profile"""
    # ACTIVE TEST CASE: Represents identifiable user data
    hr_profile = "active_sample_value_for_hr_profile"
    payload = {
        "user_id": "USR_99214_TEST",
        "hr_profile": hr_profile,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-030] [EXPECTED: DETECT DATA FLOW]
# Scenario: API ingress and egressTrace `benefits_record` through an API boundary when employment data
# Evidence: Verify the request/response schema and call site for `benefits_record`, direction of flow,
# ==============================================================================
def test_case_emp_030():
    """Test scenario for EMP-030: benefits_record"""
    # ACTIVE TEST CASE: Represents identifiable user data
    benefits_record = "active_sample_value_for_benefits_record"
    payload = {
        "user_id": "USR_99214_TEST",
        "benefits_record": benefits_record,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-031] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `employee_id` when salary stored as a range; follow
# Evidence: Show the source value, transformation or derivation applied to `employee_id`, and resultin
# ==============================================================================
def test_case_emp_031():
    """Test scenario for EMP-031: employee_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    employee_id = "active_sample_value_for_employee_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "employee_id": employee_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-032] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `salary_record` when employee ID changes across a m
# Evidence: Show the source value, transformation or derivation applied to `salary_record`, and result
# ==============================================================================
def test_case_emp_032():
    """Test scenario for EMP-032: salary_record"""
    # ACTIVE TEST CASE: Represents identifiable user data
    salary_record = "active_sample_value_for_salary_record"
    payload = {
        "user_id": "USR_99214_TEST",
        "salary_record": salary_record,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-033] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `payroll_details` when employment history nested in
# Evidence: Show the source value, transformation or derivation applied to `payroll_details`, and resu
# ==============================================================================
def test_case_emp_033():
    """Test scenario for EMP-033: payroll_details"""
    # ACTIVE TEST CASE: Represents identifiable user data
    payroll_details = "active_sample_value_for_payroll_details"
    payload = {
        "user_id": "USR_99214_TEST",
        "payroll_details": payroll_details,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-034] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `resume` when payroll data included in a generated 
# Evidence: Show the source value, transformation or derivation applied to `resume`, and resulting sin
# ==============================================================================
def test_case_emp_034():
    """Test scenario for EMP-034: resume"""
    # ACTIVE TEST CASE: Represents identifiable user data
    resume = "active_sample_value_for_resume"
    payload = {
        "user_id": "USR_99214_TEST",
        "resume": resume,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-035] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `employment_history` when HR export sent to a third
# Evidence: Show the source value, transformation or derivation applied to `employment_history`, and r
# ==============================================================================
def test_case_emp_035():
    """Test scenario for EMP-035: employment_history"""
    # ACTIVE TEST CASE: Represents identifiable user data
    employment_history = "active_sample_value_for_employment_history"
    payload = {
        "user_id": "USR_99214_TEST",
        "employment_history": employment_history,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-036] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `job_title` when employee details included in logs;
# Evidence: Show the source value, transformation or derivation applied to `job_title`, and resulting 
# ==============================================================================
def test_case_emp_036():
    """Test scenario for EMP-036: job_title"""
    # ACTIVE TEST CASE: Represents identifiable user data
    job_title = "active_sample_value_for_job_title"
    payload = {
        "user_id": "USR_99214_TEST",
        "job_title": job_title,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-037] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `compensation` when job title inferred from a profi
# Evidence: Show the source value, transformation or derivation applied to `compensation`, and resulti
# ==============================================================================
def test_case_emp_037():
    """Test scenario for EMP-037: compensation"""
    # ACTIVE TEST CASE: Represents identifiable user data
    compensation = "active_sample_value_for_compensation"
    payload = {
        "user_id": "USR_99214_TEST",
        "compensation": compensation,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-038] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `manager_id` when employee record encrypted at rest
# Evidence: Show the source value, transformation or derivation applied to `manager_id`, and resulting
# ==============================================================================
def test_case_emp_038():
    """Test scenario for EMP-038: manager_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    manager_id = "active_sample_value_for_manager_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "manager_id": manager_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-039] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `hr_profile` when field exists only in an old migra
# Evidence: Show the source value, transformation or derivation applied to `hr_profile`, and resulting
# ==============================================================================
def test_case_emp_039():
    """Test scenario for EMP-039: hr_profile"""
    # ACTIVE TEST CASE: Represents identifiable user data
    hr_profile = "active_sample_value_for_hr_profile"
    payload = {
        "user_id": "USR_99214_TEST",
        "hr_profile": hr_profile,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-040] [EXPECTED: DETECT IF TRACEABLE]
# Scenario: Data transformation and derivationTest `benefits_record` when employment data joined acros
# Evidence: Show the source value, transformation or derivation applied to `benefits_record`, and resu
# ==============================================================================
def test_case_emp_040():
    """Test scenario for EMP-040: benefits_record"""
    # ACTIVE TEST CASE: Represents identifiable user data
    benefits_record = "active_sample_value_for_benefits_record"
    payload = {
        "user_id": "USR_99214_TEST",
        "benefits_record": benefits_record,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-041] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `employee_id` when salary stored as
# Evidence: Identify the exact `employee_id` write/read operation and target (table, document, cache, 
# ==============================================================================
def test_case_emp_041():
    """Test scenario for EMP-041: employee_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    employee_id = "active_sample_value_for_employee_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "employee_id": employee_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-042] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `salary_record` when employee ID ch
# Evidence: Identify the exact `salary_record` write/read operation and target (table, document, cache
# ==============================================================================
def test_case_emp_042():
    """Test scenario for EMP-042: salary_record"""
    # ACTIVE TEST CASE: Represents identifiable user data
    salary_record = "active_sample_value_for_salary_record"
    payload = {
        "user_id": "USR_99214_TEST",
        "salary_record": salary_record,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-043] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `payroll_details` when employment h
# Evidence: Identify the exact `payroll_details` write/read operation and target (table, document, cac
# ==============================================================================
def test_case_emp_043():
    """Test scenario for EMP-043: payroll_details"""
    # ACTIVE TEST CASE: Represents identifiable user data
    payroll_details = "active_sample_value_for_payroll_details"
    payload = {
        "user_id": "USR_99214_TEST",
        "payroll_details": payroll_details,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-044] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `resume` when payroll data included
# Evidence: Identify the exact `resume` write/read operation and target (table, document, cache, file,
# ==============================================================================
def test_case_emp_044():
    """Test scenario for EMP-044: resume"""
    # ACTIVE TEST CASE: Represents identifiable user data
    resume = "active_sample_value_for_resume"
    payload = {
        "user_id": "USR_99214_TEST",
        "resume": resume,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-045] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `employment_history` when HR export
# Evidence: Identify the exact `employment_history` write/read operation and target (table, document, 
# ==============================================================================
def test_case_emp_045():
    """Test scenario for EMP-045: employment_history"""
    # ACTIVE TEST CASE: Represents identifiable user data
    employment_history = "active_sample_value_for_employment_history"
    payload = {
        "user_id": "USR_99214_TEST",
        "employment_history": employment_history,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-046] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `job_title` when employee details i
# Evidence: Identify the exact `job_title` write/read operation and target (table, document, cache, fi
# ==============================================================================
def test_case_emp_046():
    """Test scenario for EMP-046: job_title"""
    # ACTIVE TEST CASE: Represents identifiable user data
    job_title = "active_sample_value_for_job_title"
    payload = {
        "user_id": "USR_99214_TEST",
        "job_title": job_title,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-047] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `compensation` when job title infer
# Evidence: Identify the exact `compensation` write/read operation and target (table, document, cache,
# ==============================================================================
def test_case_emp_047():
    """Test scenario for EMP-047: compensation"""
    # ACTIVE TEST CASE: Represents identifiable user data
    compensation = "active_sample_value_for_compensation"
    payload = {
        "user_id": "USR_99214_TEST",
        "compensation": compensation,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-048] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `manager_id` when employee record e
# Evidence: Identify the exact `manager_id` write/read operation and target (table, document, cache, f
# ==============================================================================
def test_case_emp_048():
    """Test scenario for EMP-048: manager_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    manager_id = "active_sample_value_for_manager_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "manager_id": manager_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-049] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `hr_profile` when field exists only
# Evidence: Identify the exact `hr_profile` write/read operation and target (table, document, cache, f
# ==============================================================================
def test_case_emp_049():
    """Test scenario for EMP-049: hr_profile"""
    # ACTIVE TEST CASE: Represents identifiable user data
    hr_profile = "active_sample_value_for_hr_profile"
    payload = {
        "user_id": "USR_99214_TEST",
        "hr_profile": hr_profile,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-050] [EXPECTED: DETECT STORAGE PATH]
# Scenario: Storage and persistenceCheck persistence or logging of `benefits_record` when employment d
# Evidence: Identify the exact `benefits_record` write/read operation and target (table, document, cac
# ==============================================================================
def test_case_emp_050():
    """Test scenario for EMP-050: benefits_record"""
    # ACTIVE TEST CASE: Represents identifiable user data
    benefits_record = "active_sample_value_for_benefits_record"
    payload = {
        "user_id": "USR_99214_TEST",
        "benefits_record": benefits_record,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-051] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `employee_id` becomes identifiable or linkable when salary s
# Evidence: Record `employee_id`'s join key/foreign key, related table or service, and the code path t
# ==============================================================================
def test_case_emp_051():
    """Test scenario for EMP-051: employee_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    employee_id = "active_sample_value_for_employee_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "employee_id": employee_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-052] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `salary_record` becomes identifiable or linkable when employ
# Evidence: Record `salary_record`'s join key/foreign key, related table or service, and the code path
# ==============================================================================
def test_case_emp_052():
    """Test scenario for EMP-052: salary_record"""
    # ACTIVE TEST CASE: Represents identifiable user data
    salary_record = "active_sample_value_for_salary_record"
    payload = {
        "user_id": "USR_99214_TEST",
        "salary_record": salary_record,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-053] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `payroll_details` becomes identifiable or linkable when empl
# Evidence: Record `payroll_details`'s join key/foreign key, related table or service, and the code pa
# ==============================================================================
def test_case_emp_053():
    """Test scenario for EMP-053: payroll_details"""
    # ACTIVE TEST CASE: Represents identifiable user data
    payroll_details = "active_sample_value_for_payroll_details"
    payload = {
        "user_id": "USR_99214_TEST",
        "payroll_details": payroll_details,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-054] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `resume` becomes identifiable or linkable when payroll data 
# Evidence: Record `resume`'s join key/foreign key, related table or service, and the code path that l
# ==============================================================================
def test_case_emp_054():
    """Test scenario for EMP-054: resume"""
    # ACTIVE TEST CASE: Represents identifiable user data
    resume = "active_sample_value_for_resume"
    payload = {
        "user_id": "USR_99214_TEST",
        "resume": resume,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-055] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `employment_history` becomes identifiable or linkable when H
# Evidence: Record `employment_history`'s join key/foreign key, related table or service, and the code
# ==============================================================================
def test_case_emp_055():
    """Test scenario for EMP-055: employment_history"""
    # ACTIVE TEST CASE: Represents identifiable user data
    employment_history = "active_sample_value_for_employment_history"
    payload = {
        "user_id": "USR_99214_TEST",
        "employment_history": employment_history,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-056] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `job_title` becomes identifiable or linkable when employee d
# Evidence: Record `job_title`'s join key/foreign key, related table or service, and the code path tha
# ==============================================================================
def test_case_emp_056():
    """Test scenario for EMP-056: job_title"""
    # ACTIVE TEST CASE: Represents identifiable user data
    job_title = "active_sample_value_for_job_title"
    payload = {
        "user_id": "USR_99214_TEST",
        "job_title": job_title,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-057] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `compensation` becomes identifiable or linkable when job tit
# Evidence: Record `compensation`'s join key/foreign key, related table or service, and the code path 
# ==============================================================================
def test_case_emp_057():
    """Test scenario for EMP-057: compensation"""
    # ACTIVE TEST CASE: Represents identifiable user data
    compensation = "active_sample_value_for_compensation"
    payload = {
        "user_id": "USR_99214_TEST",
        "compensation": compensation,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-058] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `manager_id` becomes identifiable or linkable when employee 
# Evidence: Record `manager_id`'s join key/foreign key, related table or service, and the code path th
# ==============================================================================
def test_case_emp_058():
    """Test scenario for EMP-058: manager_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    manager_id = "active_sample_value_for_manager_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "manager_id": manager_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-059] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `hr_profile` becomes identifiable or linkable when field exi
# Evidence: Record `hr_profile`'s join key/foreign key, related table or service, and the code path th
# ==============================================================================
def test_case_emp_059():
    """Test scenario for EMP-059: hr_profile"""
    # ACTIVE TEST CASE: Represents identifiable user data
    hr_profile = "active_sample_value_for_hr_profile"
    payload = {
        "user_id": "USR_99214_TEST",
        "hr_profile": hr_profile,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-060] [EXPECTED: DETECT LINKAGE IF EVIDENCED]
# Scenario: Linkage and joinsTest whether `benefits_record` becomes identifiable or linkable when empl
# Evidence: Record `benefits_record`'s join key/foreign key, related table or service, and the code pa
# ==============================================================================
def test_case_emp_060():
    """Test scenario for EMP-060: benefits_record"""
    # ACTIVE TEST CASE: Represents identifiable user data
    benefits_record = "active_sample_value_for_benefits_record"
    payload = {
        "user_id": "USR_99214_TEST",
        "benefits_record": benefits_record,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-061] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `employee_id` to a third-party boundary when salary stored as a 
# Evidence: Verify the payload field `employee_id`, outbound call site, destination/vendor, and whethe
# ==============================================================================
def test_case_emp_061():
    """Test scenario for EMP-061: employee_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    employee_id = "active_sample_value_for_employee_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "employee_id": employee_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-062] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `salary_record` to a third-party boundary when employee ID chang
# Evidence: Verify the payload field `salary_record`, outbound call site, destination/vendor, and whet
# ==============================================================================
def test_case_emp_062():
    """Test scenario for EMP-062: salary_record"""
    # ACTIVE TEST CASE: Represents identifiable user data
    salary_record = "active_sample_value_for_salary_record"
    payload = {
        "user_id": "USR_99214_TEST",
        "salary_record": salary_record,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-063] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `payroll_details` to a third-party boundary when employment hist
# Evidence: Verify the payload field `payroll_details`, outbound call site, destination/vendor, and wh
# ==============================================================================
def test_case_emp_063():
    """Test scenario for EMP-063: payroll_details"""
    # ACTIVE TEST CASE: Represents identifiable user data
    payroll_details = "active_sample_value_for_payroll_details"
    payload = {
        "user_id": "USR_99214_TEST",
        "payroll_details": payroll_details,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-064] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `resume` to a third-party boundary when payroll data included in
# Evidence: Verify the payload field `resume`, outbound call site, destination/vendor, and whether the
# ==============================================================================
def test_case_emp_064():
    """Test scenario for EMP-064: resume"""
    # ACTIVE TEST CASE: Represents identifiable user data
    resume = "active_sample_value_for_resume"
    payload = {
        "user_id": "USR_99214_TEST",
        "resume": resume,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-065] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `employment_history` to a third-party boundary when HR export se
# Evidence: Verify the payload field `employment_history`, outbound call site, destination/vendor, and
# ==============================================================================
def test_case_emp_065():
    """Test scenario for EMP-065: employment_history"""
    # ACTIVE TEST CASE: Represents identifiable user data
    employment_history = "active_sample_value_for_employment_history"
    payload = {
        "user_id": "USR_99214_TEST",
        "employment_history": employment_history,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-066] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `job_title` to a third-party boundary when employee details incl
# Evidence: Verify the payload field `job_title`, outbound call site, destination/vendor, and whether 
# ==============================================================================
def test_case_emp_066():
    """Test scenario for EMP-066: job_title"""
    # ACTIVE TEST CASE: Represents identifiable user data
    job_title = "active_sample_value_for_job_title"
    payload = {
        "user_id": "USR_99214_TEST",
        "job_title": job_title,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-067] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `compensation` to a third-party boundary when job title inferred
# Evidence: Verify the payload field `compensation`, outbound call site, destination/vendor, and wheth
# ==============================================================================
def test_case_emp_067():
    """Test scenario for EMP-067: compensation"""
    # ACTIVE TEST CASE: Represents identifiable user data
    compensation = "active_sample_value_for_compensation"
    payload = {
        "user_id": "USR_99214_TEST",
        "compensation": compensation,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-068] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `manager_id` to a third-party boundary when employee record encr
# Evidence: Verify the payload field `manager_id`, outbound call site, destination/vendor, and whether
# ==============================================================================
def test_case_emp_068():
    """Test scenario for EMP-068: manager_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    manager_id = "active_sample_value_for_manager_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "manager_id": manager_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-069] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `hr_profile` to a third-party boundary when field exists only in
# Evidence: Verify the payload field `hr_profile`, outbound call site, destination/vendor, and whether
# ==============================================================================
def test_case_emp_069():
    """Test scenario for EMP-069: hr_profile"""
    # ACTIVE TEST CASE: Represents identifiable user data
    hr_profile = "active_sample_value_for_hr_profile"
    payload = {
        "user_id": "USR_99214_TEST",
        "hr_profile": hr_profile,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-070] [EXPECTED: DETECT OUTBOUND FLOW IF EVIDENCED]
# Scenario: Third-party transferTrace `benefits_record` to a third-party boundary when employment data
# Evidence: Verify the payload field `benefits_record`, outbound call site, destination/vendor, and wh
# ==============================================================================
def test_case_emp_070():
    """Test scenario for EMP-070: benefits_record"""
    # ACTIVE TEST CASE: Represents identifiable user data
    benefits_record = "active_sample_value_for_benefits_record"
    payload = {
        "user_id": "USR_99214_TEST",
        "benefits_record": benefits_record,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-071] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `employee_id` when salary stored as a range
# Evidence: Record the observed representation and protection/transform function for `employee_id`; di
# ==============================================================================
def test_case_emp_071():
    """Test scenario for EMP-071: employee_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    employee_id = "active_sample_value_for_employee_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "employee_id": employee_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-072] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `salary_record` when employee ID changes ac
# Evidence: Record the observed representation and protection/transform function for `salary_record`; 
# ==============================================================================
def test_case_emp_072():
    """Test scenario for EMP-072: salary_record"""
    # ACTIVE TEST CASE: Represents identifiable user data
    salary_record = "active_sample_value_for_salary_record"
    payload = {
        "user_id": "USR_99214_TEST",
        "salary_record": salary_record,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-073] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `payroll_details` when employment history n
# Evidence: Record the observed representation and protection/transform function for `payroll_details`
# ==============================================================================
def test_case_emp_073():
    """Test scenario for EMP-073: payroll_details"""
    # ACTIVE TEST CASE: Represents identifiable user data
    payroll_details = "active_sample_value_for_payroll_details"
    payload = {
        "user_id": "USR_99214_TEST",
        "payroll_details": payroll_details,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-074] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `resume` when payroll data included in a ge
# Evidence: Record the observed representation and protection/transform function for `resume`; disting
# ==============================================================================
def test_case_emp_074():
    """Test scenario for EMP-074: resume"""
    # ACTIVE TEST CASE: Represents identifiable user data
    resume = "active_sample_value_for_resume"
    payload = {
        "user_id": "USR_99214_TEST",
        "resume": resume,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-075] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `employment_history` when HR export sent to
# Evidence: Record the observed representation and protection/transform function for `employment_histo
# ==============================================================================
def test_case_emp_075():
    """Test scenario for EMP-075: employment_history"""
    # ACTIVE TEST CASE: Represents identifiable user data
    employment_history = "active_sample_value_for_employment_history"
    payload = {
        "user_id": "USR_99214_TEST",
        "employment_history": employment_history,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-076] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `job_title` when employee details included 
# Evidence: Record the observed representation and protection/transform function for `job_title`; dist
# ==============================================================================
def test_case_emp_076():
    """Test scenario for EMP-076: job_title"""
    # ACTIVE TEST CASE: Represents identifiable user data
    job_title = "active_sample_value_for_job_title"
    payload = {
        "user_id": "USR_99214_TEST",
        "job_title": job_title,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-077] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `compensation` when job title inferred from
# Evidence: Record the observed representation and protection/transform function for `compensation`; d
# ==============================================================================
def test_case_emp_077():
    """Test scenario for EMP-077: compensation"""
    # ACTIVE TEST CASE: Represents identifiable user data
    compensation = "active_sample_value_for_compensation"
    payload = {
        "user_id": "USR_99214_TEST",
        "compensation": compensation,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-078] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `manager_id` when employee record encrypted
# Evidence: Record the observed representation and protection/transform function for `manager_id`; dis
# ==============================================================================
def test_case_emp_078():
    """Test scenario for EMP-078: manager_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    manager_id = "active_sample_value_for_manager_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "manager_id": manager_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-079] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `hr_profile` when field exists only in an o
# Evidence: Record the observed representation and protection/transform function for `hr_profile`; dis
# ==============================================================================
def test_case_emp_079():
    """Test scenario for EMP-079: hr_profile"""
    # ACTIVE TEST CASE: Represents identifiable user data
    hr_profile = "active_sample_value_for_hr_profile"
    payload = {
        "user_id": "USR_99214_TEST",
        "hr_profile": hr_profile,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-080] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
# Scenario: Masked, encrypted, or pseudonymous dataInspect `benefits_record` when employment data join
# Evidence: Record the observed representation and protection/transform function for `benefits_record`
# ==============================================================================
def test_case_emp_080():
    """Test scenario for EMP-080: benefits_record"""
    # ACTIVE TEST CASE: Represents identifiable user data
    benefits_record = "active_sample_value_for_benefits_record"
    payload = {
        "user_id": "USR_99214_TEST",
        "benefits_record": benefits_record,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-081] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `employee ID in fictional d
# Evidence: Verify that the only evidence is `employee ID in fictional demo` and that no populated, us
# ==============================================================================
def test_case_emp_081():
    """Test scenario for EMP-081: employee ID in fictional demo"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_employee_ID_in_fictional_demo = "MOCK_NON_PII_LITERAL_EMPLOYEE_ID_IN_FICTIONAL_DEMO"
    unrelated_system_config = {
        "config_key": "employee ID in fictional demo",
        "is_pii": False,
        "value": dummy_employee_ID_in_fictional_demo
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: EMP-082] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `role used for access contr
# Evidence: Verify that the only evidence is `role used for access control` and that no populated, use
# ==============================================================================
def test_case_emp_082():
    """Test scenario for EMP-082: role used for access control"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_role_used_for_access_control = "MOCK_NON_PII_LITERAL_ROLE_USED_FOR_ACCESS_CONTROL"
    unrelated_system_config = {
        "config_key": "role used for access control",
        "is_pii": False,
        "value": dummy_role_used_for_access_control
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: EMP-083] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `job title in a public job 
# Evidence: Verify that the only evidence is `job title in a public job advert` and that no populated,
# ==============================================================================
def test_case_emp_083():
    """Test scenario for EMP-083: job title in a public job advert"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_job_title_in_a_public_job_advert = "MOCK_NON_PII_LITERAL_JOB_TITLE_IN_A_PUBLIC_JOB_ADVERT"
    unrelated_system_config = {
        "config_key": "job title in a public job advert",
        "is_pii": False,
        "value": dummy_job_title_in_a_public_job_advert
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: EMP-084] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `company-wide aggregate sal
# Evidence: Verify that the only evidence is `company-wide aggregate salary statistic` and that no pop
# ==============================================================================
def test_case_emp_084():
    """Test scenario for EMP-084: company-wide aggregate salary statistic"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_company_wide_aggregate_salary_statistic = "MOCK_NON_PII_LITERAL_COMPANY_WIDE_AGGREGATE_SALARY_STATISTIC"
    unrelated_system_config = {
        "config_key": "company-wide aggregate salary statistic",
        "is_pii": False,
        "value": dummy_company_wide_aggregate_salary_statistic
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: EMP-085] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `HR field never populated` 
# Evidence: Verify that the only evidence is `HR field never populated` and that no populated, user-li
# ==============================================================================
def test_case_emp_085():
    """Test scenario for EMP-085: HR field never populated"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_HR_field_never_populated = "MOCK_NON_PII_LITERAL_HR_FIELD_NEVER_POPULATED"
    unrelated_system_config = {
        "config_key": "HR field never populated",
        "is_pii": False,
        "value": dummy_HR_field_never_populated
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: EMP-086] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `generic manager variable` 
# Evidence: Verify that the only evidence is `generic manager variable` and that no populated, user-li
# ==============================================================================
def test_case_emp_086():
    """Test scenario for EMP-086: generic manager variable"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_generic_manager_variable = "MOCK_NON_PII_LITERAL_GENERIC_MANAGER_VARIABLE"
    unrelated_system_config = {
        "config_key": "generic manager variable",
        "is_pii": False,
        "value": dummy_generic_manager_variable
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: EMP-087] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `sample résumé in tests` ap
# Evidence: Verify that the only evidence is `sample résumé in tests` and that no populated, user-link
# ==============================================================================
def test_case_emp_087():
    """Test scenario for EMP-087: sample résumé in tests"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_sample_r_sum__in_tests = "MOCK_NON_PII_LITERAL_SAMPLE_R_SUM__IN_TESTS"
    unrelated_system_config = {
        "config_key": "sample résumé in tests",
        "is_pii": False,
        "value": dummy_sample_r_sum__in_tests
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: EMP-088] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `payroll keyword in documen
# Evidence: Verify that the only evidence is `payroll keyword in documentation` and that no populated,
# ==============================================================================
def test_case_emp_088():
    """Test scenario for EMP-088: payroll keyword in documentation"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_payroll_keyword_in_documentation = "MOCK_NON_PII_LITERAL_PAYROLL_KEYWORD_IN_DOCUMENTATION"
    unrelated_system_config = {
        "config_key": "payroll keyword in documentation",
        "is_pii": False,
        "value": dummy_payroll_keyword_in_documentation
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: EMP-089] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `public corporate switchboa
# Evidence: Verify that the only evidence is `public corporate switchboard` and that no populated, use
# ==============================================================================
def test_case_emp_089():
    """Test scenario for EMP-089: public corporate switchboard"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_public_corporate_switchboard = "MOCK_NON_PII_LITERAL_PUBLIC_CORPORATE_SWITCHBOARD"
    unrelated_system_config = {
        "config_key": "public corporate switchboard",
        "is_pii": False,
        "value": dummy_public_corporate_switchboard
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: EMP-090] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Scenario: Documentation, fixtures, and unrelated tokensNegative control: `mock benefits record` appe
# Evidence: Verify that the only evidence is `mock benefits record` and that no populated, user-linked
# ==============================================================================
def test_case_emp_090():
    """Test scenario for EMP-090: mock benefits record"""
    # TRAP / NEGATIVE CONTROL: Scanner must NOT confirm this as PII
    # Context: Unrelated mock fixture, math keyword, or operational token
    dummy_mock_benefits_record = "MOCK_NON_PII_LITERAL_MOCK_BENEFITS_RECORD"
    unrelated_system_config = {
        "config_key": "mock benefits record",
        "is_pii": False,
        "value": dummy_mock_benefits_record
    }
    return unrelated_system_config

# ==============================================================================
# [TEST_ID: EMP-091] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `employee_id`: 
# Evidence: Record the exact `employee_id` source location, available type/context, missing runtime or
# ==============================================================================
def test_case_emp_091():
    """Test scenario for EMP-091: employee_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    employee_id = "active_sample_value_for_employee_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "employee_id": employee_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-092] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `salary_record`
# Evidence: Record the exact `salary_record` source location, available type/context, missing runtime 
# ==============================================================================
def test_case_emp_092():
    """Test scenario for EMP-092: salary_record"""
    # ACTIVE TEST CASE: Represents identifiable user data
    salary_record = "active_sample_value_for_salary_record"
    payload = {
        "user_id": "USR_99214_TEST",
        "salary_record": salary_record,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-093] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `payroll_detail
# Evidence: Record the exact `payroll_details` source location, available type/context, missing runtim
# ==============================================================================
def test_case_emp_093():
    """Test scenario for EMP-093: payroll_details"""
    # ACTIVE TEST CASE: Represents identifiable user data
    payroll_details = "active_sample_value_for_payroll_details"
    payload = {
        "user_id": "USR_99214_TEST",
        "payroll_details": payroll_details,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-094] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `resume`: payro
# Evidence: Record the exact `resume` source location, available type/context, missing runtime or link
# ==============================================================================
def test_case_emp_094():
    """Test scenario for EMP-094: resume"""
    # ACTIVE TEST CASE: Represents identifiable user data
    resume = "active_sample_value_for_resume"
    payload = {
        "user_id": "USR_99214_TEST",
        "resume": resume,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-095] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `employment_his
# Evidence: Record the exact `employment_history` source location, available type/context, missing run
# ==============================================================================
def test_case_emp_095():
    """Test scenario for EMP-095: employment_history"""
    # ACTIVE TEST CASE: Represents identifiable user data
    employment_history = "active_sample_value_for_employment_history"
    payload = {
        "user_id": "USR_99214_TEST",
        "employment_history": employment_history,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-096] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `job_title`: em
# Evidence: Record the exact `job_title` source location, available type/context, missing runtime or l
# ==============================================================================
def test_case_emp_096():
    """Test scenario for EMP-096: job_title"""
    # ACTIVE TEST CASE: Represents identifiable user data
    job_title = "active_sample_value_for_job_title"
    payload = {
        "user_id": "USR_99214_TEST",
        "job_title": job_title,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-097] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `compensation`:
# Evidence: Record the exact `compensation` source location, available type/context, missing runtime o
# ==============================================================================
def test_case_emp_097():
    """Test scenario for EMP-097: compensation"""
    # ACTIVE TEST CASE: Represents identifiable user data
    compensation = "active_sample_value_for_compensation"
    payload = {
        "user_id": "USR_99214_TEST",
        "compensation": compensation,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-098] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `manager_id`: e
# Evidence: Record the exact `manager_id` source location, available type/context, missing runtime or 
# ==============================================================================
def test_case_emp_098():
    """Test scenario for EMP-098: manager_id"""
    # ACTIVE TEST CASE: Represents identifiable user data
    manager_id = "active_sample_value_for_manager_id"
    payload = {
        "user_id": "USR_99214_TEST",
        "manager_id": manager_id,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-099] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `hr_profile`: f
# Evidence: Record the exact `hr_profile` source location, available type/context, missing runtime or 
# ==============================================================================
def test_case_emp_099():
    """Test scenario for EMP-099: hr_profile"""
    # ACTIVE TEST CASE: Represents identifiable user data
    hr_profile = "active_sample_value_for_hr_profile"
    payload = {
        "user_id": "USR_99214_TEST",
        "hr_profile": hr_profile,
        "is_active_pii": True
    }
    return payload

# ==============================================================================
# [TEST_ID: EMP-100] [EXPECTED: POTENTIAL FINDING WITH UNCERTAINTY]
# Scenario: Ambiguous, incomplete, or runtime-only evidenceAmbiguous-evidence case for `benefits_recor
# Evidence: Record the exact `benefits_record` source location, available type/context, missing runtim
# ==============================================================================
def test_case_emp_100():
    """Test scenario for EMP-100: benefits_record"""
    # ACTIVE TEST CASE: Represents identifiable user data
    benefits_record = "active_sample_value_for_benefits_record"
    payload = {
        "user_id": "USR_99214_TEST",
        "benefits_record": benefits_record,
        "is_active_pii": True
    }
    return payload
