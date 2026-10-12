"""
COMPLYDP PII DETECTION TESTBED — DATA MODELS & ENTITIES
Maps to object-level and AST scanner rules across all 15 categories.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import date, datetime

# ==============================================================================
# 1. PERSONAL IDENTITY & CONTACT MODELS (ID, CON, DEM)
# ==============================================================================

@dataclass
class UserProfile:
    """
    [ID-001, ID-002] [EXPECTED: DETECT POTENTIAL PII]
    Represents direct identity attributes of an active system user.
    """
    user_id: str
    full_name: str
    first_name: str
    last_name: str
    email: str
    mobile_no: str
    age: int
    birth_date: date
    gender: str
    emergency_contact: Optional[str] = None
    residential_address: Optional[str] = None
    postal_code: Optional[str] = None

# ==============================================================================
# 2. GOVERNMENT & FINANCIAL IDENTIFIER MODELS (GOV, FIN, PAY)
# ==============================================================================

@dataclass
class GovernmentKYCProfile:
    """
    [GOV-001, GOV-002, GOV-003] [EXPECTED: DETECT POTENTIAL PII]
    Represents government identity records linked to KYC onboarding.
    """
    user_id: str
    aadhaar_number: str
    pan_number: str
    passport_number: str
    driving_license: Optional[str] = None
    voter_id: Optional[str] = None

@dataclass
class FinancialAccountProfile:
    """
    [FIN-001, PAY-001, PAY-002] [EXPECTED: DETECT POTENTIAL PII]
    Financial and payment tracking data structures.
    """
    user_id: str
    annual_income: float
    monthly_salary: float
    credit_score: int
    bank_account_number: str
    ifsc_code: str
    upi_id: str
    risk_profile: str
    investment_timeline_years: int
    financial_goals: List[str] = field(default_factory=list)

# ==============================================================================
# 3. HEALTH, BIOMETRICS & EMPLOYMENT MODELS (HLT, BIO, EMP, EDU)
# ==============================================================================

@dataclass
class MedicalRecordEntry:
    """
    [HLT-001, HLT-002] [EXPECTED: DETECT POTENTIAL PII]
    Protected health information linked to patients.
    """
    patient_id: str
    medical_record_number: str
    diagnosis: str
    prescription_details: str
    insurance_claim_id: str
    blood_group: str

@dataclass
class BiometricPayload:
    """
    [BIO-001, BIO-002] [EXPECTED: DETECT POTENTIAL PII]
    Biometric templates and embedding records.
    """
    user_id: str
    face_id: str
    face_embedding: bytes
    fingerprint_minutiae: bytes
    iris_scan: bytes

@dataclass
class EmploymentRecord:
    """
    [EMP-001, EMP-002] [EXPECTED: DETECT POTENTIAL PII]
    Corporate payroll and employee identities.
    """
    employee_id: str
    uan_number: str
    esic_number: str
    company_name: str
    payroll_details: str
    designation: str

@dataclass
class EducationRecord:
    """
    [EDU-001, EDU-002] [EXPECTED: DETECT POTENTIAL PII]
    Academic records and student evaluations.
    """
    student_id: str
    institution_name: str
    qualification: str
    exam_result: str
    grade_point_average: float

# ==============================================================================
# 4. DIGITAL, COMMUNICATIONS & DERIVED MODELS (DIG, LOC, COM, DER)
# ==============================================================================

@dataclass
class DigitalTelemetryRecord:
    """
    [DIG-001, LOC-001] [EXPECTED: DETECT POTENTIAL PII]
    Device and spatial telemetry.
    """
    user_id: str
    ip_address: str
    device_id: str
    cookie_id: str
    latitude: float
    longitude: float
    current_location: str

@dataclass
class CommunicationRecord:
    """
    [COM-001, DER-001] [EXPECTED: DETECT POTENTIAL PII]
    Ingested user interaction and derived behavioral scores.
    """
    user_id: str
    sms_body: str
    message_content: str
    customer_score: float
    predicted_income_band: str
    investment_persona: str
