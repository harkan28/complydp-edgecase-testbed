"""
COMPLYDP TESTBED — ACTIVE PRODUCTION PII SERVICES
Contains operational, production-style implementations of real PII entities.
This module is designed to test whether ComplyDP detects genuine, active PII
in contrast to synthetic false-positive traps.
"""

import re
import datetime
from typing import Dict, Any, List, Optional

# ==============================================================================
# 1. GOVERNMENT & NATIONAL IDENTIFIERS (REAL PII IMPLEMENTATIONS)
# ==============================================================================

class RealAadhaarIdentityService:
    """Production service for ingesting and validating active Indian Aadhaar numbers."""
    def __init__(self):
        self.aadhaar_storage: Dict[str, str] = {}

    def ingest_and_store_aadhaar(self, user_id: str, raw_aadhaar_number: str) -> Dict[str, Any]:
        # Real 12-digit Aadhaar regex validation
        cleaned = re.sub(r'[\s\-]', '', raw_aadhaar_number)
        if not re.match(r'^[2-9]\d{11}$', cleaned):
            raise ValueError("Invalid Aadhaar number format")
        
        self.aadhaar_storage[user_id] = cleaned
        return {
            "user_id": user_id,
            "aadhaar_number": cleaned,
            "status": "STORED_ACTIVE_PII",
            "verified_at": datetime.datetime.utcnow().isoformat()
        }

class RealPANCardService:
    """Production service for storing and assessing Indian Income Tax PAN credentials."""
    def __init__(self):
        self.pan_registry: Dict[str, str] = {}

    def register_user_pan(self, user_id: str, pan_card_number: str) -> Dict[str, Any]:
        # Real 10-character alphanumeric PAN regex: 5 letters, 4 digits, 1 letter
        pan_clean = pan_card_number.strip().upper()
        if not re.match(r'^[A-Z]{5}[0-9]{4}[A-Z]$', pan_clean):
            raise ValueError("Invalid PAN card format")
        
        self.pan_registry[user_id] = pan_clean
        return {
            "user_id": user_id,
            "pan_number": pan_clean,
            "tax_jurisdiction": "INCOME_TAX_INDIA",
            "is_tax_payer": True
        }

class RealPassportService:
    """Production service storing genuine Indian passport travel identity records."""
    def __init__(self):
        self.passport_database: Dict[str, Dict[str, Any]] = {}

    def issue_passport_profile(self, user_id: str, passport_number: str, expiry_date: str) -> Dict[str, Any]:
        # Real Indian Passport regex: 1 letter followed by 7 digits
        clean_no = passport_number.strip().upper()
        if not re.match(r'^[A-Z][0-9]{7}$', clean_no):
            raise ValueError("Invalid Indian passport number format")
        
        record = {
            "passport_number": clean_no,
            "expiry_date": expiry_date,
            "issuing_authority": "GOVERNMENT_OF_INDIA",
            "travel_document_type": "REGULAR_PASSPORT"
        }
        self.passport_database[user_id] = record
        return record

class RealDrivingLicenseService:
    """Production service for Indian motor driving license verification."""
    def __init__(self):
        self.dl_records: Dict[str, str] = {}

    def record_driving_license(self, user_id: str, dl_number: str) -> Dict[str, Any]:
        clean_dl = dl_number.strip().upper()
        self.dl_records[user_id] = clean_dl
        return {"user_id": user_id, "driving_license": clean_dl, "verified": True}

class RealVoterIDService:
    """Production service for Indian Election Commission EPIC voter card records."""
    def __init__(self):
        self.voter_db: Dict[str, str] = {}

    def record_voter_identity(self, user_id: str, epic_number: str) -> Dict[str, Any]:
        clean_epic = epic_number.strip().upper()
        self.voter_db[user_id] = clean_epic
        return {"user_id": user_id, "voter_id": clean_epic, "voting_eligible": True}

class RealVehicleRCService:
    """Production service for storing actual vehicle registration RC plate numbers."""
    def __init__(self):
        self.vehicle_registry: Dict[str, str] = {}

    def register_motor_vehicle(self, user_id: str, plate_number: str) -> Dict[str, Any]:
        # Real Indian RC plate: e.g. MH02CB1234
        clean_rc = re.sub(r'[\s\-]', '', plate_number).upper()
        self.vehicle_registry[user_id] = clean_rc
        return {
            "user_id": user_id,
            "vehicle_registration": clean_rc,
            "rc_status": "ACTIVE_MOTOR_VEHICLE"
        }

# ==============================================================================
# 2. FINANCIAL, PAYMENT & RETIREMENT IDENTIFIERS (REAL PII)
# ==============================================================================

class RealBankingPaymentService:
    """Production service for bank accounts, UPI IDs, and IFSC routing."""
    def __init__(self):
        self.bank_accounts: Dict[str, str] = {}
        self.upi_directory: Dict[str, str] = {}

    def link_savings_bank_account(self, user_id: str, account_number: str, ifsc_code: str) -> Dict[str, Any]:
        clean_acc = account_number.strip()
        clean_ifsc = ifsc_code.strip().upper()
        if not re.match(r'^[A-Z]{4}0[A-Z0-9]{6}$', clean_ifsc):
            raise ValueError("Invalid IFSC bank code")
        
        self.bank_accounts[user_id] = clean_acc
        return {
            "user_id": user_id,
            "bank_account_number": clean_acc,
            "ifsc_code": clean_ifsc,
            "routing_type": "NEFT_RTGS_IMPS"
        }

    def register_upi_vpa(self, user_id: str, vpa_address: str) -> Dict[str, Any]:
        clean_upi = vpa_address.strip().lower()
        if '@' not in clean_upi:
            raise ValueError("Invalid UPI ID")
        
        self.upi_directory[user_id] = clean_upi
        return {"user_id": user_id, "upi_id": clean_upi, "status": "VPA_ACTIVE"}

class RealNPSPRANService:
    """Production National Pension System (NPS) PRAN account manager."""
    def __init__(self):
        self.pran_records: Dict[str, str] = {}

    def register_pran_pension_account(self, user_id: str, pran_number: str) -> Dict[str, Any]:
        # Real 12-digit NPS PRAN number
        clean_pran = pran_number.strip()
        if not re.match(r'^\d{12}$', clean_pran):
            raise ValueError("Invalid 12-digit NPS PRAN number")
        
        self.pran_records[user_id] = clean_pran
        return {
            "user_id": user_id,
            "pran_number": clean_pran,
            "scheme": "NATIONAL_PENSION_SYSTEM",
            "tier_1_active": True
        }

class RealEPFOUANService:
    """Production EPFO Universal Account Number (UAN) manager."""
    def __init__(self):
        self.uan_records: Dict[str, str] = {}

    def link_epfo_uan(self, user_id: str, uan_number: str) -> Dict[str, Any]:
        # Real 12-digit EPFO UAN number
        clean_uan = uan_number.strip()
        if not re.match(r'^\d{12}$', clean_uan):
            raise ValueError("Invalid 12-digit EPFO UAN number")
        
        self.uan_records[user_id] = clean_uan
        return {
            "user_id": user_id,
            "uan_number": clean_uan,
            "provident_fund_active": True
        }

class RealCKYCRegistryService:
    """Production Central KYC (CKYC) registry identifier client."""
    def __init__(self):
        self.ckyc_records: Dict[str, str] = {}

    def fetch_ckyc_profile(self, user_id: str, ckyc_number: str) -> Dict[str, Any]:
        # Real 14-digit CKYC registry number
        clean_ckyc = ckyc_number.strip()
        if not re.match(r'^\d{14}$', clean_ckyc):
            raise ValueError("Invalid 14-digit CKYC identifier")
        
        self.ckyc_records[user_id] = clean_ckyc
        return {
            "user_id": user_id,
            "ckyc_number": clean_ckyc,
            "kyc_compliance": "CENTRAL_KYC_VERIFIED"
        }

# ==============================================================================
# 3. HEALTH & EMPLOYMENT SOCIAL SECURITY (REAL PII)
# ==============================================================================

class RealABHAHealthService:
    """Production Ayushman Bharat Digital Health Account (ABHA) service."""
    def __init__(self):
        self.health_records: Dict[str, Dict[str, Any]] = {}

    def create_abha_health_id(self, user_id: str, abha_number: str, blood_group: str) -> Dict[str, Any]:
        # Real 14-digit ABHA ID: XX-XXXX-XXXX-XXXX
        clean_abha = re.sub(r'[\s\-]', '', abha_number)
        record = {
            "user_id": user_id,
            "abha_number": clean_abha,
            "blood_group": blood_group,
            "diagnosis": "Hypertension Stage 1",
            "prescription": "Amlodipine 5mg OD",
            "health_facility": "AIIMS Digital Health Record"
        }
        self.health_records[user_id] = record
        return record

class RealESICInsuranceService:
    """Production Employee State Insurance Corporation (ESIC) service."""
    def __init__(self):
        self.esic_records: Dict[str, str] = {}

    def register_esic_insurance(self, user_id: str, esic_number: str) -> Dict[str, Any]:
        # Real 17-digit ESIC employee insurance code
        clean_esic = esic_number.strip()
        self.esic_records[user_id] = clean_esic
        return {
            "user_id": user_id,
            "esic_number": clean_esic,
            "medical_benefit_active": True
        }

# ==============================================================================
# 4. USER PROFILE & DEMOGRAPHIC IDENTITY (REAL PII)
# ==============================================================================

class RealUserProfileManager:
    """Production user profile service managing direct personal attributes."""
    def __init__(self):
        self.profiles: Dict[str, Dict[str, Any]] = {}

    def save_complete_user_profile(self, user_id: str, name: str, email: str, 
                                   phone: str, age: int, income: float, 
                                   pincode: str, address: str) -> Dict[str, Any]:
        profile = {
            "user_id": user_id,
            "full_name": name,
            "name": name,
            "email": email,
            "phone": phone,
            "mobile_no": phone,
            "age": age,
            "annual_income": income,
            "monthly_salary": income / 12.0,
            "risk_profile": "moderate_aggressive",
            "financial_goals": ["Buy Home", "Retirement Fund"],
            "pincode": pincode,
            "residential_address": address,
            "postal_address": address
        }
        self.profiles[user_id] = profile
        return profile
