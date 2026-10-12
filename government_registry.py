"""
COMPLYDP PII DETECTION TESTBED — GOVERNMENT REGISTRY & KYC MODULE
Tests national identifiers (Aadhaar, PAN, Passport, ESIC, CKYC, Voter ID, Driving License).
"""

from typing import Dict, Any, List

# [TC: EMP-081, GOV-083] Mock portal merchant lists (False Positive Traps)
MOCK_GOVERNMENT_PORTALS = [
    'Income Tax Department',
    'GST Portal',
    'MCA Portal',
    'EPFO Portal',
    'ESIC Office',           # Mock merchant literal, NOT an employee insurance ID
    'Passport Seva Kendra',  # Mock merchant literal, NOT a personal passport number
    'Aadhaar Enrolment Hub'  # Mock merchant literal, NOT an Aadhaar number
]

MOCK_FEE_DESCRIPTIONS = [
    'Passport Fee',          # Fee description, not passport document
    'Visa Processing Fee',
    'Driving License Test Fee'
]

class GovernmentDocumentRegistry:
    def __init__(self):
        self.portals = MOCK_GOVERNMENT_PORTALS

    def verify_citizen_credentials(self, user_id: str) -> Dict[str, Any]:
        """
        [TC: GOV-001, GOV-002, GOV-003, GOV-004]
        Active government identifier profile linked to an identifiable individual.
        """
        citizen_profile = {
            "user_id": user_id,
            "aadhaar_number": "2345 6789 0123",            # 12-digit Aadhaar UID
            "pan_number": "ABCDE1234F",                     # 10-digit Indian Permanent Account Number
            "passport_number": "M1234567",                  # Indian Passport document number
            "passport_no": "M1234567",
            "driving_license": "DL-0420110012345",          # State driving license
            "voter_id": "ABC1234567",                       # Electoral photo identity card
            "esic_number": "11223344556677889",             # 17-digit ESIC employee insurance ID
            "ckyc_number": "10029384756102",                # 14-digit Central KYC registry ID
            "tax_id": "TX-991204-IN"
        }
        return citizen_profile
