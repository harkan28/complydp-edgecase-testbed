"""
COMPLYDP PII DETECTION TESTBED — HEALTH & MEDICAL SERVICE
Tests health data detection and ABHA substring collision traps.
"""

from typing import Dict, Any, List

class PatientHealthService:
    def __init__(self):
        # [TC: HLT-081] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
        # 'abha' substring collision in Indian surname 'Sabharwal'
        self.consultation_directory = [
            {"doctor": "Dr. Sharma", "patient_name": "Anika Sabharwal", "department": "Cardiology"},
            {"doctor": "Dr. Mehta", "patient_name": "Raunak Sabharwal", "department": "Pediatrics"},
            {"doctor": "Dr. Verma", "patient_name": "Pooja Sabharwal", "department": "Dermatology"}
        ]

    def record_patient_encounter(self, patient_id: str, diagnosis: str, 
                                 prescription: str, blood_group: str) -> Dict[str, Any]:
        """
        [TC: HLT-001, HLT-002] [EXPECTED: DETECT POTENTIAL PII]
        Records clinical diagnosis and prescription details linked to an identifiable patient.
        """
        medical_record = {
            "patient_id": patient_id,                      # Patient Identifier
            "medical_record_number": f"MRN-{patient_id}",  # Medical Record Number
            "diagnosis": diagnosis,                        # Health condition
            "prescription": prescription,                  # Prescription drugs
            "blood_group": blood_group,                    # Health demographic
            "abha_id": "91-1234-5678-9012",                # Ayushman Bharat Health Account
            "insurance_claim_id": "CLM-99214-HEALTH"       # Medical insurance claim
        }
        return medical_record

    def check_infrastructure_health(self) -> Dict[str, str]:
        """
        [TC: HLT-082] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
        System healthcheck endpoint (/healthz). Must NOT be flagged as medical PII.
        """
        return {"status": "HEALTHY", "service": "health_api", "system_health": "UP"}
