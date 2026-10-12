"""
COMPLYDP PII DETECTION TESTBED — SYNTHETIC DATASET GENERATOR
Generates mock machine learning training records for expense categorization.
Tests whether the scanner mistakes mock merchant strings and expense categories for personal PII.
"""

import random
from typing import List, Dict

# [TC: ID-082] Expense category label string — NOT a personal vehicle registration plate
EXPENSE_CATEGORIES = [
    'fuel refill',
    'insurance renewal',
    'vehicle registration',  # Mock category tag
    'pollution certificate',
    'toll charges'
]

# [TC: GOV-083, EMP-081, GOV-084] Mock government merchants — NOT personal government IDs
GOVERNMENT_SERVICES_MERCHANTS = [
    'Income Tax Department',
    'GST Portal',
    'MCA Portal',
    'EPFO',
    'ESIC',                  # Mock portal string, not 17-digit employee insurance ID
    'PF Office',
    'Passport Seva',         # Mock portal string, not passport document number
    'Aadhaar Center',        # Mock center string, not 12-digit Aadhaar national ID
    'Jan Aushadhi Kendra'
]

GOVERNMENT_FEE_TYPES = [
    'Passport Fee',          # Fee label, not passport PII
    'Visa Fee',
    'License Fee',
    'Registration Fee',
    'Court Fee'
]

def generate_mock_expense_record() -> Dict[str, Any]:
    return {
        "merchant": random.choice(GOVERNMENT_SERVICES_MERCHANTS),
        "category": random.choice(EXPENSE_CATEGORIES),
        "fee_type": random.choice(GOVERNMENT_FEE_TYPES),
        "amount": round(random.uniform(100.0, 5000.0), 2)
    }
