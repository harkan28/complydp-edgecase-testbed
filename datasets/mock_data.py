"""
COMPLYDP PII DETECTION TESTBED — SYNTHETIC DATASETS & MOCK FIXTURES
Tests the scanner against substring stemming collisions and mock category label confusion.

FALSE POSITIVE TRAP TEST CASES COVERED:
- [FIN-081] 'pran' matched inside human name 'Pranay'
- [HLT-081] 'abha' matched inside Indian surname 'Sabharwal'
- [EMP-081] 'ESIC' matched in mock government portal merchant array
- [GOV-083] 'Passport Seva' matched in mock government merchant array
- [ID-082]  'vehicle registration' matched as an expense category label
- [GOV-084] 'Aadhaar Center' matched in mock utility center list
"""

import csv
from typing import List, Dict

# ==============================================================================
# 1. SUBSTRING COLLISION FIXTURES (Indian Synthetic Names)
# ==============================================================================

MOCK_TRANSACTIONS = [
    # [TC: FIN-081] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
    # 'pran' substring collision in 'Pranay Gopal' — NPS PRAN does NOT exist
    {"txn_id": "TXN-1001", "sender": "Pranay Gopal", "upi": "pranay@okaxis", "amount": 1450.00},
    {"txn_id": "TXN-1002", "sender": "Pranay Bala", "upi": "pranay.b@okhdfcbank", "amount": 250.00},

    # [TC: HLT-081] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
    # 'abha' substring collision in 'Anika Sabharwal' — ABHA health ID does NOT exist
    {"txn_id": "TXN-1003", "sender": "Anika Sabharwal", "upi": "anika.s@okicici", "amount": 5400.00},
    {"txn_id": "TXN-1004", "sender": "Raunak Sabharwal", "upi": "raunak@okybl", "amount": 890.00},
]

# ==============================================================================
# 2. MOCK EXPENSE CATEGORIES & MERCHANT STRING LITERALS (Semantic Confusion Traps)
# ==============================================================================

# [TC: ID-082] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Mock expense subcategory labels. 'vehicle registration' is a category, NOT a plate number
VEHICLE_EXPENSE_CATEGORIES = [
    'fuel refill',
    'insurance renewal',
    'vehicle registration',  # Expense label, not vehicle RC PII
    'pollution certificate',
    'toll payment'
]

# [TC: GOV-083, EMP-081, GOV-084] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
# Mock government utility merchant strings.
# Must NOT be flagged as live Passport numbers, ESIC insurance IDs, or Aadhaar records
GOVERNMENT_PORTAL_MERCHANTS = [
    'Income Tax Department',
    'GST Portal',
    'MCA Portal',
    'EPFO Portal',
    'ESIC Office',          # Merchant string, not 17-digit ESIC employee insurance ID
    'PF Office',
    'Passport Seva',        # Merchant string, not passport document number
    'Aadhaar Center',       # Merchant string, not 12-digit Aadhaar national ID
    'Jan Aushadhi Kendra'
]

MOCK_GOVERNMENT_FEE_TYPES = [
    'Passport Fee',         # Fee classification, not personal passport PII
    'Visa Fee',
    'Driving License Fee',
    'Registration Fee',
    'Court Fee'
]
