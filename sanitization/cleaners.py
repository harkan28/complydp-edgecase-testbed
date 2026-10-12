"""
COMPLYDP PII DETECTION TESTBED — DATA SANITIZATION & REDACTION ROUTINES
Tests the scanner's ability to differentiate between data sanitization (re.sub)
and active PII collection/storage.

NEGATIVE CONTROLS & TRAP TEST CASES:
- [CON-081] Negative Control: Pincode regex used exclusively for data sanitization
- [GOV-081] Negative Control: Aadhaar masking routine
- [FIN-081] Negative Control: Bank account truncation
"""

import re
from typing import str

def sanitize_merchant_name(raw_merchant_text: str) -> str:
    """
    [TC: CON-081] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
    Strip trailing Indian 6-digit postal pincodes from merchant descriptions.
    The scanner MUST recognize that re.sub() strips the pincode rather than storing it.
    """
    cleaned = raw_merchant_text.strip()
    # Pincode regex pattern used exclusively to DELETE postal codes
    pincode_pattern = r'\s+\d{6}$'  # pincode
    cleaned = re.sub(pincode_pattern, '', cleaned)
    return cleaned

def redact_phone_number(log_message: str) -> str:
    """
    [TC: CON-071] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
    Redact mobile numbers from inbound application log messages.
    """
    phone_pattern = r'(\+?91[\-\s]?)?[6-9]\d{9}'
    return re.sub(phone_pattern, '[PHONE_REDACTED]', log_message)

def mask_bank_account_number(account_number: str) -> str:
    """
    [TC: PAY-071] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
    Mask all but the last 4 digits of a bank account.
    """
    if len(account_number) <= 4:
        return "XXXX"
    return "X" * (len(account_number) - 4) + account_number[-4:]

def mask_aadhaar_number(aadhaar_number: str) -> str:
    """
    [TC: GOV-071] [EXPECTED: DETECT TYPE; QUALIFY VALUE VISIBILITY]
    Mask the first 8 digits of a 12-digit Aadhaar number per UIDAI compliance.
    """
    cleaned = re.sub(r'[\s\-]', '', aadhaar_number)
    if len(cleaned) == 12:
        return f"XXXX-XXXX-{cleaned[-4:]}"
    return "XXXX-XXXX-XXXX"

def strip_tax_identifiers(payload_text: str) -> str:
    """
    [TC: GOV-082] [EXPECTED: DO NOT FLAG AS CONFIRMED PII]
    Delete PAN/tax identifiers before forwarding telemetry payloads.
    """
    pan_regex = r'[A-Z]{5}[0-9]{4}[A-Z]'
    return re.sub(pan_regex, '[TAX_ID_REMOVED]', payload_text)
