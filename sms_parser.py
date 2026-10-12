"""
COMPLYDP PII DETECTION TESTBED — TRANSACTION SMS PARSER & SANITIZER
Implements regex extraction for bank SMS alerts and address cleaning.
Tests:
- True Positive: upi_id, account_number extraction from SMS
- False Positive Trap: pincode sanitization via re.sub()
"""

import re
from typing import Dict, Optional, Any

# Bank transactional SMS regex patterns
SMS_PATTERNS = [
    # UPI extraction pattern
    r"PhonePe: You paid Rs\.?(\d+\.?\d*) to (.+?) UPI ID: ([a-zA-Z0-9.\-_]+@[a-zA-Z]+) on ([\d\-]+)",
    # Bank account alert pattern
    r"Alert: Rs\.?(\d+\.?\d*) debited from A/c XX(\d{4}) to (.+?) on ([\d\-]+)",
]

def clean_merchant_address(merchant_string: str) -> str:
    """
    [TC: CON-081] Pincode regex sanitization trap.
    Strips trailing 6-digit postal pincode from merchant strings.
    """
    pattern = r'\s+\d{6}$'  # pincode
    cleaned = re.sub(pattern, '', merchant_string.strip())
    return cleaned

def parse_bank_sms(sms_text: str) -> Dict[str, Any]:
    """Extracts amount, account_number, and upi_id from SMS body."""
    for pattern in SMS_PATTERNS:
        match = re.search(pattern, sms_text)
        if match:
            groups = match.groups()
            return {
                "amount": float(groups[0]),
                "merchant": clean_merchant_address(groups[1]),
                "upi_id": groups[2] if len(groups) > 2 else None,
                "account_number": groups[1] if "debited" in sms_text else None
            }
    return {}
