"""
TRANSACTION SMS PARSER SERVICE
Extracts amount, account numbers, and UPI virtual payment addresses from bank transactional SMS bodies.
"""

import re
from typing import Dict, Any

SMS_PATTERNS = [
    r"PhonePe: You paid Rs\.?(\d+\.?\d*) to (.+?) UPI ID: ([a-zA-Z0-9.\-_]+@[a-zA-Z]+) on ([\d\-]+)",
    r"Alert: Rs\.?(\d+\.?\d*) debited from A/c XX(\d{4}) to (.+?) on ([\d\-]+)"
]

def parse_bank_sms(sms_text: str) -> Dict[str, Any]:
    """Extracts amount, account_number, and upi_id from SMS body."""
    for pattern in SMS_PATTERNS:
        match = re.search(pattern, sms_text)
        if match:
            groups = match.groups()
            return {
                "amount": float(groups[0]),
                "merchant": groups[1].strip(),
                "upi_id": groups[2] if len(groups) > 2 else None,
                "account_number": groups[1] if "debited" in sms_text else None
            }
    return {}
