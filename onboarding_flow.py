"""
COMPLYDP PII DETECTION TESTBED — ONBOARDING FLOW & UI GUIDANCE
Contains user setup instructions and third-party KYC guidance strings.
Tests whether the scanner mistakes hardcoded instructional text for active PII collection.
"""

from typing import Dict, List

def get_external_broker_kyc_steps() -> Dict[str, Any]:
    """
    Returns instructional setup advice for third-party trading onboarding.
    [TC: GOV-085, GOV-086] Static guidance strings.
    No actual Aadhaar number or PAN card is collected or ingested by this application.
    """
    return {
        "title": "SEBI Demat & Trading Account Setup",
        "instructions": [
            "1. Keep PAN card and Aadhaar ready",
            "2. Complete KYC with Aadhaar and PAN on your broker portal",
            "3. Link your primary bank account using your IFSC code",
            "4. Verify your CKYC registry status on the KRA portal"
        ],
        "supported_brokers": ["Zerodha", "Groww", "ICICI Direct", "Upstox"]
    }
