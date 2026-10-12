"""
COMPLYDP PII DETECTION TESTBED — COMMUNICATION & BEHAVIORAL LOGGER
Tests communication content and activity logs (SMS bodies, messages, call logs).
"""

from typing import Dict, Any, List

class CommunicationAuditLogger:
    def log_inbound_communication(self, user_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        [TC: COM-001, COM-002] [EXPECTED: DETECT POTENTIAL PII]
        Ingests user communication payloads and interaction logs.
        """
        event = {
            "user_id": user_id,
            "sms_body": "Your bank verification code is 591240. Valid for 10 minutes.", # SMS text
            "message_content": "Can you please confirm my order delivery status?",      # Message body
            "call_log": "+91-9876543210 (Duration: 3m 42s)",                            # Call records
            "conversation_history": "Customer support chat transcript between user and agent",
            "browsing_history": ["/dashboard/savings", "/investments/gold", "/profile/kyc"]
        }
        return event
