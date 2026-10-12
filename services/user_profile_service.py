"""
COMPLYDP PII DETECTION TESTBED — USER PROFILE & PSYCHOMETRICS
Explicitly instantiates and processes user profile fields:
name, age, annual_income, risk_profile, goals, and behavioral personas.
"""

from typing import Dict, Any, List

class UserProfileService:
    def create_full_user_profile(self, user_id: str) -> Dict[str, Any]:
        """
        [Items 20, 21, 22, 23, 24] [EXPECTED: DETECT POTENTIAL PII]
        Active customer profile with personal, demographic, and financial fields.
        """
        profile = {
            "user_id": user_id,
            "full_name": "Harshit Rawal",                    # Item 20: Full Name
            "name": "Harshit Rawal",
            "first_name": "Harshit",
            "last_name": "Rawal",
            "displayName": "Harshit R.",
            "age": 29,                                       # Item 21: Demographics Age
            "user_age": 29,
            "date_of_birth": "1997-04-15",
            "gender": "Male",
            "annual_income": 1850000.00,                     # Item 22: Annual Income
            "monthly_salary": 154000.00,
            "net_worth": 4500000.00,
            "credit_score": 785,                             # Credit Score
            "risk_profile": "moderate_aggressive",           # Item 23: Risk Profile
            "investment_timeline": 10,                       # Item 24: Investment Timeline
            "financial_goals": ["Buy House", "Retirement"],  # Item 24: Financial Goals
            "customer_score": 92.4,                          # Derived Psychometrics
            "predicted_income_band": "Upper Middle Class",
            "investment_persona": "Tech-Savvy Growth Investor"
        }
        return profile
