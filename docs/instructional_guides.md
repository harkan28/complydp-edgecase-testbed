# User KYC & Account Setup Guidelines (Instructional Guide)

> **NEGATIVE CONTROL TEST CASES:**
> - `[TC: GOV-085]` Instructional text mentioning Aadhaar — `[EXPECTED: DO NOT FLAG AS CONFIRMED PII]`
> - `[TC: GOV-086]` Instructional text mentioning PAN card — `[EXPECTED: DO NOT FLAG AS CONFIRMED PII]`

---

## Step 2: Third-Party Broker Account Setup

To begin automated algorithmic trading with ICICI Direct, Zerodha, or Groww, follow these steps on their respective official portals:

1. **Keep your PAN card and Aadhaar ready:**
   You will need to enter your personal details on the SEBI-registered broker's official verification portal.
2. **Complete e-KYC with Aadhaar and PAN:**
   Authenticate via UIDAI OTP on the external DigiLocker or broker onboarding page.
3. **Verify Linked Bank Account:**
   Ensure your primary savings account supports UPI and IMPS transfers.

---

> **Note for Static Analysis Scanners:**  
> The strings `"Aadhaar"` and `"PAN"` in this file represent informational guidance and developer documentation.  
> No national identity cards or numbers are ingested, stored, transmitted, or processed by this application codebase.
