# ComplyDP Scanner Live Scan Audit & Evaluation Report

**Target Repository:** `harkan28/complydp-edgecase-testbed`  
**Scan Engine:** ComplyDP Static Code Scanner (GitHub Integration)  
**Date:** October 12, 2026  
**Auditor System:** Edge-Case Test Suite Benchmark  

---

## 1. Executive Summary of Live Scan Results

* **Total Findings Inferred by Scanner:** 14
* **True Positives (Accurate Detections):** 4 (28.6%)
* **False Positives (Scanner Errors / Traps Triggered):** 10 (71.4%)
* **False Negatives (Missed Active PII & Vendors):** 15+ Core Categories Completely Omitted
* **False Discovery Rate (FDR):** **71.4%**

---

## 2. Itemized Pass / Fail Matrix (14 Scanned Cards)

| # | Inferred Identifier | Expected Ground Truth | Scanner Outcome | Audit Verdict | Technical Failure Mode / Root Cause | Action in ComplyDP UI |
|:---:|:---|:---:|:---:|:---:|:---|:---:|
| **1** | `user.financial.pran` | **Should Ignore** | Flagged | ❌ **FAIL (FP)** | **Substring Stemming Collision:** Matched `pran` inside human name `"Pranay"` in `transactions.csv`. | **Reject** |
| **2** | `user.employment.uan` | **Should Ignore** | Flagged | ❌ **FAIL (FP)** | **Substring Stemming Collision:** Matched `uan` inside ordinary math words `"quantity"` and `"quantile"`. | **Reject** |
| **3** | `user.identity.aadhaar` | **Should Ignore** | Flagged | ❌ **FAIL (FP)** | **Instructional Text Trap:** Matched hardcoded guidance string (`"Complete KYC with Aadhaar"`). No ID stored. | **Reject** |
| **4** | `user.identity.pan` | **Should Ignore** | Flagged | ❌ **FAIL (FP)** | **Instructional Text Trap:** Matched hardcoded guidance string (`"Keep PAN card ready"`). No ID stored. | **Reject** |
| **5** | `user.contact.pincode` | **Should Ignore** | Flagged | ❌ **FAIL (FP)** | **Sanitization Context Blindspot:** Regex `r'\s+\d{6}$'` exists strictly in `re.sub()` to *delete* postal codes. | **Reject** |
| **6** | `user.identity.vehicle_registration` | **Should Ignore** | Flagged | ❌ **FAIL (FP)** | **Semantic Confusion:** Matched mock expense category string label `'vehicle registration'`. | **Reject** |
| **7** | `user.identity.passport` | **Should Ignore** | Flagged | ❌ **FAIL (FP)** | **Mock Merchant / Fee Confusion:** Matched synthetic string literals `'Passport Seva'` and `'Passport Fee'`. | **Reject** |
| **8** | `user.financial.ifsc` | **Should Ignore** | Flagged | ❌ **FAIL (FP)** | **Instructional Text Trap:** Matched advice string (`"Link primary bank account using IFSC"`). | **Reject** |
| **9** | `user.identity.driving_licence` | **Should Ignore** | Flagged | ❌ **FAIL (FP)** | **Empty Schema / Mock Label Trap:** Column exists with zero active ingestion pipeline. | **Reject** |
| **10** | `user.identity.voter_id` | **Should Ignore** | Flagged | ❌ **FAIL (FP)** | **Empty Schema / Mock Label Trap:** Column exists with zero active ingestion pipeline. | **Reject** |
| **11** | `user.financial.upi` | **Should Detect** | Flagged | ✅ **PASS (TP)** | **Accurate:** Active column in SQLite database and extracted from inbound SMS feeds via regex. | **Confirm** |
| **12** | `user.financial.bank_account` | **Should Detect** | Flagged | ✅ **PASS (TP)** | **Accurate:** Active column in SQLite database and parsed from transactional SMS bodies. | **Confirm** |
| **13** | `user.contact.email` | **Should Detect** | Flagged | ✅ **PASS (TP)** | **Accurate:** Core user profile attribute in SQLite schema and profile creation handler. | **Confirm** |
| **14** | `user.contact.phone` | **Should Detect** | Flagged | ✅ **PASS (TP)** | **Accurate:** Core user profile attribute in SQLite schema linking users to SMS feeds. | **Confirm** |

---

## 3. Systematic Breakdown of Scanner Defect Categories

### Defect Mode 1: Substring Stemming Collisions (No Word Boundaries)
* **Cases:** `user.financial.pran`, `user.employment.uan`
* **Trigger Code:** `"Pranay Gopal"`, `df['savings'].quantile(0.75)`, `order['quantity']`
* **Defect:** Scanner tokenizes sub-parts of words instead of enforcing word boundaries (`\bPRAN\b`, `\bUAN\b`).

### Defect Mode 2: Static Instructional & Guidance Text Matching
* **Cases:** `user.identity.aadhaar`, `user.identity.pan`, `user.financial.ifsc`
* **Trigger Code:** `"1. Keep PAN card and Aadhaar ready"`, `"2. Complete KYC with Aadhaar and PAN"`
* **Defect:** Scanner treats static user guidance and markdown/UI advice strings as active personal data ingestion.

### Defect Mode 3: Data Sanitization Blindness (`re.sub` vs Storage)
* **Cases:** `user.contact.pincode`
* **Trigger Code:** `re.sub(r'\s+\d{6}$', '', merchant_string)`
* **Defect:** Scanner detects the regex pattern but fails to analyze AST usage: the data is being *deleted/stripped*, not retained.

### Defect Mode 4: Semantic Confusion (Mock Categories vs PII)
* **Cases:** `user.identity.vehicle_registration`, `user.identity.passport`
* **Trigger Code:** `'vehicle registration'`, `'Passport Fee'`, `'Passport Seva'`
* **Defect:** Scanner flags string literals in mock arrays without distinguishing between categorization labels and actual PII payloads.

---

## 4. Critical False Negatives (Active Data Fields Completely Missed)

The scanner completely failed to generate findings for the following active entities present in the repository:

1. **`user.name` (Full Name):** Present in `users.full_name TEXT NOT NULL` and `user_profile_service.py`.
2. **`user.demographics.age`:** Present in `users.age INTEGER` and `user_profile_service.py`.
3. **`user.financial.annual_income`:** Present in `financial_accounts.annual_income REAL`.
4. **`user.financial.risk_profile`:** Present in `financial_accounts.risk_profile TEXT`.
5. **`user.financial.goals`:** Present in `financial_accounts.financial_goals TEXT`.
6. **`user.health.patient_id` / `diagnosis`:** Present in `health_service.py`.
7. **`user.health.abha`:** Present in `health_service.py` and `transactions.csv` (Sabharwal).
8. **`user.employment.esic`:** Present in `government_registry.py` and `data_manager.py`.
9. **`user.financial.ckyc`:** Present in `government_registry.py` (`ckyc_number = "10029384756102"`).
10. **`user.biometrics.*`:** Present in `biometric_auth.py` (`face_id`, `face_embedding`, `iris_scan`).
11. **`user.education.*`:** Present in `education_portal.py` (`student_id`, `marks`, `qualification`).
12. **`user.location.*`:** Present in `geolocation_tracker.py` (`latitude`, `longitude`, `home_address`).
13. **`user.digital.*`:** Present in `digital_telemetry_service.py` (`ip_address`, `device_id`, `cookie_id`).
14. **Third-Party Vendors:** UI-Avatars CDN, Ionicons, Google Fonts, ICICI Breeze API, Finnhub Market Data API, Kagglehub.
