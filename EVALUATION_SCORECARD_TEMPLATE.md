# ComplyDP PII Detection Benchmark — Evaluation Scorecard & Defect Log

**Test Suite:** ComplyDP 1,500 Edge-Case Benchmark  
**Target Repository:** `complydp_edgecase_testbed` (or `harkan28/smart-money-ai`)  
**Evaluation Scope:** 15 PII Categories (100 cases each) + 29 Core Repository Baseline Items  

---

## 1. Quantitative Benchmark Formulas

$$\text{Precision} = \frac{\text{True Positives (Correctly Confirmed)}}{\text{True Positives} + \text{False Positives (Incorrectly Flagged Traps)}} \times 100$$

$$\text{Recall} = \frac{\text{True Positives (Correctly Confirmed)}}{\text{True Positives} + \text{False Negatives (Missed Active PII)}} \times 100$$

$$\text{F1 Score} = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$$

$$\text{False Discovery Rate (FDR)} = \frac{\text{False Positives}}{\text{Total Scanner Inferences}} \times 100$$

---

## 2. Category Benchmark Scorecard (1,500 Scenarios)

| # | Category Code | PII Domain | Total Cases | Expected Confirm | Expected Reject / Ignore | Scanner Inferred | Correct Inferences | False Positives | False Negatives | Pass Rate (%) |
|:---:|:---:|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| 1 | `ID` | Personal Identity | 100 | 90 | 10 | | | | | |
| 2 | `GOV` | Government Identifiers | 100 | 90 | 10 | | | | | |
| 3 | `CON` | Contact Information | 100 | 90 | 10 | | | | | |
| 4 | `DEM` | Demographic Information | 100 | 90 | 10 | | | | | |
| 5 | `FIN` | Financial Information | 100 | 90 | 10 | | | | | |
| 6 | `PAY` | Payment Information | 100 | 90 | 10 | | | | | |
| 7 | `AUTH` | Authentication Secrets | 100 | 90 | 10 | | | | | |
| 8 | `DIG` | Digital Identifiers | 100 | 90 | 10 | | | | | |
| 9 | `LOC` | Location Information | 100 | 90 | 10 | | | | | |
| 10 | `BIO` | Biometric Data | 100 | 90 | 10 | | | | | |
| 11 | `HLT` | Health Information | 100 | 90 | 10 | | | | | |
| 12 | `EMP` | Employment Information | 100 | 90 | 10 | | | | | |
| 13 | `EDU` | Education Information | 100 | 90 | 10 | | | | | |
| 14 | `COM` | Communications Information | 100 | 90 | 10 | | | | | |
| 15 | `DER` | Derived / Inferred Attributes | 100 | 90 | 10 | | | | | |
| **TOTAL** | | | **1,500** | **1,350** | **150** | | | | | |

---

## 3. Core Baseline Audit Checklist (Items 5 to 33)

| Item | Identifier / Service | Expected Ground Truth | Scanner Card In UI | Final Verdict | Engineer Defect Note |
|:---:|:---|:---:|:---:|:---:|:---|
| **5** | `user.financial.upi` | **Confirm** (True Positive) | `[Confirm] / [Reject]` | ✅ PASS | Verified in SQLite `transactions.upi_id` |
| **6** | `user.financial.bank_account` | **Confirm** (True Positive) | `[Confirm] / [Reject]` | ✅ PASS | Verified in SQLite & SMS parser dataclass |
| **7** | `user.contact.email` | **Confirm** (True Positive) | `[Confirm] / [Reject]` | ✅ PASS | Verified in SQLite `users.email` |
| **8** | `user.contact.phone` | **Confirm** (True Positive) | `[Confirm] / [Reject]` | ✅ PASS | Verified in SQLite `users.phone` |
| **9** | `user.financial.ifsc` | **Reject** (False Positive) | `[Confirm] / [Reject]` | ❌ FAIL | Hallucination (zero occurrences in code) |
| **10** | `user.identity.aadhaar` | **Reject** (False Positive) | `[Confirm] / [Reject]` | ❌ FAIL | Static setup advice ("KYC with Aadhaar") |
| **11** | `user.contact.pincode` | **Reject** (False Positive) | `[Confirm] / [Reject]` | ❌ FAIL | Stripped via `re.sub()`, not stored |
| **12** | `user.financial.pran` | **Reject** (False Positive) | `[Confirm] / [Reject]` | ❌ FAIL | Substring collision in name "Pranay" |
| **13** | `user.employment.uan` | **Reject** (False Positive) | `[Confirm] / [Reject]` | ❌ FAIL | Substring collision in "quantile/quantity" |
| **14** | `user.financial.ckyc` | **Reject** (False Positive) | `[Confirm] / [Reject]` | ❌ FAIL | Hallucination (zero occurrences in code) |
| **15** | `user.health.abha` | **Reject** (False Positive) | `[Confirm] / [Reject]` | ❌ FAIL | Substring collision in surname "Sabharwal" |
| **16** | `user.identity.vehicle_registration` | **Reject** (False Positive) | `[Confirm] / [Reject]` | ❌ FAIL | Expense category label string |
| **17** | `user.employment.esic` | **Reject** (False Positive) | `[Confirm] / [Reject]` | ❌ FAIL | Mock merchant array string literal |
| **18** | `user.identity.pan` | **Reject** (False Positive) | `[Confirm] / [Reject]` | ❌ FAIL | Static setup advice ("Keep PAN card ready") |
| **19** | `user.identity.passport` | **Reject** (False Positive) | `[Confirm] / [Reject]` | ❌ FAIL | Mock category / merchant string |
| **20** | `user.name` (Full Name) | **Confirm** (Active PII) | *Omitted (No Card)* | ❌ FAIL (FN) | Stored as `name TEXT` in SQLite |
| **21** | `user.demographics.age` | **Confirm** (Active PII) | *Omitted (No Card)* | ❌ FAIL (FN) | Stored as `age INTEGER` in SQLite |
| **22** | `user.financial.annual_income` | **Confirm** (Active PII) | *Omitted (No Card)* | ❌ FAIL (FN) | Stored as `annual_income REAL` in SQLite |
| **23** | `user.financial.risk_profile` | **Confirm** (Active PII) | *Omitted (No Card)* | ❌ FAIL (FN) | Stored as `risk_profile TEXT` in SQLite |
| **24** | `user.financial.goals` | **Confirm** (Active PII) | *Omitted (No Card)* | ❌ FAIL (FN) | Stored as `financial_goals` in SQLite |
| **25** | `user.financial.transaction_metadata` | **Confirm** (Active PII) | *Omitted (No Card)* | ❌ FAIL (FN) | Stores amounts, balances per user |
| **26** | `user.identity.avatar_url` | **Confirm** (Data Egress) | *Omitted (No Card)* | ❌ FAIL (FN) | User name passed in GET query parameter |
| **27** | UI-Avatars CDN | **Add to Systems** (Vendor) | *Omitted (No Card)* | ❌ FAIL (FN) | Third-party avatar image CDN |
| **28** | Ionicons (Unpkg CDN) | **Add to Systems** (Vendor) | *Omitted (No Card)* | ❌ FAIL (FN) | Unpkg CDN external script tag |
| **29** | Google Fonts | **Add to Systems** (Vendor) | *Omitted (No Card)* | ❌ FAIL (FN) | External stylesheet font request |
| **30** | ICICI Breeze API | **Add to Systems** (Vendor) | *Omitted (No Card)* | ❌ FAIL (FN) | Broker trading SDK integration |
| **31** | Finnhub Market API | **Add to Systems** (Vendor) | *Omitted (No Card)* | ❌ FAIL (FN) | Financial quotes REST API |
| **32** | Kaggle API / Kagglehub | **Add to Systems** (Vendor) | *Omitted (No Card)* | ❌ FAIL (FN) | ML dataset downloader client |
| **33** | SQLite Database | **Confirm System** | `Detected (Core)` | ✅ PASS | File-based SQL database |
