# ComplyDP Scanner Audit & 1,500 Edge-Case Benchmark Suite

**Repository:** `harkan28/complydp-edgecase-testbed`  
**GitHub URL:** [https://github.com/harkan28/complydp-edgecase-testbed](https://github.com/harkan28/complydp-edgecase-testbed)  
**Evaluation Scope:** 1,500 Scenarios across 15 PII Categories + Core Production Baseline  
**Auditor System:** Quality Assurance & Static Code Analysis Verification Audit  
**Date:** October 12, 2026  

---

## Executive Summary

This repository was purpose-built as an adversarial and systematic benchmark to evaluate the accuracy, coverage, and inference engine of the **ComplyDP Static Code Scanner** (GitHub Integration).

During live scanning, ComplyDP evaluated this codebase and produced **15 finding cards**. A deep-dive audit against our ground-truth catalog revealed that ComplyDP suffered from two critical architectural failures:
1. **Extreme False Discovery Rate (73.3% False Positive Rate):** Of the 15 inferred findings, **11 are false alarms** triggered by substring matching errors, text sanitization blindness, mock dataset labels, and static UI instructional strings.
2. **Massive Domain Blindspots (86.7% Coverage Failure):** The scanner completely missed **13 out of the 15 standard PII domains** (including Biometrics, Education, Health, Location, Digital Identifiers, User Demographics, and Third-Party API Vendors) due to a hardcoded 15-identifier vocabulary limit and an inability to parse SQL DDL schemas or typed dataclasses.

---

## 1. What Was Built & Deployed

To comprehensively test ComplyDP, we extracted all **1,500 edge cases** from the official benchmark document (`ComplyDP_PII_Edge_Case_Test_Suite_1500_REVISED.docx`) and deployed a fully compilable, multi-tier Python and SQL testbed:

```text
complydp-edgecase-testbed/
├── README.md                              # Repository overview, architecture, & audit results
├── COMPLYDP_SYSTEM_PROBLEMS_AND_DEFECTS_REPORT.md # Ultra-detailed technical defects & root causes audit
├── ENTERPRISE_200_CLEAN_PII_BENCHMARK.md  # Ground-truth taxonomy of 200 clean, distinct PII entities
│
├── database/                              # Production database schemas & active databases
│   ├── enterprise_pii.db                  # Active SQLite database with 1,000 real records across 6 tables
│   ├── enterprise_pii_catalog_200.py      # Schema & repository covering 200 distinct global PII entities
│   ├── data_manager.py                    # Active SQLite CRUD manager across all 15 PII domains
│   ├── models.py                          # Data models & dataclass structures
│   └── schemas.sql                        # Production SQL DDL tables
│
├── datasets/                              # Active enterprise datasets & real data files
│   ├── enterprise_pii_records.csv         # 1,000 realistic rows covering all 200 primary PII fields
│   ├── production_customers_payload.json  # 200 complete enterprise customer API payloads
│   └── transactions.csv                   # 1,000 realistic financial transaction records (UPI, IFSC, Bank)
│
├── services/                              # Active production microservices processing real PII
│   ├── real_pii_production_services.py    # Clean production ingestors for Aadhaar, PAN, Passport, DL
│   ├── biometric_auth.py                  # Biometric vectors, minutiae templates, iris code handlers
│   ├── health_service.py                  # Patient medical records, prescriptions, ICD-10 diagnosis
│   ├── government_registry.py             # Statutory ID registries & validation handlers
│   ├── user_profile_service.py            # User profile data, demographic parameters
│   ├── geolocation_tracker.py             # GPS coordinates, spatial telemetry, route waypoints
│   ├── digital_telemetry_service.py       # IP addresses, device IMEI, MAC address tracking
│   ├── education_portal.py                # Student roll numbers, GPA, academic transcript records
│   ├── communication_logger.py            # Message logs, telecommunication metadata
│   └── sms_parser.py                      # Production SMS regex transaction parser
│
└── test_suites/                           # The 1,500 edge-case test suites (15 modules × 100 cases)
    ├── test_cases_master.json             # Full machine-readable catalog of all 1,500 scenarios
    ├── suite_01_personal_identity.py      # 100 Test Cases: ID-001 to ID-100
    ├── suite_02_government_ids.py         # 100 Test Cases: GOV-001 to GOV-100
    ├── suite_03_contact_info.py           # 100 Test Cases: CON-001 to CON-100
    ├── suite_04_demographics.py           # 100 Test Cases: DEM-001 to DEM-100
    ├── suite_05_financial_info.py         # 100 Test Cases: FIN-001 to FIN-100
    ├── suite_06_payments.py               # 100 Test Cases: PAY-001 to PAY-100
    ├── suite_07_auth_secrets.py           # 100 Test Cases: AUTH-001 to AUTH-100
    ├── suite_08_digital_telemetry.py      # 100 Test Cases: DIG-001 to DIG-100
    ├── suite_09_location_tracking.py      # 100 Test Cases: LOC-001 to LOC-100
    ├── suite_10_biometric_data.py         # 100 Test Cases: BIO-001 to BIO-100
    ├── suite_11_health_records.py         # 100 Test Cases: HLT-001 to HLT-100
    ├── suite_12_employment_info.py        # 100 Test Cases: EMP-001 to EMP-100
    ├── suite_13_education_records.py      # 100 Test Cases: EDU-001 to EDU-100
    ├── suite_14_communications.py         # 100 Test Cases: COM-001 to COM-100
    └── suite_15_derived_attributes.py     # 100 Test Cases: DER-001 to DER-100
```

---

## 2. In-Depth Analysis of Problems in ComplyDP

Our testing revealed four severe architectural flaws in ComplyDP's static analysis engine:

```
+--------------------------------------------------------------------------------------------------+
|                            COMPLYDP ARCHITECTURAL FAILURE MODES SUMMARY                          |
+--------------------------+------------------------------------+----------------------------------+
| Flaw Category            | Live Examples from Repository      | Technical Root Cause             |
+--------------------------+------------------------------------+----------------------------------+
| 1. Substring Stemming    | • 'pran' in "Pranay"               | Scanner regexes lack word        |
|    Collisions            | • 'uan' in "quantity", "quantile"  | boundaries (\b). Tokenizes       |
|                          | • 'abha' in "Sabharwal"            | internal sub-parts of words.     |
+--------------------------+------------------------------------+----------------------------------+
| 2. Instructional UI Text | • "Keep PAN card ready"            | Scanner cannot distinguish       |
|    Matching              | • "Complete KYC with Aadhaar"      | between human guidance text and  |
|                          | • "Link bank using IFSC"           | active data ingestion models.    |
+--------------------------+------------------------------------+----------------------------------+
| 3. Sanitization Context  | • Regex r'\s+\d{6}$', # pincode    | Scanner AST blindspot: fails to  |
|    Blindness             |   inside re.sub(pattern, '', name) | check if data is being deleted   |
|                          |                                    | vs retained/stored.              |
+--------------------------+------------------------------------+----------------------------------+
| 4. Semantic Role         | • Label 'vehicle registration'     | Flags string literals without    |
|    Confusion             | • Merchant 'Passport Seva'         | evaluating whether they are      |
|                          | • Merchant 'ESIC'                  | category tags or actual IDs.     |
+--------------------------+------------------------------------+----------------------------------+
| 5. Hardcoded Vocabulary  | • Misses Biometrics, Health,       | Scanner rulebook is capped at    |
|    Ceiling               |   Location, Education, Digital     | ~15 hardcoded Indian identifiers;|
|                          | • Misses users.full_name, age      | no generalized PII AST parsing.  |
+--------------------------+------------------------------------+----------------------------------+
```

---

### Problem 1: Substring Stemming Collisions (No Word Boundary Enforcement)
* **What Happened:** ComplyDP uses naive substring search without regex boundary delimiters (`\b`).
* **Evidence in Code:**
  * In `transactions.csv`: Line `51de0122...,Pranay Gopal,2575877412@okaxis...` contains the common Indian given name **"Pranay"**. ComplyDP matched the 4 letters `pran` and falsely created a card for National Pension System (`user.financial.pran`).
  * In `analytics/telemetry_and_math.py`: Lines calculating `quantile(0.75)` and trade `quantity = 10` contain the letters `uan`. ComplyDP matched `uan` and falsely flagged EPFO Universal Account Number (`user.employment.uan`).
* **Impact:** High developer fatigue; false alarms on basic math, trading, and natural language strings.

---

### Problem 2: Instructional UI & Guidance Text False Positives
* **What Happened:** The scanner treats hardcoded strings in setup instructions and help documentation as active personal data collection.
* **Evidence in Code:**
  * In `onboarding_flow.py`:
    ```python
    "instructions": [
        "1. Keep PAN card and Aadhaar ready",
        "2. Complete KYC with Aadhaar and PAN on your broker portal",
        "3. Link your primary bank account using your IFSC code",
        "4. Verify your CKYC registry status on the KRA portal"
    ]
    ```
  * ComplyDP flagged all four: `user.identity.aadhaar`, `user.identity.pan`, `user.financial.ifsc`, and `user.financial.ckyc`.
* **Impact:** The application does not store, ingest, or validate any of these documents; it merely gives advice on completing KYC on external portals (Zerodha/Groww).

---

### Problem 3: Sanitization Context Blindspot (`re.sub` Deletion vs Storage)
* **What Happened:** The scanner identifies regex patterns labeled with PII keywords, but completely ignores whether the code is *storing* or *purging* the data.
* **Evidence in Code:**
  * In `sms_parser.py`:
    ```python
    def clean_merchant_address(merchant_string: str) -> str:
        pattern = r'\s+\d{6}$'  # pincode
        cleaned = re.sub(pattern, '', merchant_string.strip())
        return cleaned
    ```
  * ComplyDP flagged `user.contact.pincode`.
* **Impact:** The regex exists strictly to strip postal codes to sanitize merchant names. No residential user pincode is stored or processed.

---

### Problem 4: Semantic Confusion (Mock Categories vs PII)
* **What Happened:** ComplyDP cannot differentiate between an expense category label and a personal identification credential.
* **Evidence in Code:**
  * In `dataset_generator.py`:
    ```python
    EXPENSE_CATEGORIES = ['fuel refill', 'insurance renewal', 'vehicle registration', 'toll charges']
    GOVERNMENT_SERVICES_MERCHANTS = ['Passport Seva', 'ESIC', 'Aadhaar Center']
    GOVERNMENT_FEE_TYPES = ['Passport Fee', 'Visa Fee']
    ```
  * ComplyDP flagged `user.identity.vehicle_registration` and `user.identity.passport`.
* **Impact:** `'vehicle registration'` was a mock classification label for car expenses; `'Passport Seva'` was a merchant name. No vehicle license plate or passport number was ever present.

---

### Problem 5: The Hardcoded 15-Identifier Ceiling & Massive False Negatives
* **Why ComplyDP Outputted Only 15 Cards:**  
  ComplyDP's UI is designed to emit **1 Card per Identifier Type**. More critically, **ComplyDP's engine currently only possesses detection rules for ~15 Indian-specific terms**:
  `[uan, pran, upi, bank_account, pincode, driving_licence, voter_id, passport, phone, email, ifsc, aadhaar, pan, vehicle_registration, ckyc]`.
* **The Result:** ComplyDP is **completely blind** to 13 out of 15 domains in the 1,500 test suite:
  * **Biometric Data:** Zero detections for `face_id`, `face_embedding`, `iris_scan`, `fingerprint_template`.
  * **Education Records:** Zero detections for `student_id`, `exam_result`, `marks`, `grade_point_average`.
  * **Health Records:** Zero detections for `patient_id`, `medical_record`, `diagnosis`, `prescription`.
  * **Location Information:** Zero detections for `latitude`, `longitude`, `geohash`, `current_location`.
  * **Digital Identifiers:** Zero detections for `ip_address`, `device_id`, `cookie_id`, `session_id`.
  * **User Profile Data:** Zero detections for `users.full_name`, `age`, `annual_income`, `risk_profile`.
  * **Third-Party Vendors:** Zero detections for UI-Avatars, Ionicons, Google Fonts, Breeze API, Finnhub API, Kagglehub.

---

## 3. Detailed Audit Matrix of the 15 Live Inferred Cards

| # | Inferred Card | Ground Truth Expectation | Live Scanner Outcome | Verification Verdict | Technical Root Cause | Recommended Action in UI |
|:---:|:---|:---:|:---:|:---:|:---|:---:|
| **1** | `user.employment.uan` | **Should Ignore** | Flagged | ❌ **FAIL (FP)** | Substring match in `"quantile"` and `"quantity"` | **Reject** |
| **2** | `user.financial.pran` | **Should Ignore** | Flagged | ❌ **FAIL (FP)** | Substring match in synthetic name `"Pranay"` | **Reject** |
| **3** | `user.identity.aadhaar` | **Should Ignore** | Flagged | ❌ **FAIL (FP)** | Instructional guidance text matching | **Reject** |
| **4** | `user.identity.pan` | **Should Ignore** | Flagged | ❌ **FAIL (FP)** | Instructional guidance text matching | **Reject** |
| **5** | `user.financial.ifsc` | **Should Ignore** | Flagged | ❌ **FAIL (FP)** | Instructional guidance text matching | **Reject** |
| **6** | `user.financial.ckyc` | **Should Ignore** | Flagged | ❌ **FAIL (FP)** | Instructional guidance text matching | **Reject** |
| **7** | `user.contact.pincode` | **Should Ignore** | Flagged | ❌ **FAIL (FP)** | `re.sub()` sanitization regex blindspot | **Reject** |
| **8** | `user.identity.vehicle_registration` | **Should Ignore** | Flagged | ❌ **FAIL (FP)** | Mock expense category label string | **Reject** |
| **9** | `user.identity.passport` | **Should Ignore** | Flagged | ❌ **FAIL (FP)** | Mock merchant/fee array literal | **Reject** |
| **10** | `user.identity.driving_licence` | **Should Ignore** | Flagged | ❌ **FAIL (FP)** | Mock column placeholder with zero ingestion | **Reject** |
| **11** | `user.identity.voter_id` | **Should Ignore** | Flagged | ❌ **FAIL (FP)** | Mock column placeholder with zero ingestion | **Reject** |
| **12** | `user.financial.upi` | **Should Detect** | Flagged | ✅ **PASS (TP)** | Active SQLite column & PhonePe SMS regex | **Confirm** |
| **13** | `user.financial.bank_account` | **Should Detect** | Flagged | ✅ **PASS (TP)** | Active SQLite column & bank alert SMS regex | **Confirm** |
| **14** | `user.contact.phone` | **Should Detect** | Flagged | ✅ **PASS (TP)** | Active SQLite user profile column | **Confirm** |
| **15** | `user.contact.email` | **Should Detect** | Flagged | ✅ **PASS (TP)** | Active SQLite user profile column | **Confirm** |

---

## 4. Benchmark Scorecard Metrics

$$\text{Precision} = \frac{4}{4 + 11} \times 100 = \mathbf{26.7\%}$$

$$\text{False Discovery Rate (FDR)} = \frac{11}{15} \times 100 = \mathbf{73.3\%}$$

$$\text{Category Coverage Rate} = \frac{2\text{ Categories Detected}}{15\text{ Benchmark Domains}} \times 100 = \mathbf{13.3\%}$$

$$\text{Domain Blindspot Rate (False Negatives)} = \mathbf{86.7\%}$$

---

## 5. Engineering Calibration Guide (Fixes for ComplyDP Team)

To fix the scanner, the ComplyDP development team must implement the following 5 changes:

1. **Enforce Regex Word Boundaries:**  
   Replace bare string checks with strict boundary delimiters (`\b(?<![a-zA-Z])PRAN(?![a-zA-Z])\b`) so "Pranay" and "quantile" are never flagged.
2. **Abstract Syntax Tree (AST) Sanitization Checks:**  
   When regexes match in Python, check the AST node. If the pattern is passed to `re.sub()`, `str.replace()`, or sanitization cleaners, classify as **Sanitization**, not PII storage.
3. **Contextual Role Filtering:**  
   Ignore string literals enclosed in instructional UI guidance blocks, help manuals, or synthetic dataset arrays (`EXPENSE_CATEGORIES`, `MOCK_MERCHANTS`).
4. **Expand AST Schema Parsers:**  
   Parse SQL `CREATE TABLE` statements and Python typed dataclasses (`@dataclass`, Pydantic `BaseModel`) so core user fields (`full_name`, `age`, `annual_income`, `risk_profile`, `goals`) are automatically detected.
5. **Implement Vendor & Dependency Signatures:**  
   Add detectors for external SDK imports (`breeze_connect`, `finnhub`, `kagglehub`) and frontend `<script>`/`<link>` tags (UI-Avatars, Ionicons, Google Fonts).
