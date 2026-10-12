# ComplyDP PII Detection Edge-Case Test Suite — Master Index (1,500 Scenarios)

**Benchmark Document:** `ComplyDP_PII_Edge_Case_Test_Suite_1500_REVISED.docx`  
**Master Data File:** [`test_cases_master.json`](file:///Users/harshitrawal/Downloads/complydp/ocr/complydp_edgecase_testbed/master_catalog/test_cases_master.json)  
**Total Test Scenarios:** 1,500  
**Categories:** 15 distinct PII & data domain categories (100 scenarios each)  

---

## 1. Category Distribution Matrix

| # | Code | Category Name | ID Range | Test Count | Expected PII Findings | Negative Controls (Traps) |
|:---:|:---:|:---|:---:|:---:|:---:|:---:|
| 1 | `ID` | Personal Identity | `ID-001` to `ID-100` | 100 | 90 | 10 (`ID-081` to `ID-090`) |
| 2 | `GOV` | Government Identifiers | `GOV-001` to `GOV-100` | 100 | 90 | 10 (`GOV-081` to `GOV-090`) |
| 3 | `CON` | Contact Information | `CON-001` to `CON-100` | 100 | 90 | 10 (`CON-081` to `CON-090`) |
| 4 | `DEM` | Demographic Information | `DEM-001` to `DEM-100` | 100 | 90 | 10 (`DEM-081` to `DEM-090`) |
| 5 | `FIN` | Financial Information | `FIN-001` to `FIN-100` | 100 | 90 | 10 (`FIN-081` to `FIN-090`) |
| 6 | `PAY` | Payment Information | `PAY-001` to `PAY-100` | 100 | 90 | 10 (`PAY-081` to `PAY-090`) |
| 7 | `AUTH` | Authentication Secrets | `AUTH-001` to `AUTH-100` | 100 | 90 | 10 (`AUTH-081` to `AUTH-090`) |
| 8 | `DIG` | Digital Identifiers | `DIG-001` to `DIG-100` | 100 | 90 | 10 (`DIG-081` to `DIG-090`) |
| 9 | `LOC` | Location Information | `LOC-001` to `LOC-100` | 100 | 90 | 10 (`LOC-081` to `LOC-090`) |
| 10 | `BIO` | Biometric Data | `BIO-001` to `BIO-100` | 100 | 90 | 10 (`BIO-081` to `BIO-090`) |
| 11 | `HLT` | Health Information | `HLT-001` to `HLT-100` | 100 | 90 | 10 (`HLT-081` to `HLT-090`) |
| 12 | `EMP` | Employment Information | `EMP-001` to `EMP-100` | 100 | 90 | 10 (`EMP-081` to `EMP-090`) |
| 13 | `EDU` | Education Information | `EDU-001` to `EDU-100` | 100 | 90 | 10 (`EDU-081` to `EDU-090`) |
| 14 | `COM` | Communications Information | `COM-001` to `COM-100` | 100 | 90 | 10 (`COM-081` to `COM-090`) |
| 15 | `DER` | Derived / Inferred Attributes | `DER-001` to `DER-100` | 100 | 90 | 10 (`DER-081` to `DER-090`) |
| **Total** | | | | **1,500** | **1,350** | **150** |

---

## 2. Standardized Scenario Tiers (Each Category 001 - 100)

Every category follows a uniform 10-tier architectural progression:

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ Tier 1: Cases 001–020 (20 cases)  Schema & Field Naming (DETECT POTENTIAL PII)        │
│ Tier 2: Cases 021–030 (10 cases)  API Ingress & Egress (DETECT DATA FLOW)             │
│ Tier 3: Cases 031–040 (10 cases)  Data Transformation (DETECT IF TRACEABLE)           │
│ Tier 4: Cases 041–050 (10 cases)  Storage & Persistence (DETECT STORAGE PATH)         │
│ Tier 5: Cases 051–060 (10 cases)  User Linkage / Identity Graph (DETECT LINKAGE)      │
│ Tier 6: Cases 061–070 (10 cases)  Vendor & Third-Party SDK Egress (DETECT OUTBOUND)   │
│ Tier 7: Cases 071–080 (10 cases)  Masked/Encrypted/Hashed (DETECT TYPE; QUALIFY)       │
│ Tier 8: Cases 081–090 (10 cases)  Negative Controls / Traps (DO NOT FLAG CONFIRMED)   │
│ Tier 9: Cases 091–100 (10 cases)  Uncertainty & Edge Cases (POTENTIAL WITH UNCERTAINTY)│
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Evaluation Taxonomy: The 7 Benchmark Failure Types

| Failure Type | Benchmark Definition | Scanner Error in Practice |
|:---|:---|:---|
| **False Negative** | Expected a detection or data-flow finding, but the scanner did not produce it. | Scanner missed `user.name`, `age`, `income`, or vendor SDKs like `Breeze`, `Finnhub`. |
| **False Positive** | Scanner reported confirmed PII without adequate supporting evidence. | Flagged "Pranay" as `PRAN`, "quantile" as `UAN`, or "Sabharwal" as `ABHA`. |
| **Context Failure** | Scanner assigned the wrong meaning or category to a field or token. | Flagged mock expense category `'vehicle registration'` as personal vehicle plate. |
| **Data-Flow Failure**| Scanner found a field but missed source, destination, direction, or transformation. | Identified an avatar image tag but missed outbound GET query leak to `ui-avatars.com`. |
| **Coverage Failure** | File, branch, dependency, parser, or repository limits left scan incomplete. | Missed fields because SQL schemas or Pydantic models were not analyzed. |
| **Evidence Failure** | Finding lacks an accurate source location, snippet, or uncertainty note. | Scanner UI shows `"No file path yet. Rescan to attach evidence."` |
| **Legal-Assessment Failure** | Scanner treats technical string match as an automatic legal non-compliance. | Hardcoded guidance string `"Complete KYC with Aadhaar"` treated as live PII storage. |
