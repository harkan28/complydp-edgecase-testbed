# ComplyDP PII Edge-Case Benchmark Testbed

A dedicated testing repository and audit suite built for evaluating and benchmarking the **ComplyDP Static Code Scanner** against **1,500 edge-case scenarios** and baseline repository scan findings.

---

## 📁 Repository Structure & Exact File Locations

```text
complydp_edgecase_testbed/
├── 📄 README.md                                # Root documentation & directory guide
├── 📄 EVALUATION_SCORECARD_TEMPLATE.md         # Master scorecard template for logging scan results
│
├── 📂 audit_evidence/
│   └── 📄 SMART_MONEY_AI_VERIFICATION_LOCATIONS.md # Line-by-line evidence & paths for Items 5–33
│
├── 📂 master_catalog/
│   ├── 📄 test_cases_master.json               # Full JSON database of all 1,500 test cases
│   └── 📄 TEST_SUITE_1500_INDEX.md             # Categorized index across all 15 PII domains
│
├── 📂 database/
│   ├── 📄 schemas.sql                          # SQL DDL schemas (testing active schema PII)
│   └── 📄 models.py                            # Python dataclasses (testing typed object entities)
│
├── 📂 sanitization/
│   └── 📄 cleaners.py                          # re.sub() routines (testing sanitization vs storage traps)
│
├── 📂 datasets/
│   └── 📄 mock_data.py                         # Synthetic fixtures (testing substring & mock label traps)
│
├── 📂 analytics/
│   └── 📄 telemetry_and_math.py                # Math & system logic (testing quantile, healthz, token_age)
│
├── 📂 integrations/
│   └── 📄 external_vendors.py                  # Breeze API, Finnhub, Kagglehub SDK integrations
│
├── 📂 frontend/
│   └── 📄 index.html                           # CDNs: UI-Avatars (PII in query), Ionicons, Google Fonts
│
└── 📂 docs/
    └── 📄 instructional_guides.md              # Static onboarding guides (Aadhaar & PAN text traps)
```

---

## 🎯 How to Use This Testbed

1. **Connect & Scan on GitHub**:
   * Push or connect this directory to GitHub.
   * Add the repository in ComplyDP and trigger a scan.
2. **Review Generated Cards in ComplyDP**:
   * Inspect each card (`Confirm` vs `Reject`) against the expected outcomes in [`test_cases_master.json`](file:///Users/harshitrawal/Downloads/complydp/ocr/complydp_edgecase_testbed/master_catalog/test_cases_master.json).
3. **Record Findings in the Scorecard**:
   * Use [`EVALUATION_SCORECARD_TEMPLATE.md`](file:///Users/harshitrawal/Downloads/complydp/ocr/complydp_edgecase_testbed/EVALUATION_SCORECARD_TEMPLATE.md) to record pass/fail results.
4. **Hand Off Defects**:
   * Hand off the failed items to the development team with exact code references and root-cause notes.
