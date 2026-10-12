# Smart Money AI — PII & Systems Verification: Exact File Locations & Evidence Matrix

**Target Repository:** `harkan28/smart-money-ai`  
**Repository Root Path:** `/Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai`  
**Auditor System:** ComplyDP Systems & PII Code Scanner Evaluation  
**Date:** October 12, 2026  

---

## Executive Summary of Findings

| Category | Count | Scanner Behavior | Recommended UI Action |
|:---|:---:|:---|:---:|
| **True Positives** | 4 | Accurately detected active PII in database & parser | **Confirm** |
| **False Positives** | 11 | Misidentified due to substring collision, mock strings, sanitization, or hallucination | **Reject** |
| **False Negatives (PII)** | 7 | Active user PII present in SQLite schema & dataclasses, but omitted by scanner | **Add to Catalog** |
| **False Negatives (Vendors)** | 6 | External third-party SDKs, CDNs, and APIs present in code, but omitted by scanner | **Add to Systems** |
| **Database System** | 1 | SQLite database engine detected | **Confirm** |

---

## 1. True Positives (Accurately Detected by ComplyDP)
*These identifiers actively exist in database schemas or are processed by the application. UI Action: **Confirm**.*

### Item 5: `user.financial.upi`
* **File Location 1:** [`smart_money_ai/utils/data_manager.py`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/smart_money_ai/utils/data_manager.py#L75)
  * **Line 75:** `upi_id TEXT,` inside `CREATE TABLE IF NOT EXISTS transactions`
  * **Line 192:** `transaction_data.get('upi_id'),`
* **File Location 2:** [`smart_money_ai/config/bank_patterns.json`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/smart_money_ai/config/bank_patterns.json#L193)
  * **Line 193:** `"PhonePe: You paid Rs\.?(\d+\.?\d*) to (.+?) UPI ID: (.+?) on ([\d\-]+)"`
* **File Location 3:** [`smart_money_ai/intelligence/expense_categorizer.py`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/smart_money_ai/intelligence/expense_categorizer.py#L343)
  * **Line 343:** UPI pattern matching in expense categorization logic
* **Verdict / Finding:** Active database column and regex extraction from inbound SMS transaction feeds.

---

### Item 6: `user.financial.bank_account`
* **File Location 1:** [`smart_money_ai/utils/data_manager.py`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/smart_money_ai/utils/data_manager.py#L71)
  * **Line 71:** `account_number TEXT,` inside `CREATE TABLE IF NOT EXISTS transactions`
  * **Line 188:** `transaction_data['account_number'],`
* **File Location 2:** [`SMS PARSING SYSTEM/sms_parser/core_parser.py`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/SMS%20PARSING%20SYSTEM/sms_parser/core_parser.py#L25)
  * **Line 25:** Dataclass field definition `account_number: str`
* **File Location 3:** [`smart_money_ai/core/sms_parser/enhanced_sms_parser.py`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/smart_money_ai/core/sms_parser/enhanced_sms_parser.py#L29)
  * **Line 29:** `account_number: str` in dataclass `SMSParsedData`
  * **Line 330:** `account_number = groups[1]` regex capture group assignment
* **Verdict / Finding:** Active SQLite column and core dataclass attribute extracted from bank SMS alerts.

---

### Item 7: `user.contact.email`
* **File Location 1:** [`smart_money_ai/utils/data_manager.py`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/smart_money_ai/utils/data_manager.py#L49)
  * **Line 49:** `email TEXT UNIQUE,` inside `CREATE TABLE IF NOT EXISTS users`
  * **Line 127:** `user_data['email'],` in user profile storage handler
* **File Location 2:** [`smart_money_ai/core/smart_money_ai.py`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/smart_money_ai/core/smart_money_ai.py#L80)
  * **Line 80:** `email: str`
  * **Line 184:** `user_data.get('email')`
* **Verdict / Finding:** Core user profile attribute defined as unique contact identifier in the users schema.

---

### Item 8: `user.contact.phone`
* **File Location 1:** [`smart_money_ai/utils/data_manager.py`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/smart_money_ai/utils/data_manager.py#L50)
  * **Line 50:** `phone TEXT,` inside `CREATE TABLE IF NOT EXISTS users`
  * **Line 128:** `user_data.get('phone', ''),` in user profile storage handler
* **File Location 2:** [`smart_money_ai/core/smart_money_ai.py`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/smart_money_ai/core/smart_money_ai.py#L81)
  * **Line 81:** `phone: str`
* **Verdict / Finding:** Core user profile attribute linking registered users with inbound transactional SMS streams.

---

## 2. False Positives (Incorrectly Flagged by ComplyDP)
*These identifiers were flagged by the scanner but do NOT represent collected or processed PII. UI Action: **Reject**.*

### Item 9: `user.financial.ifsc`
* **File Location:** *None (Zero occurrences in the codebase)*
* **Scanner Error Type:** **Hallucination**
* **Root Cause:** Inferred purely through semantic association with Indian banking terminology. No code, model, regex, or column exists.

---

### Item 10: `user.identity.aadhaar`
* **File Location 1:** [`smart_money_ai/intelligence/investment_engine/investment_recommendations_backend.py`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/smart_money_ai/intelligence/investment_engine/investment_recommendations_backend.py#L735)
  * **Line 735:** `"2. Complete KYC with Aadhaar and PAN",`
  * **Line 746:** `"1. Keep PAN card and Aadhaar ready",`
* **File Location 2:** [`budgeting_ml_model/src/pro_plus_dataset_generator.py`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/budgeting_ml_model/src/pro_plus_dataset_generator.py#L215)
  * **Line 215:** `'Passport Seva', 'Aadhaar Center', 'Jan Aushadhi'`
* **Scanner Error Type:** **Static Instructional Text & Mock Label Confusion**
* **Root Cause:** Application outputs UI guidance telling users to complete KYC on third-party apps (Groww/Zerodha). No Aadhaar number is collected, ingested, validated, or stored.

---

### Item 11: `user.contact.pincode`
* **File Location:** [`SMS PARSING SYSTEM/sms_parser/core_parser.py`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/SMS%20PARSING%20SYSTEM/sms_parser/core_parser.py#L270)
  * **Line 270:** `r'\s+\d{6}$',  # pincode`
  * **Line 274:** `cleaned = re.sub(pattern, '', cleaned)`
* **Scanner Error Type:** **Sanitization Context Blindspot**
* **Root Cause:** Regex exists solely to *strip and discard* postal codes from merchant address strings during text sanitization via `re.sub()`. No postal code is stored or linked to users.

---

### Item 12: `user.financial.pran`
* **File Location:** [`SMS PARSING SYSTEM/transactions.csv`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/SMS%20PARSING%20SYSTEM/transactions.csv#L183)
  * **Line 183:** `51de0122-bf9d-4aa5-bea7-73cbd0ae32fd,2024-06-18 13:36:07,Pranay Gopal,2575877412@okaxis...`
  * **Line 213:** `170385a7-f8bc-49de-a637-9381e21b26f6,2024-06-09 05:15:54,Saira Dutta,0985258405@okaxis,Pranay...`
  * **Lines 357, 518, 587:** Synthetic records featuring first name "Pranay"
* **Scanner Error Type:** **Substring Stemming Collision**
* **Root Cause:** Scanner lacked boundary delimiters (`\b`) and matched the 4-letter sequence `pran` inside the common Indian given name **"Pranay"**. Zero National Pension System (NPS) PRAN records exist.

---

### Item 13: `user.employment.uan`
* **File Location 1:** [`smart_money_ai/api/breeze_trading_engine.py`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/smart_money_ai/api/breeze_trading_engine.py#L234)
  * **Line 234, 244:** `data["quantity"] = quantity`
* **File Location 2:** [`smart_money_ai/ml_models/savings_budgeting_model.py`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/smart_money_ai/ml_models/savings_budgeting_model.py#L472)
  * **Line 472:** `similar_users['savings_rate'].quantile(0.75)`
* **File Location 3:** [`examples/notebooks/advanced_investment_sentiment_model.ipynb`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/examples/notebooks/advanced_investment_sentiment_model.ipynb#L540)
  * **Line 540:** `load_in_4bit=True,  # 4-bit quantization`
* **Scanner Error Type:** **Substring Stemming Collision**
* **Root Cause:** Scanner matched `uan` inside ordinary mathematical and trading terms: **quantity**, **quantile**, and **quantization**. Zero EPFO UAN employment records exist.

---

### Item 14: `user.financial.ckyc`
* **File Location:** *None (Zero occurrences in the codebase)*
* **Scanner Error Type:** **Hallucination / Semantic Proximity Error**
* **Root Cause:** Scanner inferred this from proximity to the generic term "KYC" in documentation. Zero 14-digit Central KYC registry identifiers exist in models or payloads.

---

### Item 15: `user.health.abha`
* **File Location:** [`SMS PARSING SYSTEM/transactions.csv`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/SMS%20PARSING%20SYSTEM/transactions.csv#L27)
  * **Line 27:** `...Anika Sabharwal,5259795433@okicici...`
  * **Line 554:** `...Raunak Sabharwal,9342292431@okybl...`
  * **Lines 622, 952:** Synthetic records featuring surname "Sabharwal"
* **Scanner Error Type:** **Substring Stemming Collision**
* **Root Cause:** Scanner matched `abha` inside the Indian surname **"Sabharwal"** (`S-abha-rwal`). The application has zero medical or Ayushman Bharat health account integrations.

---

### Item 16: `user.identity.vehicle_registration`
* **File Location 1:** [`budgeting_ml_model/src/mega_dataset_generator.py`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/budgeting_ml_model/src/mega_dataset_generator.py#L210)
  * **Line 210:** `'insurance renewal', 'vehicle registration', 'pollution certificate', 'driving license'`
* **File Location 2:** [`budgeting_ml_model/src/large_dataset_generator.py`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/budgeting_ml_model/src/large_dataset_generator.py#L61)
* **Scanner Error Type:** **Mock Expense Category Label Confusion**
* **Root Cause:** A synthetic string label used to train an expense classifier for vehicle costs. The application does not collect vehicle RC plate numbers.

---

### Item 17: `user.employment.esic`
* **File Location:** [`budgeting_ml_model/src/pro_plus_dataset_generator.py`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/budgeting_ml_model/src/pro_plus_dataset_generator.py#L214)
  * **Line 214:** `'Income Tax Department', 'GST Portal', 'MCA Portal', 'EPFO', 'ESIC', 'PF Office'`
* **Scanner Error Type:** **Mock Merchant Array String Confusion**
* **Root Cause:** Static string literal in an array of government portals used for synthetic training generation. No 17-digit ESIC employee insurance numbers are collected.

---

### Item 18: `user.identity.pan`
* **File Location:** [`smart_money_ai/intelligence/investment_engine/investment_recommendations_backend.py`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/smart_money_ai/intelligence/investment_engine/investment_recommendations_backend.py#L735)
  * **Line 735:** `"2. Complete KYC with Aadhaar and PAN",`
  * **Line 746:** `"1. Keep PAN card and Aadhaar ready",`
* **Scanner Error Type:** **Static Instructional Text Matching**
* **Root Cause:** Hardcoded onboarding guidance text. No 10-character alphanumeric PAN regex pattern, database column, or ingestion endpoint exists.

---

### Item 19: `user.identity.passport`
* **File Location 1:** [`budgeting_ml_model/src/mega_dataset_generator.py`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/budgeting_ml_model/src/mega_dataset_generator.py#L181)
  * **Line 181:** `'Passport Fee', 'Visa Fee', 'License Fee', 'Registration Fee', 'Court Fee'`
* **File Location 2:** [`budgeting_ml_model/src/pro_plus_dataset_generator.py`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/budgeting_ml_model/src/pro_plus_dataset_generator.py#L215)
  * **Line 215:** `'Passport Seva', 'Aadhaar Center', 'Jan Aushadhi'`
* **Scanner Error Type:** **Mock Merchant / Expense Label Confusion**
* **Root Cause:** Static string literals in mock transaction categories and government merchant lists. No passport number collection or storage exists.

---

## 3. False Negatives: Undetected Active PII
*The scanner completely failed to detect these 7 active personal data elements stored in the database models.*

### Item 20: `user.name` (Full Name)
* **File Location 1:** [`smart_money_ai/utils/data_manager.py`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/smart_money_ai/utils/data_manager.py#L48)
  * **Line 48:** `name TEXT NOT NULL,` in `CREATE TABLE users`
* **File Location 2:** [`smart_money_ai/core/smart_money_ai.py`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/smart_money_ai/core/smart_money_ai.py#L79)
  * **Line 79:** `name: str` in dataclass `UserProfile`
* **File Location 3:** [`frontend_static/index.html`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/frontend_static/index.html#L39)
  * **Line 39:** Rendered in avatar and greeting header
* **Finding:** Stored in primary SQLite user records and rendered in user dashboard.

---

### Item 21: `user.demographics.age`
* **File Location 1:** [`smart_money_ai/utils/data_manager.py`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/smart_money_ai/utils/data_manager.py#L51)
  * **Line 51:** `age INTEGER,` in `CREATE TABLE users`
* **File Location 2:** [`smart_money_ai/core/smart_money_ai.py`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/smart_money_ai/core/smart_money_ai.py#L82)
  * **Line 82:** `age: int` in dataclass `UserProfile`
* **Finding:** Stored in database; primary factor for life-cycle asset allocation and risk modeling.

---

### Item 22: `user.financial.annual_income`
* **File Location 1:** [`smart_money_ai/utils/data_manager.py`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/smart_money_ai/utils/data_manager.py#L52)
  * **Line 52:** `annual_income REAL,` in `CREATE TABLE users`
  * **Line 130:** `user_data['annual_income'],`
* **File Location 2:** [`smart_money_ai/core/smart_money_ai.py`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/smart_money_ai/core/smart_money_ai.py#L83)
  * **Line 83:** `annual_income: float`
* **Finding:** Primary financial attribute used to calculate debt-to-income and savings capacity.

---

### Item 23: `user.financial.risk_profile`
* **File Location 1:** [`smart_money_ai/utils/data_manager.py`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/smart_money_ai/utils/data_manager.py#L53)
  * **Line 53:** `risk_profile TEXT,` in `CREATE TABLE users`
  * **Line 131:** `user_data['risk_profile'],`
* **File Location 2:** [`smart_money_ai/core/smart_money_ai.py`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/smart_money_ai/core/smart_money_ai.py#L84)
  * **Line 84:** `risk_profile: str`
* **Finding:** Behavioral psychometric risk score ("conservative", "moderate", "aggressive") stored in SQLite.

---

### Item 24: `user.financial.goals` & `investment_timeline`
* **File Location 1:** [`smart_money_ai/utils/data_manager.py`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/smart_money_ai/utils/data_manager.py#L54)
  * **Line 54:** `investment_timeline INTEGER,` in `CREATE TABLE users`
  * **Line 55:** `financial_goals TEXT,`
  * **Lines 116-117:** `financial_goals_json = json.dumps(user_data.get('financial_goals', []))`
* **File Location 2:** [`smart_money_ai/core/smart_money_ai.py`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/smart_money_ai/core/smart_money_ai.py#L85)
  * **Lines 85-86:** `investment_timeline: int`, `financial_goals: List[str]`
* **Finding:** User's financial objectives and investment horizon saved in user record.

---

### Item 25: `user.financial.transaction_metadata`
* **File Location 1:** [`smart_money_ai/utils/data_manager.py`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/smart_money_ai/utils/data_manager.py#L64)
  * **Lines 64-77:** Columns `amount REAL`, `balance REAL`, `merchant TEXT`, `category TEXT`, `user_id TEXT`
* **File Location 2:** [`smart_money_ai/core/sms_parser/enhanced_sms_parser.py`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/smart_money_ai/core/sms_parser/enhanced_sms_parser.py#L28)
  * **Lines 28-35:** Dataclass attributes linking raw transaction records to user profiles.
* **Finding:** Stores detailed transaction amounts, merchant names, and remaining balances per user.

---

### Item 26: `user.identity.avatar_url` (Name in Avatar URL)
* **File Location:** [`frontend_static/index.html`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/frontend_static/index.html#L39)
  * **Line 39:** `<img src="https://ui-avatars.com/api/?name=Demo+User&background=6366f1&color=fff" alt="User Avatar">`
* **Finding:** User display name passed in external GET query parameters (`?name=...`) directly to an external CDN.

---

## 4. False Negatives: Undetected Third-Party Vendors & SDKs
*The Systems catalog failed to detect these external dependencies and APIs.*

### Item 27: UI-Avatars CDN
* **File Location:** [`frontend_static/index.html`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/frontend_static/index.html#L39)
  * **Line 39:** `https://ui-avatars.com/api/?name=Demo+User`
* **Vendor Role:** External user avatar generator transmitting raw user names in query strings.

---

### Item 28: Ionicons / Unpkg CDN
* **File Location:** [`frontend_static/index.html`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/frontend_static/index.html#L11)
  * **Line 11:** `<script type="module" src="https://unpkg.com/ionicons@7.1.0/dist/ionicons/ionicons.esm.js"></script>`
  * **Line 12:** `<script nomodule src="https://unpkg.com/ionicons@7.1.0/dist/ionicons/ionicons.js"></script>`
* **Vendor Role:** Client-side script loaded from external `unpkg.com` CDN without Subresource Integrity (SRI) hashes.

---

### Item 29: Google Fonts
* **File Location:** [`frontend_static/index.html`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/frontend_static/index.html#L8)
  * **Line 8:** `<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">`
* **Vendor Role:** External typography CDN exposing client IP and User-Agent to Google.

---

### Item 30: ICICI Securities Breeze API
* **File Location 1:** [`smart_money_ai/api/breeze_trading_engine.py`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/smart_money_ai/api/breeze_trading_engine.py#L2)
  * **Line 2:** `Breeze API Trading Engine Integration`
  * **Line 32:** `class BreezeAPIError(Exception):`
* **File Location 2:** [`integrations/breeze_trading.py`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/integrations/breeze_trading.py#L24)
* **Vendor Role:** External trading API SDK connecting to ICICI Direct to execute market orders and fetch demat holdings.

---

### Item 31: Finnhub Market Data API
* **File Location 1:** [`smart_money_ai/data/finnhub_integration.py`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/smart_money_ai/data/finnhub_integration.py#L2)
  * **Line 2:** `Finnhub API Integration for Real-Time Market Data`
  * **Line 49:** `class FinnhubMarketDataStreamer:`
* **File Location 2:** [`integrations/finnhub_market_data.py`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/integrations/finnhub_market_data.py#L16)
* **Vendor Role:** Outbound REST API transmitting stock symbols and fetching real-time market telemetry.

---

### Item 32: Kaggle API / Kagglehub
* **File Location 1:** [`test_kaggle_adapter.py`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/test_kaggle_adapter.py#L3)
  * **Line 3:** `Test the provided Kaggle dataset loading code`
* **File Location 2:** [`examine_behavioral_finance_dataset.py`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/examine_behavioral_finance_dataset.py#L6)
  * **Line 6:** `import kagglehub`
* **File Location 3:** [`smart_money_ai/ml_models/investment_recommendation_model.py`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/smart_money_ai/ml_models/investment_recommendation_model.py#L37)
  * **Line 37:** `import kagglehub`
* **Vendor Role:** Python client library communicating with `api.kaggle.com` for machine learning dataset retrieval.

---

## 5. Detected Database System

### Item 33: SQLite Database
* **File Location 1:** [`smart_money_ai/utils/data_manager.py`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/smart_money_ai/utils/data_manager.py#L12)
  * **Line 12:** `import sqlite3`
  * **Line 26:** `db_path = data_dir / "smart_money.db"`
* **File Location 2:** Database file paths:
  * [`test_data_validation/smart_money.db`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/test_data_validation/smart_money.db)
  * [`smart_money_ai/data/raw/smart_money.db`](file:///Users/harshitrawal/Downloads/complydp/ocr/smart-money-ai/smart_money_ai/data/raw/smart_money.db)
* **Verdict / Finding:** Accurately detected embedded relational database used for all application data storage.
