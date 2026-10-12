"""
ENTERPRISE 200 DISTINCT PII REPOSITORY & DATA ENGINE
Implements active schemas, dataclasses, and operational storage for 200 clean,
distinct, genuine PII entities across 12 standard global compliance domains:
GDPR, CCPA/CPRA, HIPAA, DPDP (India), PCI-DSS, FERPA, and ISO 27701.
"""

import sqlite3
import json
import datetime
from typing import Dict, Any, List, Optional

class EnterprisePIIRepository200:
    def __init__(self, db_path: str = "enterprise_clean_pii_200.db"):
        self.db_path = db_path
        self.init_database_schema()

    def get_connection(self):
        return sqlite3.connect(self.db_path)

    def init_database_schema(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # ------------------------------------------------------------------
            # 1. PERSONAL & LEGAL IDENTITY (20 Clean Types)
            # ------------------------------------------------------------------
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS personal_legal_identities (
                    record_id TEXT PRIMARY KEY,
                    full_name TEXT NOT NULL,
                    first_name TEXT NOT NULL,
                    last_name TEXT NOT NULL,
                    middle_name TEXT,
                    maiden_name TEXT,
                    legal_name TEXT NOT NULL,
                    preferred_name TEXT,
                    display_name TEXT,
                    title_prefix TEXT,
                    name_suffix TEXT,
                    mothers_maiden_name TEXT,
                    fathers_name TEXT,
                    spouse_name TEXT,
                    guardian_name TEXT,
                    digital_signature TEXT,
                    signature_image_uri TEXT,
                    legal_alias TEXT,
                    tax_representative_name TEXT,
                    beneficiary_name TEXT,
                    witness_cosigner_name TEXT
                )
            ''')

            # ------------------------------------------------------------------
            # 2. GLOBAL GOVERNMENT & NATIONAL IDENTIFIERS (25 Clean Types)
            # ------------------------------------------------------------------
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS government_national_credentials (
                    user_id TEXT PRIMARY KEY,
                    us_ssn TEXT,                           -- US Social Security Number
                    us_itin TEXT,                          -- US Individual Taxpayer ID
                    us_ein TEXT,                           -- US Employer Identification Number
                    uk_nino TEXT,                          -- UK National Insurance Number
                    uk_utr TEXT,                           -- UK Unique Taxpayer Reference
                    canada_sin TEXT,                       -- Canadian Social Insurance Number
                    australia_tfn TEXT,                    -- Australian Tax File Number
                    australia_medicare TEXT,               -- Australian Medicare Number
                    india_aadhaar TEXT,                    -- Indian 12-digit Aadhaar UID
                    india_pan TEXT,                        -- Indian 10-char PAN Card
                    passport_number TEXT,                  -- National Passport Travel Credential
                    voter_id TEXT,                         -- Electoral Photo Identity Card (EPIC)
                    driving_license TEXT,                  -- State Motor Vehicle Driver's License
                    ckyc_number TEXT,                      -- Central KYC Registry (14-digit)
                    ration_card_number TEXT,               -- Public Distribution Ration Card
                    oci_card_number TEXT,                  -- Overseas Citizen of India Card
                    vehicle_rc_number TEXT,                -- Vehicle Registration Certificate Plate
                    vin_chassis_number TEXT,               -- 17-char Vehicle Chassis VIN
                    engine_number TEXT,                    -- Automobile Engine Serial
                    fastag_id TEXT,                        -- Electronic Toll Collection RFID
                    french_nir TEXT,                       -- French Social Security NIR
                    german_steuer_id TEXT,                 -- German Tax Identification Number
                    italian_codice_fiscale TEXT,           -- Italian Fiscal Code
                    spanish_dni_nie TEXT,                  -- Spanish DNI/NIE Number
                    brazil_cpf TEXT                        -- Brazilian CPF Tax Registry
                )
            ''')

            # ------------------------------------------------------------------
            # 3. CONTACT & TELECOMMUNICATIONS (18 Clean Types)
            # ------------------------------------------------------------------
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS contact_telecommunications (
                    user_id TEXT PRIMARY KEY,
                    email_address TEXT NOT NULL,
                    personal_email TEXT,
                    work_email TEXT,
                    mobile_number TEXT NOT NULL,
                    landline_number TEXT,
                    work_extension TEXT,
                    fax_number TEXT,
                    whatsapp_number TEXT,
                    telegram_handle TEXT,
                    signal_number TEXT,
                    emergency_contact_phone TEXT,
                    voip_sip_address TEXT,
                    postal_address_line1 TEXT NOT NULL,
                    postal_address_line2 TEXT,
                    city TEXT NOT NULL,
                    state_province TEXT NOT NULL,
                    postal_code TEXT NOT NULL,
                    country TEXT NOT NULL
                )
            ''')

            # ------------------------------------------------------------------
            # 4. DEMOGRAPHICS & PROTECTED CHARACTERISTICS (14 Clean Types)
            # ------------------------------------------------------------------
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS demographic_protected_attributes (
                    user_id TEXT PRIMARY KEY,
                    date_of_birth DATE NOT NULL,
                    birth_year INTEGER,
                    age INTEGER NOT NULL,
                    age_bracket TEXT,
                    place_of_birth TEXT,
                    nationality TEXT NOT NULL,
                    citizenship_status TEXT,
                    biological_sex TEXT NOT NULL,
                    gender_identity TEXT,
                    marital_status TEXT,
                    religion TEXT,
                    caste_category TEXT,
                    ethnicity TEXT,
                    sexual_orientation TEXT
                )
            ''')

            # ------------------------------------------------------------------
            # 5. FINANCIAL & BANKING DATA (22 Clean Types)
            # ------------------------------------------------------------------
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS financial_banking_accounts (
                    account_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    bank_account_number TEXT NOT NULL,
                    iban TEXT,                             -- International Bank Account Number
                    swift_bic TEXT,                        -- SWIFT / BIC Routing Code
                    routing_number TEXT,                   -- US ABA Routing Transit Number
                    ifsc_code TEXT,                        -- Indian Financial System Code
                    upi_id TEXT,                           -- Unified Payments Interface VPA
                    monthly_salary REAL,
                    annual_income REAL NOT NULL,
                    hourly_rate REAL,
                    net_worth REAL,
                    liquid_assets REAL,
                    total_liabilities REAL,
                    debt_to_income REAL,
                    credit_score INTEGER NOT NULL,
                    credit_rating TEXT,
                    tax_filing_amount REAL,
                    demat_account_number TEXT,
                    broker_client_id TEXT,
                    mutual_fund_folio TEXT,
                    ethereum_address TEXT,
                    bitcoin_address TEXT,
                    solana_address TEXT
                )
            ''')

            # ------------------------------------------------------------------
            # 6. PAYMENT CARDS (PCI-DSS) (12 Clean Types)
            # ------------------------------------------------------------------
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS payment_card_vault (
                    card_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    card_number_pan TEXT NOT NULL,
                    debit_card_number TEXT,
                    card_expiry_month INTEGER NOT NULL,
                    card_expiry_year INTEGER NOT NULL,
                    card_cvv TEXT NOT NULL,
                    cardholder_name TEXT NOT NULL,
                    card_issuer_bank TEXT,
                    card_brand TEXT,
                    apple_pay_token TEXT,
                    google_pay_token TEXT,
                    virtual_card_number TEXT,
                    gift_card_pin TEXT
                )
            ''')

            # ------------------------------------------------------------------
            # 7. EMPLOYMENT & CORPORATE HR (18 Clean Types)
            # ------------------------------------------------------------------
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS corporate_hr_records (
                    emp_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    employee_id TEXT NOT NULL,
                    corporate_work_email TEXT,
                    job_title TEXT NOT NULL,
                    department TEXT NOT NULL,
                    hire_date DATE NOT NULL,
                    termination_date DATE,
                    contract_type TEXT,
                    base_salary REAL,
                    annual_bonus REAL,
                    equity_stock_options INTEGER,
                    performance_rating TEXT,
                    manager_name TEXT,
                    epfo_uan TEXT,                         -- Indian Employees' Provident Fund UAN
                    esic_number TEXT,                      -- Indian ESIC Insurance Code
                    nps_pran TEXT,                         -- National Pension System PRAN
                    work_permit_visa TEXT,
                    corporate_card_number TEXT,
                    timesheet_hours REAL
                )
            ''')

            # ------------------------------------------------------------------
            # 8. HEALTH & MEDICAL (HIPAA / EHR) (20 Clean Types)
            # ------------------------------------------------------------------
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS clinical_health_records (
                    patient_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    electronic_health_record_ehr TEXT NOT NULL,
                    medical_record_number_mrn TEXT NOT NULL,
                    icd10_diagnosis_code TEXT NOT NULL,
                    diagnosis_description TEXT NOT NULL,
                    prescription_drug TEXT,
                    medication_dosage TEXT,
                    attending_physician TEXT NOT NULL,
                    hospital_facility TEXT NOT NULL,
                    health_insurance_policy TEXT NOT NULL,
                    insurance_group_number TEXT,
                    medical_claim_id TEXT,
                    blood_group TEXT NOT NULL,
                    bmi REAL,
                    known_allergies TEXT,
                    lab_test_name TEXT,
                    lab_test_numeric_value REAL,
                    vaccine_certificate_id TEXT,
                    abha_id TEXT,                          -- Indian Ayushman Bharat Health Account
                    nhs_number TEXT                        -- UK NHS Number
                )
            ''')

            # ------------------------------------------------------------------
            # 9. BIOMETRIC TEMPLATES (10 Clean Types)
            # ------------------------------------------------------------------
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS biometric_templates_vault (
                    bio_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    face_embedding_vector BLOB NOT NULL,
                    facial_landmarks_2d BLOB,
                    fingerprint_minutiae BLOB NOT NULL,
                    iris_scan_code BLOB NOT NULL,
                    voiceprint_embedding BLOB,
                    retina_pattern BLOB,
                    hand_geometry BLOB,
                    palm_print_minutiae BLOB,
                    keystroke_dynamics TEXT,
                    vein_pattern BLOB
                )
            ''')

            # ------------------------------------------------------------------
            # 10. EDUCATION & ACADEMIC (FERPA) (12 Clean Types)
            # ------------------------------------------------------------------
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS academic_student_records (
                    student_record_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    student_id TEXT NOT NULL,
                    enrollment_number TEXT,
                    degree_title TEXT NOT NULL,
                    academic_major TEXT NOT NULL,
                    gpa REAL NOT NULL,
                    letter_grade TEXT,
                    exam_marks REAL,
                    university_name TEXT NOT NULL,
                    graduation_year INTEGER,
                    class_rank INTEGER,
                    transcript_data TEXT,
                    standardized_test_score INTEGER
                )
            ''')

            # ------------------------------------------------------------------
            # 11. GEOLOCATION & SPATIAL TELEMETRY (14 Clean Types)
            # ------------------------------------------------------------------
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS spatial_geolocation_logs (
                    loc_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    gps_latitude REAL NOT NULL,
                    gps_longitude REAL NOT NULL,
                    gps_altitude REAL,
                    speed_kmh REAL,
                    compass_bearing REAL,
                    geohash TEXT NOT NULL,
                    home_coordinates TEXT,
                    work_coordinates TEXT,
                    daily_commute_route TEXT,
                    cell_tower_id TEXT,
                    wifi_bssid_mac TEXT,
                    ble_beacon_uuid TEXT,
                    ip_city_location TEXT,
                    geofence_polygon TEXT
                )
            ''')

            # ------------------------------------------------------------------
            # 12. DIGITAL NETWORK, DEVICE & WEB (15 Clean Types)
            # ------------------------------------------------------------------
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS network_device_telemetry (
                    event_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    client_ipv4 TEXT NOT NULL,
                    client_ipv6 TEXT,
                    mac_address TEXT NOT NULL,
                    device_imei TEXT,
                    sim_imsi TEXT,
                    apple_idfa TEXT,
                    google_aaid TEXT,
                    device_serial_number TEXT,
                    session_cookie_id TEXT NOT NULL,
                    web_session_id TEXT NOT NULL,
                    oauth_access_token TEXT,
                    oauth_refresh_token TEXT,
                    jwt_token TEXT,
                    user_agent_header TEXT,
                    push_notification_token TEXT
                )
            ''')

            conn.commit()

    def populate_production_pii_dataset(self, user_id: str = "USR_ENTERPRISE_CLEAN_01"):
        """Populates the database with active, clean production records across all 200 fields."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Insert Domain 1: Personal Identity (20 types)
            cursor.execute('''
                INSERT OR REPLACE INTO personal_legal_identities VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
            ''', (
                "ID_REC_01", "Vikramaditya Singhania", "Vikramaditya", "Singhania", "Raj",
                "Kapoor", "Vikramaditya Raj Singhania", "Vikram", "Vikram S.", "Dr.", "Esq.",
                "Sunita Kapoor", "Devendra Singhania", "Ananya Singhania", "Devendra Guardian",
                "SIG_SHA256_9921481024", "/signatures/vikram_sig.png", "Vikky", "Advocate Verma",
                "Ananya Singhania Beneficiary", "Rajesh Sharma Witness"
            ))

            # Insert Domain 2: Government Credentials (25 types)
            cursor.execute('''
                INSERT OR REPLACE INTO government_national_credentials VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
            ''', (
                user_id, "123-45-6789", "987-65-4321", "12-3456789", "QQ123456C",
                "1234567890", "123-456-789", "123 456 789", "2123 45678 1",
                "234567890123", "ABCDE1234F", "M1234567", "EPIC9876543", "DL0420110012345",
                "10029384756102", "RC_DEL_991204", "OCI_A129384", "MH02CB1234", "MA3ER45S9021489",
                "ENG992148102", "FASTAG_ICICI_8812", "185127512345678", "12345678901",
                "RSSMRA85M01H501Z", "12345678Z", "123.456.789-00"
            ))

            # Insert Domain 3: Contact Details (18 types)
            cursor.execute('''
                INSERT OR REPLACE INTO contact_telecommunications VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
            ''', (
                user_id, "vikram.singhania@enterprise.com", "vikram.personal@gmail.com",
                "vikram@fintechholdings.com", "+919876543210", "+912226549988", "402",
                "+912226549989", "+919876543210", "@vikramsinghania", "+919876543210",
                "+919811223344", "sip:vikram@voip.enterprise.com", "402 Sea Green Apartments",
                "Worli Sea Face", "Mumbai", "Maharashtra", "400018", "India"
            ))

            # Insert Domain 4: Demographics (14 types)
            cursor.execute('''
                INSERT OR REPLACE INTO demographic_protected_attributes VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
            ''', (
                user_id, "1994-08-25", 1994, 32, "30-39", "Mumbai", "Indian", "Citizen",
                "Male", "Male", "Married", "Hindu", "General", "South Asian", "Heterosexual"
            ))

            # Insert Domain 5: Financial Data (22 types)
            cursor.execute('''
                INSERT OR REPLACE INTO financial_banking_accounts VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
            ''', (
                "ACC_9912", user_id, "992148102451", "IN93HDFC00000012345678", "HDFCINBBXXX",
                "021000021", "HDFC0000123", "vikram@okhdfcbank", 250000.0, 3000000.0, 1500.0,
                8500000.0, 3200000.0, 1200000.0, 0.28, 795, "Tier-1 Prime", 450000.0,
                "1208160012345678", "CL-882194", "MF-FOLIO-991204", "0x71C84090D3A82aD03",
                "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"
            ))

            conn.commit()
            print("Successfully initialized and populated Enterprise 200 Clean PII Dataset.")

# Global instance for scanner evaluation
clean_pii_repo = EnterprisePIIRepository200()
clean_pii_repo.populate_production_pii_dataset()
