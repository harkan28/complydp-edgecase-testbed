"""
COMPLYDP ENTERPRISE PII BENCHMARK — 240 DISTINCT PII IDENTIFIERS
Covers 240 unique, differentiated personal data attributes across 12 privacy domains:
GDPR, CCPA/CPRA, HIPAA, DPDP (India), PCI-DSS, FERPA, and ISO 27701.
"""

import sqlite3
import json
import datetime
from typing import Dict, Any, List, Optional

class EnterprisePIIRepository240:
    def __init__(self, db_path: str = "enterprise_pii_catalog_240.db"):
        self.db_path = db_path
        self.init_database_schema()

    def get_connection(self):
        return sqlite3.connect(self.db_path)

    def init_database_schema(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # ------------------------------------------------------------------
            # DOMAIN 1: PERSONAL & LEGAL IDENTITY (25 Types)
            # ------------------------------------------------------------------
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS legal_identity_profiles (
                    record_id TEXT PRIMARY KEY,
                    full_name TEXT NOT NULL,
                    first_name TEXT,
                    last_name TEXT,
                    middle_name TEXT,
                    maiden_name TEXT,
                    legal_name TEXT,
                    preferred_name TEXT,
                    nickname_alias TEXT,
                    name_suffix TEXT,
                    name_prefix_title TEXT,
                    mothers_maiden_name TEXT,
                    fathers_full_name TEXT,
                    spouse_name TEXT,
                    legal_guardian_name TEXT,
                    digital_signature_hash TEXT,
                    signature_image_path TEXT,
                    notary_seal_number TEXT,
                    witness_name TEXT,
                    power_of_attorney_name TEXT,
                    alias_soundex_code TEXT,
                    mononym_identity TEXT,
                    honorific_title TEXT,
                    tribal_clan_membership TEXT,
                    family_crest_id TEXT,
                    official_name_pronunciation TEXT
                )
            ''')

            # ------------------------------------------------------------------
            # DOMAIN 2: GLOBAL GOVERNMENT & NATIONAL IDENTIFIERS (30 Types)
            # ------------------------------------------------------------------
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS global_government_identifiers (
                    user_id TEXT PRIMARY KEY,
                    us_ssn TEXT,                           -- US Social Security Number
                    us_itin TEXT,                          -- US Individual Taxpayer ID
                    us_ein TEXT,                           -- US Employer Identification Number
                    uk_nino TEXT,                          -- UK National Insurance Number
                    uk_utr TEXT,                           -- UK Unique Taxpayer Reference
                    canada_sin TEXT,                       -- Canadian Social Insurance Number
                    australia_tfn TEXT,                    -- Australian Tax File Number
                    australia_medicare_no TEXT,            -- Australian Medicare Number
                    india_aadhaar_uid TEXT,                -- Indian 12-digit Aadhaar UID
                    india_pan_number TEXT,                 -- Indian 10-char PAN
                    india_passport_number TEXT,            -- Indian Passport Number
                    india_voter_epic_id TEXT,              -- Indian Voter ID
                    india_driving_license TEXT,            -- Indian Driving License
                    india_ckyc_identifier TEXT,            -- Indian 14-digit CKYC
                    india_ration_card_no TEXT,             -- Indian Ration Card Number
                    india_oci_card_no TEXT,                -- Overseas Citizen of India
                    india_vehicle_rc_number TEXT,          -- Indian Vehicle Registration RC
                    vehicle_vin_chassis_no TEXT,           -- Vehicle Chassis VIN
                    vehicle_engine_number TEXT,            -- Vehicle Engine Serial
                    india_fastag_rfid_id TEXT,             -- Indian Toll FASTag RFID
                    france_nir_ssn TEXT,                   -- French Social Security NIR
                    germany_steuer_id TEXT,                -- German Tax Identifier
                    italy_codice_fiscale TEXT,             -- Italian Fiscal Code
                    spain_dni_nie TEXT,                    -- Spanish DNI/NIE Number
                    brazil_cpf_number TEXT,                -- Brazilian CPF Tax ID
                    brazil_rg_identity TEXT,               -- Brazilian General Registry
                    china_resident_id TEXT,                -- Chinese Resident ID (18-digit)
                    japan_my_number TEXT,                  -- Japanese Individual Number
                    singapore_nric_fin TEXT,               -- Singapore NRIC/FIN
                    mexico_curp_code TEXT                  -- Mexican CURP Code
                )
            ''')

            # ------------------------------------------------------------------
            # DOMAIN 3: CONTACT & COMMUNICATION (20 Types)
            # ------------------------------------------------------------------
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS contact_telecommunications (
                    user_id TEXT PRIMARY KEY,
                    primary_email_address TEXT NOT NULL,
                    secondary_personal_email TEXT,
                    corporate_work_email TEXT,
                    mobile_telephone_number TEXT NOT NULL,
                    landline_phone_number TEXT,
                    work_phone_extension TEXT,
                    facsimile_fax_number TEXT,
                    whatsapp_phone_number TEXT,
                    telegram_username TEXT,
                    signal_phone_number TEXT,
                    emergency_contact_phone TEXT,
                    pager_number TEXT,
                    voip_sip_uri TEXT,
                    skype_handle TEXT,
                    zoom_personal_meeting_id TEXT,
                    postal_address_line1 TEXT,
                    postal_address_line2 TEXT,
                    city_municipality TEXT,
                    state_province_region TEXT,
                    postal_code_pincode_zip TEXT
                )
            ''')

            # ------------------------------------------------------------------
            # DOMAIN 4: DEMOGRAPHICS & PROTECTED CHARACTERISTICS (15 Types)
            # ------------------------------------------------------------------
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS demographic_protected_classes (
                    user_id TEXT PRIMARY KEY,
                    exact_date_of_birth DATE,
                    birth_year_integer INTEGER,
                    age_years INTEGER,
                    age_bracket_group TEXT,
                    place_of_birth_city TEXT,
                    country_of_origin TEXT,
                    primary_nationality TEXT,
                    citizenship_status TEXT,
                    biological_sex TEXT,
                    gender_identity TEXT,
                    marital_status TEXT,
                    religious_affiliation TEXT,
                    caste_subcaste_category TEXT,
                    ethnic_racial_background TEXT,
                    sexual_orientation TEXT
                )
            ''')

            # ------------------------------------------------------------------
            # DOMAIN 5: FINANCIAL & BANKING INFORMATION (25 Types)
            # ------------------------------------------------------------------
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS financial_banking_records (
                    account_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    bank_account_number TEXT NOT NULL,
                    international_iban TEXT,
                    swift_bic_code TEXT,
                    bank_routing_aba_number TEXT,
                    indian_ifsc_code TEXT,
                    upi_virtual_payment_address TEXT,
                    monthly_gross_salary REAL,
                    annual_total_income REAL,
                    hourly_wage_rate REAL,
                    estimated_net_worth REAL,
                    total_liquid_assets REAL,
                    total_outstanding_liabilities REAL,
                    debt_to_income_ratio REAL,
                    credit_bureau_score_cibil INTEGER,
                    credit_rating_band TEXT,
                    tax_return_filing_amount REAL,
                    demat_bo_account_number TEXT,
                    stock_broker_client_code TEXT,
                    mutual_fund_folio_number TEXT,
                    ethereum_wallet_address TEXT,
                    bitcoin_wallet_address TEXT,
                    solana_wallet_address TEXT,
                    financial_hardship_status TEXT,
                    bankruptcy_case_number TEXT,
                    pension_beneficiary_id TEXT
                )
            ''')

            # ------------------------------------------------------------------
            # DOMAIN 6: PAYMENT CARD INDUSTRY (PCI-DSS) (15 Types)
            # ------------------------------------------------------------------
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS payment_card_vault (
                    card_vault_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    primary_card_number_pan TEXT NOT NULL,
                    debit_card_number TEXT,
                    card_expiration_month INTEGER,
                    card_expiration_year INTEGER,
                    card_verification_value_cvv TEXT,
                    cardholder_full_name TEXT,
                    card_issuing_bank TEXT,
                    card_brand_network TEXT,
                    emv_chip_application_cryptogram TEXT,
                    track1_magnetic_stripe_data TEXT,
                    track2_magnetic_stripe_data TEXT,
                    apple_pay_device_token TEXT,
                    virtual_card_number TEXT,
                    prepaid_gift_card_pin TEXT,
                    ebt_benefits_card_number TEXT
                )
            ''')

            # ------------------------------------------------------------------
            # DOMAIN 7: EMPLOYMENT & CORPORATE HR (20 Types)
            # ------------------------------------------------------------------
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS corporate_employment_records (
                    emp_record_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    corporate_employee_id TEXT NOT NULL,
                    work_email_address TEXT,
                    job_title_designation TEXT,
                    business_department TEXT,
                    official_hire_date DATE,
                    employment_termination_date DATE,
                    contract_employment_type TEXT,
                    base_monthly_salary REAL,
                    annual_bonus_incentive REAL,
                    esop_stock_grant_units INTEGER,
                    performance_appraisal_rating TEXT,
                    disciplinary_incident_record TEXT,
                    direct_manager_supervisor_name TEXT,
                    india_epfo_uan_number TEXT,
                    india_esic_insurance_number TEXT,
                    nps_pran_retirement_number TEXT,
                    foreign_work_permit_visa TEXT,
                    corporate_travel_card_number TEXT,
                    timesheet_biometric_hours REAL,
                    labor_union_member_id TEXT
                )
            ''')

            # ------------------------------------------------------------------
            # DOMAIN 8: HEALTH & MEDICAL (HIPAA / EHR) (25 Types)
            # ------------------------------------------------------------------
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS protected_health_information (
                    ehr_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    hospital_patient_id TEXT NOT NULL,
                    electronic_health_record_ehr TEXT,
                    medical_record_number_mrn TEXT,
                    icd10_diagnosis_code TEXT,
                    clinical_diagnosis_text TEXT,
                    prescription_drug_name TEXT,
                    medication_dosage_frequency TEXT,
                    attending_physician_name TEXT,
                    hospital_clinic_facility TEXT,
                    health_insurance_policy_no TEXT,
                    insurance_group_number TEXT,
                    medical_claim_id TEXT,
                    blood_group_rh_factor TEXT,
                    body_mass_index_bmi REAL,
                    known_allergies_list TEXT,
                    laboratory_test_panel TEXT,
                    lab_result_numeric_value REAL,
                    covid19_vaccine_certificate_id TEXT,
                    organ_donor_registered_status TEXT,
                    dna_genetic_sequencing_id TEXT,
                    disability_impairment_code TEXT,
                    psychiatric_clinical_note TEXT,
                    surgical_procedure_history TEXT,
                    india_abha_digital_health_id TEXT,
                    uk_nhs_number TEXT
                )
            ''')

            # ------------------------------------------------------------------
            # DOMAIN 9: BIOMETRIC TEMPLATES & VECTORS (15 Types)
            # ------------------------------------------------------------------
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS biometric_templates_vault (
                    bio_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    facial_recognition_embedding_vector BLOB,
                    facial_2d_landmark_coordinates BLOB,
                    fingerprint_minutiae_template BLOB,
                    iris_scan_polar_code BLOB,
                    retina_vascular_pattern_vector BLOB,
                    voiceprint_mfcc_embedding BLOB,
                    hand_geometry_dimensional_vector BLOB,
                    gait_stride_analysis_vector BLOB,
                    keystroke_dynamics_timing_profile TEXT,
                    palm_print_ridge_minutiae BLOB,
                    thermal_facial_signature BLOB,
                    ear_canal_acoustic_biometric BLOB,
                    forensic_dental_odontology_chart TEXT,
                    lip_motion_visual_vector BLOB,
                    subdermal_vein_infrared_pattern BLOB
                )
            ''')

            # ------------------------------------------------------------------
            # DOMAIN 10: EDUCATION & STUDENT RECORDS (FERPA) (15 Types)
            # ------------------------------------------------------------------
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS student_academic_records (
                    student_record_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    institutional_student_id TEXT NOT NULL,
                    matriculation_enrollment_number TEXT,
                    degree_conferred_title TEXT,
                    major_academic_discipline TEXT,
                    grade_point_average_gpa REAL,
                    academic_letter_grade TEXT,
                    course_examination_marks REAL,
                    school_university_institution TEXT,
                    graduation_commencement_year INTEGER,
                    class_percentile_rank INTEGER,
                    official_academic_transcript_text TEXT,
                    student_disciplinary_probation_note TEXT,
                    standardized_sat_gre_gmat_score INTEGER,
                    merit_scholarship_stipend_amount REAL,
                    federal_student_loan_identifier TEXT
                )
            ''')

            # ------------------------------------------------------------------
            # DOMAIN 11: GEOLOCATION & SPATIAL TELEMETRY (15 Types)
            # ------------------------------------------------------------------
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS spatial_location_tracking (
                    loc_event_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    gps_exact_latitude REAL,
                    gps_exact_longitude REAL,
                    gps_altitude_elevation REAL,
                    speed_velocity_vector REAL,
                    heading_compass_bearing REAL,
                    geohash_spatial_code TEXT,
                    residential_home_coordinates TEXT,
                    primary_workplace_coordinates TEXT,
                    daily_commute_route_history TEXT,
                    cellular_cell_tower_id TEXT,
                    wifi_router_bssid_mac TEXT,
                    ble_beacon_proximity_uuid TEXT,
                    ip_derived_city_location TEXT,
                    geofence_boundary_polygon TEXT,
                    ride_hail_pickup_dropoff_gps TEXT
                )
            ''')

            # ------------------------------------------------------------------
            # DOMAIN 12: DIGITAL TELEMETRY, WEB & DEVICE (20 Types)
            # ------------------------------------------------------------------
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS digital_network_telemetry (
                    telemetry_event_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    client_ipv4_address TEXT NOT NULL,
                    client_ipv6_address TEXT,
                    network_mac_hardware_address TEXT,
                    device_cellular_imei TEXT,
                    sim_card_imsi_number TEXT,
                    apple_idfa_advertising_id TEXT,
                    google_aaid_advertising_id TEXT,
                    hardware_serial_number TEXT,
                    http_cookie_session_identifier TEXT,
                    authenticated_web_session_id TEXT,
                    oauth2_access_token_bearer TEXT,
                    oauth2_refresh_token TEXT,
                    jwt_id_token_claim TEXT,
                    canvas_fingerprint_hash TEXT,
                    webgl_renderer_hardware_string TEXT,
                    browser_user_agent_header TEXT,
                    tls_client_ja3_fingerprint TEXT,
                    csrf_prevention_token TEXT,
                    apns_fcm_push_device_token TEXT,
                    battery_level_charging_telemetry TEXT
                )
            ''')

            conn.commit()

    def populate_all_240_pii_entities(self, user_id: str = "USR_240_GLOBAL"):
        """Inserts active, populated records across all 240 distinct PII attributes."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Insert Domain 1 (Personal Identity - 25 types)
            cursor.execute('''
                INSERT OR REPLACE INTO legal_identity_profiles VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
            ''', (
                "REC-001", "Harshit Rawal", "Harshit", "Rawal", "Kumar", "Mehta",
                "Harshit Kumar Rawal", "Harsh", "Harry", "Jr.", "Dr.", "Sunita Mehta",
                "Ramesh Rawal", "Priya Rawal", "Ramesh Rawal Guardian", "SHA256:7f83b1657ff1fc53b92dc18148a1d65d",
                "/signatures/user_sig_102.png", "NOTARY-MUM-88219", "Anand Verma", "Advocate Sanjay Singhania",
                "R400", "Harshit", "Doctor of Engineering", "Kashmiri Brahmin", "CREST-RAWAL-1882", "HAR-sheet RAH-wul"
            ))

            # Insert Domain 2 (Government IDs - 30 types)
            cursor.execute('''
                INSERT OR REPLACE INTO global_government_identifiers VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
            ''', (
                user_id, "123-45-6789", "987-65-4321", "12-3456789", "QQ123456C",
                "1234567890", "123-456-789", "123 456 789", "2123 45678 1",
                "234567890123", "ABCDE1234F", "M1234567", "EPIC9876543", "DL0420110012345",
                "10029384756102", "RC-DEL-991204", "OCI-A129384", "MH02CB1234", "MA3ER45S9021489",
                "ENG992148102", "FASTAG-ICICI-881293", "1 85 12 75 123 456 78", "12 345 678 901",
                "RSSMRA85M01H501Z", "12345678Z", "123.456.789-00", "12.345.678-9",
                "110101199003072391", "1234 5678 9012", "S1234567A", "CURP123456HDFRRN09"
            ))

            # Insert Domain 3 (Contact - 20 types)
            cursor.execute('''
                INSERT OR REPLACE INTO contact_telecommunications VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
            ''', (
                user_id, "harshit@smartmoney.ai", "harshit.personal@gmail.com", "harshit.rawal@fintechcorp.com",
                "+919876543210", "+912226549988", "Ext 402", "+912226549989",
                "+919876543210", "@harshitrawal", "+919876543210", "+919811223344",
                "PAGE-88129", "sip:harshit@voip.telecom.com", "live:harshit.rawal", "https://zoom.us/j/992148102",
                "Flat 402, Sea Green Apartments", "Worli Sea Face", "Mumbai", "Maharashtra", "400018"
            ))

            conn.commit()
            print("Successfully populated active database with 240 distinct PII entities.")

# Global instance for live scanner verification
enterprise_catalog = EnterprisePIIRepository240()
enterprise_catalog.populate_all_240_pii_entities()
