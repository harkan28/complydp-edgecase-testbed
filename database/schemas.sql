-- ==============================================================================
-- COMPLYDP PII DETECTION TESTBED — DATABASE SCHEMAS (DDL)
-- Maps to Test Suites: ID, GOV, CON, DEM, FIN, PAY, AUTH, DIG, LOC, BIO, HLT, EMP, EDU, COM, DER
-- ==============================================================================

-- [TC: ID-001 to ID-020, CON-001 to CON-020, DEM-001 to DEM-020] Core User Profiles
CREATE TABLE IF NOT EXISTS users (
    -- [ID-001] [EXPECTED: DETECT POTENTIAL PII] Full Name
    id VARCHAR(64) PRIMARY KEY,
    full_name VARCHAR(255) NOT NULL,
    -- [ID-002] [EXPECTED: DETECT POTENTIAL PII] Split Name Fields
    first_name VARCHAR(128),
    last_name VARCHAR(128),
    maiden_name VARCHAR(128),
    legal_name VARCHAR(255),
    preferred_name VARCHAR(128),
    alias VARCHAR(128),
    
    -- [CON-001, CON-002] [EXPECTED: DETECT POTENTIAL PII] Contact Information
    email VARCHAR(255) UNIQUE NOT NULL,
    mobile_no VARCHAR(32) NOT NULL,
    emergency_contact VARCHAR(32),
    residential_address TEXT,
    postal_address TEXT,
    postal_code VARCHAR(16),
    
    -- [DEM-001 to DEM-005] [EXPECTED: DETECT POTENTIAL PII] Demographic Attributes
    birth_date DATE,
    birth_year INT,
    age INT,
    gender VARCHAR(32),
    nationality VARCHAR(64),
    demographic_profile TEXT,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- [TC: GOV-001 to GOV-020] Government Identifiers
CREATE TABLE IF NOT EXISTS government_identities (
    user_id VARCHAR(64) REFERENCES users(id),
    -- [GOV-001] [EXPECTED: DETECT POTENTIAL PII] National ID
    aadhaar_number VARCHAR(16),
    -- [GOV-002] [EXPECTED: DETECT POTENTIAL PII] Tax Identifier
    pan_number VARCHAR(16),
    -- [GOV-003] [EXPECTED: DETECT POTENTIAL PII] Travel Identity
    passport_number VARCHAR(32),
    voter_id VARCHAR(32),
    driving_license_number VARCHAR(32),
    social_security_number VARCHAR(32),
    tax_id VARCHAR(32),
    kyc_document_id VARCHAR(64),
    identity_document_number VARCHAR(64)
);

-- [TC: FIN-001 to FIN-020, PAY-001 to PAY-020] Financial & Payment Information
CREATE TABLE IF NOT EXISTS financial_profiles (
    user_id VARCHAR(64) REFERENCES users(id),
    -- [FIN-001] [EXPECTED: DETECT POTENTIAL PII] Salary & Income
    annual_income DECIMAL(15, 2),
    monthly_salary DECIMAL(15, 2),
    net_worth DECIMAL(18, 2),
    credit_score INT,
    risk_profile VARCHAR(32),
    
    -- [PAY-001 to PAY-005] [EXPECTED: DETECT POTENTIAL PII] Payment Identifiers
    bank_account_number VARCHAR(64),
    ifsc_code VARCHAR(16),
    upi_id VARCHAR(128),
    payment_method_details TEXT,
    transaction_reference VARCHAR(64)
);

-- [TC: AUTH-001 to AUTH-020] Authentication Secrets
CREATE TABLE IF NOT EXISTS authentication_records (
    user_id VARCHAR(64) REFERENCES users(id),
    -- [AUTH-001] [EXPECTED: DETECT POTENTIAL PII] Password Hash
    password_hash VARCHAR(255) NOT NULL,
    mfa_secret VARCHAR(128),
    jwt_token_signature VARCHAR(512),
    auth_fingerprint VARCHAR(128),
    refresh_token VARCHAR(255)
);

-- [TC: DIG-001 to DIG-020] Digital Telemetry & Identifiers
CREATE TABLE IF NOT EXISTS digital_identifiers (
    user_id VARCHAR(64) REFERENCES users(id),
    -- [DIG-001] [EXPECTED: DETECT POTENTIAL PII] IP Address
    ip_address VARCHAR(45),
    cookie_id VARCHAR(128),
    device_id VARCHAR(128),
    advertising_id VARCHAR(128),
    session_id VARCHAR(128),
    analytics_user_id VARCHAR(128)
);

-- [TC: LOC-001 to LOC-020] Location & Physical Coordinates
CREATE TABLE IF NOT EXISTS location_tracking (
    user_id VARCHAR(64) REFERENCES users(id),
    -- [LOC-001] [EXPECTED: DETECT POTENTIAL PII] Location Coordinates
    latitude DECIMAL(10, 8),
    longitude DECIMAL(11, 8),
    geohash VARCHAR(16),
    current_location VARCHAR(255),
    home_address TEXT,
    work_address TEXT
);

-- [TC: BIO-001 to BIO-020] Biometric Data
CREATE TABLE IF NOT EXISTS biometric_templates (
    user_id VARCHAR(64) REFERENCES users(id),
    -- [BIO-001] [EXPECTED: DETECT POTENTIAL PII] Biometric Embeddings
    face_id VARCHAR(64),
    face_embedding BLOB,
    fingerprint_minutiae BLOB,
    iris_scan BLOB,
    voice_print BLOB
);

-- [TC: HLT-001 to HLT-020] Health & Medical Records
CREATE TABLE IF NOT EXISTS health_records (
    user_id VARCHAR(64) REFERENCES users(id),
    -- [HLT-001] [EXPECTED: DETECT POTENTIAL PII] Health Information
    patient_id VARCHAR(64),
    medical_record_number VARCHAR(64),
    diagnosis TEXT,
    prescription_details TEXT,
    insurance_claim_id VARCHAR(64),
    blood_group VARCHAR(8)
);

-- [TC: EMP-001 to EMP-020] Employment & Workplace Information
CREATE TABLE IF NOT EXISTS employment_records (
    user_id VARCHAR(64) REFERENCES users(id),
    -- [EMP-001] [EXPECTED: DETECT POTENTIAL PII] HR Identifiers
    employee_id VARCHAR(64),
    payroll_details TEXT,
    employment_history TEXT,
    uan_number VARCHAR(32),
    esic_number VARCHAR(32),
    designation VARCHAR(128),
    department VARCHAR(128)
);

-- [TC: EDU-001 to EDU-020] Education Information
CREATE TABLE IF NOT EXISTS education_records (
    user_id VARCHAR(64) REFERENCES users(id),
    -- [EDU-001] [EXPECTED: DETECT POTENTIAL PII] Academic Records
    student_id VARCHAR(64),
    institution_name VARCHAR(255),
    qualification VARCHAR(128),
    exam_result VARCHAR(32),
    grade_point_average DECIMAL(4, 2),
    transcript_data TEXT
);

-- [TC: COM-001 to COM-020] Communications & Behavioral Logs
CREATE TABLE IF NOT EXISTS communication_events (
    user_id VARCHAR(64) REFERENCES users(id),
    -- [COM-001] [EXPECTED: DETECT POTENTIAL PII] Message Content
    sms_body TEXT,
    message_content TEXT,
    call_log TEXT,
    browsing_history TEXT,
    conversation_history TEXT
);

-- [TC: DER-001 to DER-020] Derived & Inferred Psychometrics
CREATE TABLE IF NOT EXISTS derived_intelligence (
    user_id VARCHAR(64) REFERENCES users(id),
    -- [DER-001] [EXPECTED: DETECT POTENTIAL PII] Inferred Behavioral Model
    customer_score DECIMAL(5, 2),
    predicted_income_band VARCHAR(64),
    investment_persona VARCHAR(64),
    inferred_preference TEXT,
    churn_probability DECIMAL(4, 3)
);
