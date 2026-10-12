"""
COMPLYDP PII DETECTION TESTBED — ACTIVE DATABASE MANAGER
Implements active SQLite database schemas and CRUD operations using sqlite3.
Contains explicit CREATE TABLE definitions for all 15 PII categories.
"""

import sqlite3
import json
from pathlib import Path
from typing import Dict, Any, List, Optional

class EdgeCaseDataManager:
    def __init__(self, db_path: str = "edgecase_testbed.db"):
        self.db_path = db_path
        self.init_database()

    def get_connection(self):
        return sqlite3.connect(self.db_path)

    def init_database(self):
        """Initializes tables covering all 15 PII domains."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # ==================================================================
            # 1. CORE USER & CONTACT (ID, CON, DEM)
            # ==================================================================
            # [ID-001, ID-002] Full Name, First/Last Name
            # [CON-001, CON-002] Email, Phone, Address, Postal Code
            # [DEM-001, DEM-002] Age, Date of Birth, Gender
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    full_name TEXT NOT NULL,
                    first_name TEXT,
                    last_name TEXT,
                    email TEXT UNIQUE NOT NULL,
                    phone TEXT NOT NULL,
                    mobile_no TEXT,
                    age INTEGER,
                    date_of_birth DATE,
                    gender TEXT,
                    residential_address TEXT,
                    postal_address TEXT,
                    pincode TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # ==================================================================
            # 2. FINANCIAL & PAYMENT INFORMATION (FIN, PAY)
            # ==================================================================
            # [FIN-001] Income, Salary, Credit Score, Net Worth
            # [PAY-001, PAY-002] Bank Account, UPI ID, IFSC Code
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS financial_accounts (
                    account_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    annual_income REAL,
                    monthly_salary REAL,
                    credit_score INTEGER,
                    net_worth REAL,
                    risk_profile TEXT,
                    investment_timeline INTEGER,
                    financial_goals TEXT,
                    bank_name TEXT,
                    bank_account_number TEXT NOT NULL,
                    account_number TEXT,
                    ifsc_code TEXT,
                    upi_id TEXT,
                    payment_method_details TEXT,
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                )
            ''')

            # [PAY-003] Transactions with Amount, Balance, Merchant & UPI
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS transactions (
                    transaction_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    amount REAL NOT NULL,
                    balance REAL,
                    merchant TEXT,
                    category TEXT,
                    account_number TEXT,
                    upi_id TEXT,
                    timestamp DATETIME,
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                )
            ''')

            # ==================================================================
            # 3. GOVERNMENT IDENTIFIERS (GOV)
            # ==================================================================
            # [GOV-001, GOV-002, GOV-003] Aadhaar, PAN, Passport, Driving License
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS government_identity_records (
                    record_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    aadhaar_number TEXT,
                    pan_number TEXT,
                    passport_no TEXT,
                    passport_number TEXT,
                    driving_license TEXT,
                    voter_id TEXT,
                    tax_id TEXT,
                    national_id TEXT,
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                )
            ''')

            # ==================================================================
            # 4. HEALTH & BIOMETRIC PROFILES (HLT, BIO)
            # ==================================================================
            # [HLT-001] Patient ID, Medical Record, Diagnosis, Prescription
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS health_profiles (
                    health_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    patient_id TEXT,
                    medical_record TEXT,
                    diagnosis TEXT,
                    prescription TEXT,
                    blood_group TEXT,
                    insurance_claim_id TEXT,
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                )
            ''')

            # [BIO-001] Face ID, Face Embedding, Fingerprint, Iris
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS biometric_vault (
                    vault_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    face_id TEXT,
                    face_embedding BLOB,
                    fingerprint_template BLOB,
                    iris_scan BLOB,
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                )
            ''')

            # ==================================================================
            # 5. EMPLOYMENT & EDUCATION (EMP, EDU)
            # ==================================================================
            # [EMP-001] Employee ID, UAN, ESIC, Salary Record, Payroll
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS employment_details (
                    emp_record_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    employee_id TEXT,
                    uan_number TEXT,
                    esic_number TEXT,
                    salary_record REAL,
                    payroll_details TEXT,
                    department TEXT,
                    designation TEXT,
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                )
            ''')

            # [EDU-001] Student ID, Exam Result, Marks, Qualification
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS education_history (
                    edu_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    student_id TEXT,
                    institution_name TEXT,
                    qualification TEXT,
                    degree TEXT,
                    exam_result TEXT,
                    marks REAL,
                    transcript TEXT,
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                )
            ''')

            # ==================================================================
            # 6. DIGITAL, LOCATION, COMMUNICATIONS & DERIVED (DIG, LOC, COM, DER)
            # ==================================================================
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS digital_telemetry (
                    telemetry_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    ip_address TEXT,
                    device_id TEXT,
                    cookie_id TEXT,
                    session_id TEXT,
                    advertising_id TEXT,
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS location_breadcrumbs (
                    loc_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    latitude REAL,
                    longitude REAL,
                    home_address TEXT,
                    current_location TEXT,
                    geohash TEXT,
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS communication_audit_log (
                    comm_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    sms_body TEXT,
                    message_content TEXT,
                    call_log TEXT,
                    conversation_history TEXT,
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS derived_intelligence (
                    intel_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    customer_score REAL,
                    predicted_income_band TEXT,
                    investment_persona TEXT,
                    inferred_preference TEXT,
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                )
            ''')

            conn.commit()

    def insert_user_profile(self, user_data: Dict[str, Any]):
        """Inserts user profile with personal data."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO users (
                    user_id, full_name, first_name, last_name, email, phone, age, residential_address
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                user_data['user_id'], user_data['full_name'], user_data.get('first_name'),
                user_data.get('last_name'), user_data['email'], user_data['phone'],
                user_data.get('age'), user_data.get('residential_address')
            ))
            conn.commit()
