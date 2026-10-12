# 🛡️ Enterprise 200 Clean Distinct PII Benchmark Catalog

**Repository:** `harkan28/complydp-edgecase-testbed`  
**Live Code:** [`enterprise_pii_catalog_200.py`](file:///Users/harshitrawal/Downloads/complydp/ocr/complydp_edgecase_testbed/enterprise_pii_catalog_200.py)  
**Total Differentiated Clean PII Attributes:** **Exactly 200 Distinct Entities**  
**Standards Covered:** GDPR (EU), CCPA/CPRA (California), HIPAA (Healthcare), DPDP (India), PCI-DSS (Payment Cards), FERPA (Education), ISO 27701.

---

## 1. Domain Summary Matrix (200 Clean Attributes)

```
+--------------------------------------------------------------------------------------------------+
|                            ENTERPRISE 200 CLEAN PII DOMAIN ARCHITECTURE                          |
+----+----------------------------------------+---------------+------------------------------------+
| #  | Privacy Domain                         | Entity Count  | Scope & Governing Regulations      |
+----+----------------------------------------+---------------+------------------------------------+
| 1  | Personal & Legal Identity              | 20 Entities   | Full names, legal aliases, cosigner|
| 2  | Global National & Government IDs       | 25 Entities   | US, UK, Canada, Australia, India   |
| 3  | Contact & Telecommunications           | 18 Entities   | Mobile, work email, VoIP, postal   |
| 4  | Demographics & Protected Classes       | 14 Entities   | Age, DOB, gender, nationality      |
| 5  | Financial & Banking Data               | 22 Entities   | IBAN, SWIFT, CIBIL, Crypto wallets |
| 6  | Payment Card Industry (PCI-DSS)        | 12 Entities   | PAN, CVV, Apple Pay token, Virtual |
| 7  | Employment & Corporate HR              | 18 Entities   | Employee ID, UAN, ESIC, base salary|
| 8  | Protected Health Information (HIPAA)   | 20 Entities   | ICD-10, EHR, MRN, Rx, ABHA, blood  |
| 9  | Biometric Templates & Physical Data    | 10 Entities   | Face vectors, iris, fingerprint    |
| 10 | Education & Academic Records (FERPA)   | 12 Entities   | Student ID, GPA, transcripts, rank |
| 11 | Geolocation & Spatial Telemetry        | 14 Entities   | Exact GPS, altitude, BSSID, routes |
| 12 | Digital Network & Device Telemetry     | 15 Entities   | IPv4/v6, MAC, IMEI, IDFA, cookies  |
+----+----------------------------------------+---------------+------------------------------------+
|    | TOTAL CLEAN DISTINCT PII ENTITIES      | 200 ENTITIES  | Zero Traps • 100% Production Grade |
+----+----------------------------------------+---------------+------------------------------------+
```

---

## 2. Itemized Catalog of the 200 Clean PII Entities

### Domain 1: Personal & Legal Identity (20 Types)
1. `full_name`: Complete person name.
2. `first_name`: Given name.
3. `last_name`: Family / surname.
4. `middle_name`: Secondary given name.
5. `maiden_name`: Pre-marital surname.
6. `legal_name`: Officially registered civil name.
7. `preferred_name`: Everyday / chosen name.
8. `display_name`: Application user handle.
9. `title_prefix`: Salutation (Dr., Mr., Prof.).
10. `name_suffix`: Generational tag (Jr., Sr., III).
11. `mothers_maiden_name`: Security verification secret.
12. `fathers_name`: Paternal lineage name.
13. `spouse_name`: Legal marital partner name.
14. `guardian_name`: Legal ward / minor guardian.
15. `digital_signature`: Cryptographic PKI identity key.
16. `signature_image_uri`: Visual signature asset.
17. `legal_alias`: Registered trade / pen name.
18. `tax_representative_name`: Designated tax agent.
19. `beneficiary_name`: Estate / insurance heir.
20. `witness_cosigner_name`: Legal contract cosigner.

### Domain 2: Global National & Government Identifiers (25 Types)
21. `us_ssn`: US Social Security Number.
22. `us_itin`: US Individual Taxpayer ID.
23. `us_ein`: US Employer Identification Number.
24. `uk_nino`: UK National Insurance Number.
25. `uk_utr`: UK Unique Taxpayer Reference.
26. `canada_sin`: Canadian Social Insurance Number.
27. `australia_tfn`: Australian Tax File Number.
28. `australia_medicare`: Australian Medicare Number.
29. `india_aadhaar`: Indian 12-digit UIDAI Aadhaar.
30. `india_pan`: Indian 10-char Income Tax PAN.
31. `passport_number`: International Passport Number.
32. `voter_id`: Electoral Photo Identity Card (EPIC).
33. `driving_license`: State Motor Driver's License.
34. `ckyc_number`: Central KYC Registry Number (14-digit).
35. `ration_card_number`: Public Distribution Card.
36. `oci_card_number`: Overseas Citizen of India Card.
37. `vehicle_rc_number`: Vehicle Registration RC Plate.
38. `vin_chassis_number`: 17-char Vehicle Chassis VIN.
39. `engine_number`: Automobile Engine Serial.
40. `fastag_id`: Electronic Toll RFID Identifier.
41. `french_nir`: French Social Security Number.
42. `german_steuer_id`: German Tax ID Number.
43. `italian_codice_fiscale`: Italian Fiscal Code.
44. `spanish_dni_nie`: Spanish National Identity ID.
45. `brazil_cpf`: Brazilian Tax Registry Number.

### Domain 3: Contact & Telecommunications (18 Types)
46. `email_address`: Primary contact email.
47. `personal_email`: Personal backup email.
48. `work_email`: Corporate organizational email.
49. `mobile_number`: Mobile cellular telephone.
50. `landline_number`: Fixed-line residential phone.
51. `work_extension`: Corporate PBX extension.
52. `fax_number`: Facsimile transmission number.
53. `whatsapp_number`: WhatsApp instant messaging line.
54. `telegram_handle`: Telegram messaging username.
55. `signal_number`: Encrypted Signal telephone.
56. `emergency_contact_phone`: Emergency kin phone.
57. `voip_sip_address`: VoIP SIP communication URI.
58. `postal_address_line1`: Primary street & number.
59. `postal_address_line2`: Suite / apartment number.
60. `city`: Residential city / municipality.
61. `state_province`: Territorial state / province.
62. `postal_code`: Postal / PIN / ZIP code.
63. `country`: Country of residence.

### Domain 4: Demographics & Protected Attributes (14 Types)
64. `date_of_birth`: Full date of birth (YYYY-MM-DD).
65. `birth_year`: Calendar birth year.
66. `age`: Chronological age in years.
67. `age_bracket`: Age demographic bracket.
68. `place_of_birth`: City of birth.
69. `nationality`: Legal citizenship nation.
70. `citizenship_status`: Permanent resident, citizen, visa.
71. `biological_sex`: Clinical birth sex.
72. `gender_identity`: Self-identified gender.
73. `marital_status`: Civil marriage status.
74. `religion`: Religious affiliation.
75. `caste_category`: Indian constitutional social tier.
76. `ethnicity`: Ethnic / ancestral heritage.
77. `sexual_orientation`: Intimate attraction orientation.

### Domain 5: Financial & Banking Information (22 Types)
78. `bank_account_number`: Commercial checking/savings number.
79. `iban`: International Bank Account Number.
80. `swift_bic`: SWIFT / BIC interbank code.
81. `routing_number`: ABA Fedwire / ACH routing number.
82. `ifsc_code`: Indian Financial System Code.
83. `upi_id`: Unified Payments Interface VPA.
84. `monthly_salary`: Monthly base earnings.
85. `annual_income`: Cumulative yearly income.
86. `hourly_rate`: Standard hourly billing rate.
87. `net_worth`: Total assets minus total debt.
88. `liquid_assets`: Liquid cash equivalents.
89. `total_liabilities`: Total outstanding debt balance.
90. `debt_to_income`: Debt-to-income percentage.
91. `credit_score`: Consumer credit rating (300-900).
92. `credit_rating`: Credit tier (Prime / Subprime).
93. `tax_filing_amount`: Reported annual tax liability.
94. `demat_account_number`: Depository BO Demat ID.
95. `broker_client_id`: Equity trading account ID.
96. `mutual_fund_folio`: Mutual fund folio number.
97. `ethereum_address`: Hexadecimal Ethereum address.
98. `bitcoin_address`: Bitcoin Base58 / Bech32 address.
99. `solana_address`: Solana public key.

### Domain 6: Payment Cards (PCI-DSS) (12 Types)
100. `card_number_pan`: 16-digit Primary Account Number.
101. `debit_card_number`: Direct checking debit card.
102. `card_expiry_month`: 2-digit validity month.
103. `card_expiry_year`: 4-digit validity year.
104. `card_cvv`: 3-digit / 4-digit security code.
105. `cardholder_name`: Embossed name on payment card.
106. `card_issuer_bank`: Card issuing bank.
107. `card_brand`: Visa, Mastercard, RuPay, Amex.
108. `apple_pay_token`: Device Primary Account Number (DPAN).
109. `google_pay_token`: Google Wallet payment token.
110. `virtual_card_number`: Single-use virtual payment card.
111. `gift_card_pin`: Stored-value card PIN.

### Domain 7: Employment & Corporate HR (18 Types)
112. `employee_id`: Corporate worker badge number.
113. `corporate_work_email`: Corporate organizational email.
114. `job_title`: Official organizational role.
115. `department`: Corporate functional division.
116. `hire_date`: Start date of employment contract.
117. `termination_date`: Exit or contract end date.
118. `contract_type`: Full-time, contractor, intern.
119. `base_salary`: Fixed base compensation.
120. `annual_bonus`: Variable incentive bonus.
121. `equity_stock_options`: ESOP option grant units.
122. `performance_rating`: Annual performance review score.
123. `manager_name`: Reporting supervisor identity.
124. `epfo_uan`: Indian Employees' Provident Fund UAN.
125. `esic_number`: Indian ESIC Insurance Code.
126. `nps_pran`: National Pension System PRAN.
127. `work_permit_visa`: H-1B, Tier-2, Blue Card visa.
128. `corporate_card_number`: Corporate expense credit line.
129. `timesheet_hours`: Clock-in and clock-out hours.

### Domain 8: Health & Medical (HIPAA) (20 Types)
130. `patient_id`: Clinical patient registration code.
131. `electronic_health_record_ehr`: Longitudinal EHR file ID.
132. `medical_record_number_mrn`: Hospital department chart ID.
133. `icd10_diagnosis_code`: ICD-10 medical code.
134. `diagnosis_description`: Physician diagnosis notes.
135. `prescription_drug`: Pharmaceutical medicine name.
136. `medication_dosage`: Dosage strength and interval.
137. `attending_physician`: Treating doctor identity.
138. `hospital_facility`: Hospital clinic name.
139. `health_insurance_policy`: Health insurance subscriber ID.
140. `insurance_group_number`: Employer insurance group code.
141. `medical_claim_id`: Adjudicated medical claim ID.
142. `blood_group`: ABO and Rh blood group.
143. `bmi`: Body Mass Index biological metric.
144. `known_allergies`: Drug and food allergies panel.
145. `lab_test_name`: Laboratory diagnostic panel.
146. `lab_test_numeric_value`: Quantitative lab result.
147. `vaccine_certificate_id`: Immunization certificate ID.
148. `abha_id`: Indian 14-digit ABHA Health Account.
149. `nhs_number`: UK National Health Service Number.

### Domain 9: Biometric Templates (10 Types)
150. `face_embedding_vector`: 512-dim facial recognition vector.
151. `facial_landmarks_2d`: 68-point 2D facial landmarks.
152. `fingerprint_minutiae`: ISO/IEC 19794 ridge minutiae.
153. `iris_scan_code`: Polar iris scan Gabor wavelet code.
154. `voiceprint_embedding`: Mel-frequency cepstral vector.
155. `retina_pattern`: Ocular fundus vascular pattern.
156. `hand_geometry`: Palm and finger dimensional matrix.
157. `palm_print_minutiae`: Palmar friction ridge minutiae.
158. `keystroke_dynamics`: Typing dwell and flight profile.
159. `vein_pattern`: Near-infrared vascular pattern.

### Domain 10: Education & Academic (FERPA) (12 Types)
160. `student_id`: Primary institutional student ID.
161. `enrollment_number`: University matriculation number.
162. `degree_title`: Bachelor, Master, Doctorate degree.
163. `academic_major`: Primary concentration.
164. `gpa`: 4.0 Grade Point Average scale.
165. `letter_grade`: Letter grade evaluation (A+, B, C).
166. `exam_marks`: Numerical exam score.
167. `university_name`: Accredited college / university.
168. `graduation_year`: Year of diploma conferral.
169. `class_rank`: Cohort percentile standing.
170. `transcript_data`: Academic coursework history.
171. `standardized_test_score`: SAT / GRE / GMAT score.

### Domain 11: Geolocation & Spatial Telemetry (14 Types)
172. `gps_latitude`: Decimal degree latitude.
173. `gps_longitude`: Decimal degree longitude.
174. `gps_altitude`: Altitude above sea level in meters.
175. `speed_kmh`: Velocity in kilometers per hour.
176. `compass_bearing`: Heading direction angle (0-360°).
177. `geohash`: Hierarchical spatial bounding box code.
178. `home_coordinates`: Residential GPS cluster coordinates.
179. `work_coordinates`: Workplace GPS coordinates.
180. `daily_commute_route`: Chronological waypoint route history.
181. `cell_tower_id`: Base transceiver station (BTS) cell ID.
182. `wifi_bssid_mac`: Wi-Fi router BSSID MAC address.
183. `ble_beacon_uuid`: BLE proximity beacon UUID.
184. `ip_city_location`: GeoIP city / municipality inference.
185. `geofence_polygon`: Bounding geofence coordinates.

### Domain 12: Digital Network & Device Telemetry (15 Types)
186. `client_ipv4`: Public/private 32-bit IPv4 address.
187. `client_ipv6`: 128-bit global unicast IPv6 address.
188. `mac_address`: Hardware network adapter MAC address.
189. `device_imei`: 15-digit cellular hardware IMEI.
190. `sim_imsi`: 15-digit SIM subscriber IMSI.
191. `apple_idfa`: Apple Identifier for Advertisers.
192. `google_aaid`: Google Android Advertising ID.
193. `device_serial_number`: OEM hardware serial string.
194. `session_cookie_id`: Persistent tracking cookie ID.
195. `web_session_id`: Server web session token.
196. `oauth_access_token`: Bearer access token string.
197. `oauth_refresh_token`: OAuth refresh exchange token.
198. `jwt_token`: JSON Web Token identity claim.
199. `user_agent_header`: Browser & OS User-Agent header.
200. `push_notification_token`: APNs / FCM push device registration token.
