# 🌐 Enterprise 240 Distinct PII Taxonomy & Compliance Benchmark

**Repository:** `harkan28/complydp-edgecase-testbed`  
**File Reference:** [`enterprise_pii_catalog_240.py`](file:///Users/harshitrawal/Downloads/complydp/ocr/complydp_edgecase_testbed/enterprise_pii_catalog_240.py)  
**Total Differentiated PII Entities:** **240 Distinct Attributes**  
**Regulatory Coverage:** GDPR (EU), CCPA/CPRA (California), HIPAA (Healthcare), DPDP (India), PCI-DSS (Payments), FERPA (Education), ISO 27701.

---

## 1. Complete Breakdown of 240 Distinct PII Entities by Domain

```
+--------------------------------------------------------------------------------------------------+
|                            ENTERPRISE 240 PII TAXONOMY ARCHITECTURE                              |
+----+----------------------------------------+---------------+------------------------------------+
| #  | Privacy Domain                         | Entity Count  | Governing Regulations              |
+----+----------------------------------------+---------------+------------------------------------+
| 1  | Personal & Legal Identity              | 25 Entities   | GDPR Art 4(1), CCPA § 1798.140     |
| 2  | Global Government & National IDs       | 30 Entities   | DPDP § 2, US Privacy Act, eIDAS    |
| 3  | Contact & Telecommunications           | 20 Entities   | GDPR Art 4, ePrivacy Directive     |
| 4  | Demographics & Protected Classes       | 15 Entities   | GDPR Art 9 (Special Category), EEOC|
| 5  | Financial & Banking Data               | 25 Entities   | GLBA, DPDP, RBI Master Directions  |
| 6  | Payment Cards & PCI-DSS                | 15 Entities   | PCI-DSS v4.0 Requirement 3         |
| 7  | Employment & Corporate HR              | 20 Entities   | GDPR Art 88, Labor Laws, EPFO/ESIC |
| 8  | Protected Health Information (PHI)     | 25 Entities   | HIPAA Privacy Rule (18 Identifiers)|
| 9  | Biometric Templates & Physical Data    | 15 Entities   | GDPR Art 9(1), BIPA (Illinois)     |
| 10 | Education & Academic Records           | 15 Entities   | FERPA (34 CFR Part 99)             |
| 11 | Geolocation & Spatial Telemetry        | 15 Entities   | GDPR Art 4(1), CCPA Geolocation    |
| 12 | Digital Network & Device Telemetry     | 20 Entities   | ePrivacy, GDPR Recital 30, CCPA    |
+----+----------------------------------------+---------------+------------------------------------+
|    | TOTAL DISTINCT PII ENTITIES            | 240 ENTITIES  | Full Global Compliance Coverage    |
+----+----------------------------------------+---------------+------------------------------------+
```

---

## 2. Itemized Catalog of All 240 Distinct PII Attributes

### Domain 1: Personal & Legal Identity (25 Entities)
1. `full_name`: Standard complete person name.
2. `first_name`: Given name.
3. `last_name`: Family / surname.
4. `middle_name`: Secondary given name.
5. `maiden_name`: Pre-marriage family name.
6. `legal_name`: Officially registered civil name.
7. `preferred_name`: Chosen / everyday alias.
8. `nickname_alias`: Pseudonym or handle.
9. `name_suffix`: Generational tag (Jr., Sr., III).
10. `name_prefix_title`: Honorific (Dr., Mr., Prof.).
11. `mothers_maiden_name`: High-risk identity verification secret.
12. `fathers_full_name`: Parental lineage identifier.
13. `spouse_name`: Marital partner identity.
14. `legal_guardian_name`: Minor/ward supervisor.
15. `digital_signature_hash`: Cryptographic identity verification.
16. `signature_image_path`: Visual handwritten signature.
17. `notary_seal_number`: Legal attestation seal.
18. `witness_name`: Legal contract cosigner.
19. `power_of_attorney_name`: Legal proxy designee.
20. `alias_soundex_code`: Phonetic name encoding.
21. `mononym_identity`: Single-word legal name.
22. `honorific_title`: Knighthood / official title.
23. `tribal_clan_membership`: Indigenous community identity.
24. `family_crest_id`: Lineage coat of arms.
25. `official_name_pronunciation`: Phonetic identity audio/text.

---

### Domain 2: Global Government & National Identifiers (30 Entities)
26. `us_ssn`: US Social Security Number (9-digit).
27. `us_itin`: US Individual Taxpayer Identification Number.
28. `us_ein`: US Employer Identification Number.
29. `uk_nino`: UK National Insurance Number.
30. `uk_utr`: UK Unique Taxpayer Reference (10-digit).
31. `canada_sin`: Canadian Social Insurance Number (9-digit).
32. `australia_tfn`: Australian Tax File Number.
33. `australia_medicare_no`: Australian Universal Healthcare Number.
34. `india_aadhaar_uid`: Indian 12-digit Unique Identification.
35. `india_pan_number`: Indian 10-char Income Tax PAN.
36. `india_passport_number`: Indian Passport Travel Credential.
37. `india_voter_epic_id`: Indian Election Commission Voter Card.
38. `india_driving_license`: Indian State Motor Vehicle License.
39. `india_ckyc_identifier`: Indian 14-digit Central KYC Number.
40. `india_ration_card_no`: Indian Public Distribution System Card.
41. `india_oci_card_no`: Overseas Citizen of India Card.
42. `india_vehicle_rc_number`: Indian Motor Vehicle Registration Plate.
43. `vehicle_vin_chassis_no`: 17-char Vehicle Identification Number.
44. `vehicle_engine_number`: Automobile Engine Serial.
45. `india_fastag_rfid_id`: Electronic Toll Collection Tag.
46. `france_nir_ssn`: French Social Security NIR (15-digit).
47. `germany_steuer_id`: German Tax Identification Number (11-digit).
48. `italy_codice_fiscale`: Italian 16-char Alphanumeric Fiscal Code.
49. `spain_dni_nie`: Spanish Documento Nacional de Identidad.
50. `brazil_cpf_number`: Brazilian Cadastro de Pessoas Físicas (11-digit).
51. `brazil_rg_identity`: Brazilian Registro Geral Civil ID.
52. `china_resident_id`: Chinese 18-digit Resident Identity Card.
53. `japan_my_number`: Japanese 12-digit Individual Social Number.
54. `singapore_nric_fin`: Singapore National Registration Identity Card.
55. `mexico_curp_code`: Mexican Unique Population Registry Code.

---

### Domain 3: Contact & Telecommunications (20 Entities)
56. `primary_email_address`: Main contact email.
57. `secondary_personal_email`: Personal backup email.
58. `corporate_work_email`: Corporate organizational email.
59. `mobile_telephone_number`: Cellular telephone number.
60. `landline_phone_number`: Fixed-line residential telephone.
61. `work_phone_extension`: Office PBX telephone extension.
62. `facsimile_fax_number`: Fax communication line.
63. `whatsapp_phone_number`: Instant messaging telecom handle.
64. `telegram_username`: Telegram messenger handle.
65. `signal_phone_number`: Encrypted messaging telephone.
66. `emergency_contact_phone`: Emergency kin phone line.
67. `pager_number`: Clinical/emergency radio pager.
68. `voip_sip_uri`: Voice-over-IP SIP communication URI.
69. `skype_handle`: Skype username.
70. `zoom_personal_meeting_id`: Static teleconference room ID.
71. `postal_address_line1`: Primary street name & house number.
72. `postal_address_line2`: Suite, unit, or apartment number.
73. `city_municipality`: City or township of residence.
74. `state_province_region`: State or territorial province.
75. `postal_code_pincode_zip`: Postal routing code / PIN code.

---

### Domain 4: Demographics & Protected Characteristics (15 Entities)
76. `exact_date_of_birth`: Full day/month/year of birth.
77. `birth_year_integer`: Calendar birth year.
78. `age_years`: Exact chronological age.
79. `age_bracket_group`: Demographic bracket (e.g., 25-34).
80. `place_of_birth_city`: Municipality of birth.
81. `country_of_origin`: Native sovereign nation.
82. `primary_nationality`: Legal state citizenship.
83. `citizenship_status`: Permanent resident, citizen, visa holder.
84. `biological_sex`: Clinical birth sex (Male/Female/Intersex).
85. `gender_identity`: Self-identified gender.
86. `marital_status`: Civil marriage status.
87. `religious_affiliation`: Faith or religious denomination.
88. `caste_subcaste_category`: Indian constitutional social category.
89. `ethnic_racial_background`: Ancestral racial heritage.
90. `sexual_orientation`: Intimate attraction orientation.

---

### Domain 5: Financial & Banking Information (25 Entities)
91. `bank_account_number`: Commercial checking/savings number.
92. `international_iban`: International Bank Account Number.
93. `swift_bic_code`: Society for Worldwide Interbank Financial Telecommunication code.
94. `bank_routing_aba_number`: US Fedwire/ACH routing transit number.
95. `indian_ifsc_code`: Indian Financial System Code.
96. `upi_virtual_payment_address`: Indian Unified Payments Interface VPA.
97. `monthly_gross_salary`: Monthly base earnings.
98. `annual_total_income`: Yearly cumulative income.
99. `hourly_wage_rate`: Standard hourly billing rate.
100. `estimated_net_worth`: Total assets minus total debt.
101. `total_liquid_assets`: Cash and cash equivalents.
102. `total_outstanding_liabilities`: Total current debt balance.
103. `debt_to_income_ratio`: Monthly debt divided by gross income.
104. `credit_bureau_score_cibil`: Consumer credit bureau rating (300-900).
105. `credit_rating_band`: Psychometric credit tier (Prime/Subprime).
106. `tax_return_filing_amount`: Total reported tax liability.
107. `demat_bo_account_number`: Depository Beneficiary Owner ID.
108. `stock_broker_client_code`: Brokerage equity trading account.
109. `mutual_fund_folio_number`: Investment fund folio ID.
110. `ethereum_wallet_address`: 42-char hex Ethereum public address.
111. `bitcoin_wallet_address`: Base58 / Bech32 Bitcoin address.
112. `solana_wallet_address`: Base58 Solana public key.
113. `financial_hardship_status`: Consumer debt assistance classification.
114. `bankruptcy_case_number`: Federal insolvency court docket ID.
115. `pension_beneficiary_id`: Retirement benefit disbursement ID.

---

### Domain 6: Payment Card Industry (PCI-DSS) (15 Entities)
116. `primary_card_number_pan`: 16-digit credit card number.
117. `debit_card_number`: Direct bank debit card number.
118. `card_expiration_month`: 2-digit validity month.
119. `card_expiration_year`: 4-digit validity year.
120. `card_verification_value_cvv`: 3-digit or 4-digit security code.
121. `cardholder_full_name`: Embossed name on payment card.
122. `card_issuing_bank`: Financial institution issuing the card.
123. `card_brand_network`: Visa, Mastercard, American Express, RuPay.
124. `emv_chip_application_cryptogram`: Smartcard cryptographic payload.
125. `track1_magnetic_stripe_data`: Full magnetic stripe Track 1 payload.
126. `track2_magnetic_stripe_data`: Magnetic stripe Track 2 financial payload.
127. `apple_pay_device_token`: Device Primary Account Number (DPAN).
128. `virtual_card_number`: One-time single-use virtual payment card.
129. `prepaid_gift_card_pin`: Stored-value card redemption PIN.
130. `ebt_benefits_card_number`: Government electronic food benefits card.

---

### Domain 7: Employment & Corporate HR (20 Entities)
131. `corporate_employee_id`: Internal corporate worker badge ID.
132. `work_email_address`: Corporate employer email address.
133. `job_title_designation`: Official organizational role.
134. `business_department`: Corporate operational division.
135. `official_hire_date`: Start date of employment contract.
136. `employment_termination_date`: Exit or contract expiration date.
137. `contract_employment_type`: Full-time, contractor, intern.
138. `base_monthly_salary`: Fixed monthly compensation.
139. `annual_bonus_incentive`: Variable performance incentive.
140. `esop_stock_grant_units`: Employee equity option units.
141. `performance_appraisal_rating`: Annual managerial review score.
142. `disciplinary_incident_record`: Internal HR misconduct documentation.
143. `direct_manager_supervisor_name`: Line manager reporting identity.
144. `india_epfo_uan_number`: Indian Employees' Provident Fund UAN.
145. `india_esic_insurance_number`: Indian Employee State Insurance code.
146. `nps_pran_retirement_number`: National Pension System PRAN.
147. `foreign_work_permit_visa`: H-1B, Tier 2, Blue Card visa number.
148. `corporate_travel_card_number`: Corporate expense credit line.
149. `timesheet_biometric_hours`: Clock-in and clock-out hours.
150. `labor_union_member_id`: Organized collective bargaining ID.

---

### Domain 8: Health & Medical (HIPAA / EHR) (25 Entities)
151. `hospital_patient_id`: Clinical patient registration code.
152. `electronic_health_record_ehr`: Longitudinal EHR file number.
153. `medical_record_number_mrn`: Hospital department medical chart ID.
154. `icd10_diagnosis_code`: International Classification of Diseases code.
155. `clinical_diagnosis_text`: Physician clinical condition description.
156. `prescription_drug_name`: Pharmaceutical medicine title.
157. `medication_dosage_frequency`: Posology, strength, and interval.
158. `attending_physician_name`: Treating doctor identity.
159. `hospital_clinic_facility`: Healthcare clinical enterprise.
160. `health_insurance_policy_no`: Medical insurance subscriber ID.
161. `insurance_group_number`: Employer insurance group code.
162. `medical_claim_id`: Adjudicated healthcare billing claim ID.
163. `blood_group_rh_factor`: ABO and Rhesus blood classification.
164. `body_mass_index_bmi`: Height-to-weight biological metric.
165. `known_allergies_list`: Drug and food hypersensitivity alerts.
166. `laboratory_test_panel`: Blood, lipid, or metabolic test panel.
167. `lab_result_numeric_value`: Quantitative diagnostic biomarker result.
168. `covid19_vaccine_certificate_id`: Immunization registry certificate.
169. `organ_donor_registered_status`: Anatomical gift registry status.
170. `dna_genetic_sequencing_id`: Genomic sequencing dataset token.
171. `disability_impairment_code`: Functional physical/mental limitation code.
172. `psychiatric_clinical_note`: Behavioral health session evaluation.
173. `surgical_procedure_history`: Inpatient surgical intervention record.
174. `india_abha_digital_health_id`: Ayushman Bharat 14-digit Health Account.
175. `uk_nhs_number`: UK National Health Service 10-digit number.

---

### Domain 9: Biometric Templates & Physical Data (15 Entities)
176. `facial_recognition_embedding_vector`: 512-dim facial vector.
177. `facial_2d_landmark_coordinates`: 68-point facial feature map.
178. `fingerprint_minutiae_template`: ISO/IEC 19794 ridge endings and bifurcations.
179. `iris_scan_polar_code`: Gabor wavelet phase polar template.
180. `retina_vascular_pattern_vector`: Ocular fundus blood vessel structure.
181. `voiceprint_mfcc_embedding`: Mel-frequency cepstral acoustic vector.
182. `hand_geometry_dimensional_vector`: Hand palm and finger measurement matrix.
183. `gait_stride_analysis_vector`: Kinetic ambulation stride dynamics.
184. `keystroke_dynamics_timing_profile`: Typing flight and dwell latency profile.
185. `palm_print_ridge_minutiae`: Palmar friction ridge pattern.
186. `thermal_facial_signature`: Infrared thermogram vascular heat map.
187. `ear_canal_acoustic_biometric`: Auditory canal acoustic resonance signature.
188. `forensic_dental_odontology_chart`: Forensic dental prosthetics and charting.
189. `lip_motion_visual_vector`: Visual speech lip cadence vectors.
190. `subdermal_vein_infrared_pattern`: Near-infrared vascular hemoglobin pattern.

---

### Domain 10: Education & Student Records (FERPA) (15 Entities)
191. `institutional_student_id`: Primary college/school student ID.
192. `matriculation_enrollment_number`: Official university admission roll number.
193. `degree_conferred_title`: Bachelor, Master, Doctorate degree title.
194. `major_academic_discipline`: Primary undergraduate concentration.
195. `grade_point_average_gpa`: Cumulative 4.0 academic grade point scale.
196. `academic_letter_grade`: Course evaluation grade (A+, B, C).
197. `course_examination_marks`: Raw numerical exam score (out of 100).
198. `school_university_institution`: Accredited educational institution name.
199. `graduation_commencement_year`: Year of diploma conferral.
200. `class_percentile_rank`: Cohort academic standing percentile.
201. `official_academic_transcript_text`: Longitudinal coursework history.
202. `student_disciplinary_probation_note`: Academic misconduct record.
203. `standardized_sat_gre_gmat_score`: Psychometric entrance exam percentile.
204. `merit_scholarship_stipend_amount`: Financial academic grant allowance.
205. `federal_student_loan_identifier`: Government educational debt reference.

---

### Domain 11: Geolocation & Spatial Telemetry (15 Entities)
206. `gps_exact_latitude`: Precise decimal degree latitude coordinates.
207. `gps_exact_longitude`: Precise decimal degree longitude coordinates.
208. `gps_altitude_elevation`: Height above sea level in meters.
209. `speed_velocity_vector`: Telemetric ground speed in km/h.
210. `heading_compass_bearing`: Directional orientation angle (0-360°).
211. `geohash_spatial_code`: Hierarchical spatial bounding box code.
212. `residential_home_coordinates`: Nighttime cluster dwelling coordinates.
213. `primary_workplace_coordinates`: Daytime corporate workplace coordinates.
214. `daily_commute_route_history`: Chronological waypoint route history.
215. `cellular_cell_tower_id`: Base transceiver station (BTS) cell ID.
216. `wifi_router_bssid_mac`: Hardware MAC address of ambient Wi-Fi access point.
217. `ble_beacon_proximity_uuid`: Bluetooth Low Energy indoor beacon UUID.
218. `ip_derived_city_location`: GeoIP regional municipality inference.
219. `geofence_boundary_polygon`: Spatial perimeter boundary fence.
220. `ride_hail_pickup_dropoff_gps`: Ride transport passenger waypoints.

---

### Domain 12: Digital Telemetry, Device & Network (20 Entities)
221. `client_ipv4_address`: Public/private 32-bit internet protocol address.
222. `client_ipv6_address`: 128-bit global unicast IP address.
223. `network_mac_hardware_address`: Layer 2 Ethernet/Wi-Fi adapter hardware address.
224. `device_cellular_imei`: 15-digit International Mobile Equipment Identity.
225. `sim_card_imsi_number`: 15-digit International Mobile Subscriber Identity.
226. `apple_idfa_advertising_id`: Apple Identifier for Advertisers.
227. `google_aaid_advertising_id`: Google Android Advertising ID.
228. `hardware_serial_number`: OEM motherboard/chassis serial string.
229. `http_cookie_session_identifier`: Persistent stateful web cookie ID.
230. `authenticated_web_session_id`: Ephemeral backend server session token.
231. `oauth2_access_token_bearer`: Bearer token for resource access.
232. `oauth2_refresh_token`: Long-lived token exchange secret.
233. `jwt_id_token_claim`: JSON Web Token identity claims payload.
234. `canvas_fingerprint_hash`: HTML5 canvas rendering entropy hash.
235. `webgl_renderer_hardware_string`: GPU driver hardware identification string.
236. `browser_user_agent_header`: Client browser, OS, and rendering engine string.
237. `tls_client_ja3_fingerprint`: TLS client hello cipher suite fingerprint.
238. `csrf_prevention_token`: Anti-cross-site request forgery token.
239. `apns_fcm_push_device_token`: Apple APNs / Firebase FCM device push registration token.
240. `battery_level_charging_telemetry`: Mobile battery charge and state-of-charge metric.
