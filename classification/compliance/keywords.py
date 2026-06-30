from __future__ import annotations

from classification.compliance.raw_gdpr_keywords import (
    RAW_ACCOUNT_RECOVERY_KEYWORDS,
    RAW_ACCOUNT_USERNAME_KEYWORDS,
    RAW_ADDRESS_KEYWORDS,
    RAW_BIRTH_KEYWORDS,
    RAW_BIOMETRIC_SPECIAL_KEYWORDS,
    RAW_BACKGROUND_DRUG_TEST_KEYWORDS,
    RAW_BENEFITS_INSURANCE_KEYWORDS,
    RAW_BOARD_MATERIALS_KEYWORDS,
    RAW_BROWSING_HISTORY_KEYWORDS,
    RAW_BANK_ACCOUNT_KEYWORDS,
    RAW_CONTRACT_NDA_LEGAL_KEYWORDS,
    RAW_COOKIE_DEVICE_ID_KEYWORDS,
    RAW_CREDIT_SCORE_REPORT_KEYWORDS,
    RAW_CRIMINAL_RECORD_KEYWORDS,
    RAW_DATABASE_CONNECTION_KEYWORDS,
    RAW_DEVICE_HARDWARE_KEYWORDS,
    RAW_DISABILITY_STATUS_KEYWORDS,
    RAW_DISASTER_RECOVERY_BCP_KEYWORDS,
    RAW_EMAIL_KEYWORDS,
    RAW_ENCRYPTION_KEY_MATERIAL_KEYWORDS,
    RAW_EMERGENCY_CONTACT_KEYWORDS,
    RAW_GEOLOCATION_KEYWORDS,
    RAW_GENETIC_DNA_KEYWORDS,
    RAW_GOVERNMENT_ID_KEYWORDS,
    RAW_HEALTH_MEDICAL_KEYWORDS,
    RAW_HR_EMPLOYEE_FILE_KEYWORDS,
    RAW_IMMIGRATION_CITIZENSHIP_KEYWORDS,
    RAW_INCIDENT_ACCESS_AUDIT_LOG_KEYWORDS,
    RAW_INVOICE_BILLING_TRANSACTION_KEYWORDS,
    RAW_IP_IDENTIFIER_KEYWORDS,
    RAW_LITIGATION_PRIVILEGED_LEGAL_KEYWORDS,
    RAW_MENTAL_HEALTH_KEYWORDS,
    RAW_NAME_KEYWORDS,
    RAW_API_TOKEN_SECRET_KEYWORDS,
    RAW_NETWORK_ARCHITECTURE_KEYWORDS,
    RAW_ORG_CHART_DIRECTORY_KEYWORDS,
    RAW_PASSWORD_SECRET_KEYWORDS,
    RAW_PAYMENT_CARD_KEYWORDS,
    RAW_PHONE_KEYWORDS,
    RAW_PHYSICAL_SECURITY_BADGE_CCTV_KEYWORDS,
    RAW_PHOTO_FACE_KEYWORDS,
    RAW_POLITICAL_AFFILIATION_KEYWORDS,
    RAW_PRERELEASE_FINANCIAL_KEYWORDS,
    RAW_PRICING_MARGIN_FORECAST_KEYWORDS,
    RAW_PRIVATE_KEY_CERT_KEYWORDS,
    RAW_MA_DUE_DILIGENCE_KEYWORDS,
    RAW_PATENT_PENDING_KEYWORDS,
    RAW_RACE_ETHNICITY_KEYWORDS,
    RAW_RELIGIOUS_BELIEF_KEYWORDS,
    RAW_SEXUAL_ORIENTATION_KEYWORDS,
    RAW_SESSION_TOKEN_JWT_KEYWORDS,
    RAW_SECURITY_CONFIG_FIREWALL_KEYWORDS,
    RAW_SIGNATURE_KEYWORDS,
    RAW_SALARY_COMPENSATION_KEYWORDS,
    RAW_SOURCE_CODE_ALGORITHM_KEYWORDS,
    RAW_STRATEGY_ROADMAP_PLAN_KEYWORDS,
    RAW_TAX_RECORD_KEYWORDS,
    RAW_TERMINATION_LAYOFF_KEYWORDS,
    RAW_TIMESHEET_ATTENDANCE_KEYWORDS,
    RAW_TRADE_UNION_KEYWORDS,
    RAW_TRADE_SECRET_DESIGN_KEYWORDS,
    RAW_MFA_RECOVERY_KEYWORDS,
    RAW_VENDOR_SUPPLIER_TERMS_KEYWORDS,
    RAW_VEHICLE_KEYWORDS,
    RAW_VULNERABILITY_PENTEST_KEYWORDS,
)


def _dedupe_keywords(*groups: tuple[str, ...]) -> tuple[str, ...]:
    seen: set[str] = set()
    merged: list[str] = []
    for group in groups:
        for item in group:
            keyword = " ".join(str(item or "").strip().split())
            key = keyword.lower()
            if keyword and key not in seen:
                seen.add(key)
                merged.append(keyword)
    return tuple(merged)


NAME_KEYWORDS = (
    "full name", "legal name", "official name", "registered name", "personal name",
    "customer name", "client name", "employee name", "staff name", "applicant name",
    "candidate name", "student name", "patient name", "account holder name",
    "cardholder name", "policyholder name", "contact name", "representative name",
    "authorized person", "guardian name", "parent name", "father name", "mother name",
    "first name", "given name", "forename", "middle name", "last name", "surname",
    "family name", "patronymic", "maiden name", "birth name", "former name",
    "preferred name", "display name", "known as", "also known as", "aka", "alias",
    "nickname", "username", "user name", "account name", "passport name",
    "identity name", "taxpayer name", "insured name", "claimant name",
    "director name", "shareholder name", "beneficial owner name", "ubo name",
    "tam ad", "ad soyad", "ad ve soyad", "sexsin adi", "sexs adi",
    "musteri adi", "klient adi", "emekdas adi", "isci adi", "namized adi",
    "telebe adi", "pasiyent adi", "xeste adi", "hesab sahibinin adi",
    "kart sahibinin adi", "istifadeci adi", "elaqe sexsi", "ata adi",
    "ana adi", "soyad", "soyadi", "aile adi", "leqeb", "texellus",
)

EMAIL_KEYWORDS = (
    "email", "e-mail", "email address", "e-mail address", "mail address",
    "electronic mail", "contact email", "primary email", "secondary email",
    "personal email", "private email", "business email", "work email",
    "corporate email", "recovery email", "billing email", "invoice email",
    "registered email", "login email", "user email", "customer email",
    "client email", "employee email", "patient email", "email id",
    "email account", "elektron poct", "e-poct", "email unvani",
    "poct unvani", "elaqe emaili", "esas email", "sexsi email",
    "is emaili", "qeydiyyat emaili", "giris emaili", "istifadeci emaili",
    "musteri emaili", "emekdas emaili", "isci emaili",
)

PHONE_KEYWORDS = (
    "phone", "phone number", "telephone", "telephone number", "tel", "mobile",
    "mobile number", "gsm", "cell", "cell phone", "contact number",
    "primary phone", "secondary phone", "home phone", "work phone",
    "business phone", "office phone", "personal phone", "emergency phone",
    "fax", "whatsapp number", "telegram number", "sms number", "callback number",
    "customer phone", "client phone", "employee phone", "telefon",
    "telefon nomresi", "nomre", "elaqe nomresi", "esas nomre", "mobil nomre",
    "mobil telefon", "sexsi nomre", "is nomresi", "is telefonu", "ofis telefonu",
    "ev telefonu", "tecili elaqe nomresi", "faks nomresi", "whatsapp nomresi",
    "telegram nomresi", "sms nomresi", "musteri telefonu", "istifadeci telefonu",
)

ADDRESS_KEYWORDS = (
    "address", "postal address", "mailing address", "residential address",
    "home address", "private address", "work address", "office address",
    "business address", "registered address", "legal address", "permanent address",
    "temporary address", "current address", "physical address", "delivery address",
    "shipping address", "billing address", "correspondence address", "street address",
    "address line", "address line 1", "address1", "building number", "house number",
    "apartment number", "flat number", "unit number", "floor", "entrance", "block",
    "building", "house", "apartment", "street", "avenue", "road", "boulevard",
    "district", "city", "town", "village", "zip code", "postal code", "country",
    "unvan", "unvani", "poct unvani", "yasayis unvani", "ev unvani",
    "sexsi unvan", "is unvani", "ofis unvani", "huquqi unvan", "faktiki unvan",
    "daimi unvan", "muveqqeti unvan", "cari unvan", "catdirilma unvani",
    "kuce", "kuce adi", "prospekt", "yol", "rayon", "seher", "qesebe",
    "kend", "bolge", "olke", "bina", "bina nomresi", "ev nomresi",
    "menzil", "menzil nomresi", "blok", "giris", "mertebe", "poct indeksi",
)

BIRTH_KEYWORDS = (
    "date of birth", "dateofbirth", "dob", "d.o.b.", "birth date", "birthdate",
    "birthday", "born date", "born on", "year of birth", "birth year",
    "month of birth", "day of birth", "age", "place of birth", "birth place",
    "birthplace", "born in", "city of birth", "birth city", "country of birth",
    "birth country", "region of birth", "birth region", "district of birth",
    "birth district", "town of birth", "birth town", "village of birth",
    "birth village", "birth location", "native city", "native country", "hometown",
    "birth certificate date", "birth registration date", "birth registry",
    "employee dob", "customer dob", "patient dob", "passport dob", "id dob",
    "dogum tarixi", "tevellud", "tevellud tarixi", "anadan olma tarixi",
    "doguldugu tarix", "dogum gunu", "dogum ili", "dogum ayi", "yas",
    "doguldugu yer", "dogum yeri", "doguldugu seher", "dogum seheri",
    "doguldugu olke", "dogum olkesi", "dogum rayonu", "dogma seher",
)

GOVERNMENT_ID_KEYWORDS = (
    "government id", "government identifier", "official id", "identity number",
    "identification number", "id number", "national id", "personal id",
    "personal number", "personal code", "pin", "pin code", "citizen id",
    "resident id", "identity card", "id card", "identity document",
    "document id", "document number", "document no", "document serial",
    "serial number", "id serial", "fin", "fin code", "fincode", "passport",
    "passport number", "passport no", "passport id", "passport serial",
    "driver license", "driver's license", "driving license", "license number",
    "dl number", "tax id", "tax identification number", "tin", "taxpayer id",
    "vat id", "ssn", "social security number", "social insurance number",
    "insurance number", "health insurance number", "visa number", "work permit number",
    "permit number", "military id", "voter id", "electronic id", "biometric id",
    "dovlet id", "resmi id", "sexsiyyet nomresi", "identifikasiya nomresi",
    "id nomresi", "milli id", "sexsi id", "ferdi nomre", "ferdi kod",
    "vetendas id", "rezident id", "sexsiyyet vesiqesi", "vesiqe nomresi",
    "sened nomresi", "seriya nomresi", "fin kod", "pasport", "pasport nomresi",
    "suruculuk vesiqesi", "lisenziya nomresi", "vergi id", "voen", "sigorta nomresi",
)

SIGNATURE_KEYWORDS = (
    "signature", "signature value", "signature_value", "signed", "is signed",
    "signatory", "signer", "signed by", "authorized signer", "handwritten signature",
    "physical signature", "wet signature", "manual signature", "paper signature",
    "ink signature", "digital signature", "electronic signature", "e-signature",
    "biometric signature", "signature image", "signature scan", "scanned signature",
    "signature file", "signature attachment", "signature png", "signature jpg",
    "signature jpeg", "signature pdf", "signature blob", "signature data",
    "signature base64", "signature hash", "signature specimen", "signature sample",
    "signature capture", "signature pad", "signature block", "signature field",
    "sign here", "customer signature", "client signature", "employee signature",
    "contract signature", "agreement signature", "consent signature", "signed document",
    "signed agreement", "signed contract", "signature date", "signature timestamp",
    "digital certificate", "signing certificate", "certificate thumbprint",
    "public key signature", "pki signature", "signed hash", "signed payload",
    "imza", "imzalanmis", "imzali", "imzalayan", "el imzasi", "fiziki imza",
    "reqemsal imza", "elektron imza", "e-imza", "asan imza", "sima imza",
    "imza sekli", "imza skani", "imza fayli", "imza png", "imza jpg",
    "imza jpeg", "imza pdf", "imza base64", "imza hash", "imza numunesi",
    "imza yeri", "musteri imzasi", "isci imzasi", "muqavile imzasi",
    "imza tarixi", "imza sertifikati",
)

PHOTO_FACE_KEYWORDS = (
    "photo", "photograph", "picture", "image", "portrait", "profile photo",
    "profile picture", "user photo", "customer photo", "employee photo",
    "passport photo", "id photo", "identity photo", "document photo",
    "face photo", "face image", "facial image", "portrait image", "headshot",
    "mugshot", "face scan", "face capture", "face template", "face vector",
    "face embedding", "biometric photo", "biometric image", "biometric face",
    "biometric template", "facial recognition", "face recognition", "face id",
    "selfie", "kyc photo", "kyc selfie", "onboarding selfie",
    "verification photo", "identity verification photo", "video selfie",
    "selfie with document", "face liveness", "liveness image", "avatar",
    "photo file", "image file", "photo base64", "face base64",
    "foto", "sekil", "portret", "profil sekli", "profil fotosu",
    "pasport sekli", "sexsiyyet sekli", "uz sekli", "sifet sekli",
    "uz skani", "sifet skani", "uz embedding", "uz tanima",
    "biometrik sekil", "biometrik foto", "selfi", "kyc sekli",
    "canliliq yoxlamasi", "foto fayli",
)

VEHICLE_KEYWORDS = (
    "vehicle plate", "license plate", "licence plate", "number plate",
    "registration plate", "plate number", "vehicle registration number",
    "registration number", "vehicle number", "vin", "vin number", "vin code",
    "vehicle identification number", "chassis number", "frame number",
    "body number", "engine number", "motor number", "vehicle serial number",
    "vehicle make", "vehicle model", "model year", "vehicle color",
    "vehicle owner", "car owner", "registered owner", "vehicle registration",
    "technical passport", "vehicle passport", "vehicle insurance",
    "parking permit", "toll tag", "road tax number",
    "neqliyyat vasitesi nomresi", "avtomobil nomresi", "masin nomresi",
    "dovlet nomre nisani", "nomre nisani", "qeydiyyat nomresi",
    "vin kod", "vin nomresi", "sassi nomresi", "kuzov nomresi",
    "muherrik nomresi", "motor nomresi", "avtomobil markasi",
    "masin modeli", "avtomobil ili", "avtomobil rengi",
)

ACCOUNT_RECOVERY_KEYWORDS = (
    "mother's maiden name", "mothers maiden name", "mother maiden name",
    "maternal maiden name", "maternal surname", "security question",
    "security answer", "secret question", "secret answer", "challenge question",
    "challenge answer", "recovery question", "recovery answer",
    "account recovery question", "account recovery answer",
    "password recovery question", "password recovery answer",
    "verification question", "verification answer", "authentication question",
    "authentication answer", "kba", "kba question", "kba answer",
    "memorable word", "memorable answer", "memorable phrase",
    "security phrase", "secret phrase", "recovery phrase", "password hint",
    "login hint", "account hint", "first pet name", "first school",
    "childhood friend", "favorite teacher", "favorite color", "birth city question",
    "first car", "first job", "favorite food", "favorite movie",
    "ananin qizliq soyadi", "ana qizliq soyadi", "tehlukesizlik suali",
    "tehlukesizlik cavabi", "gizli sual", "gizli cavab", "berpa suali",
    "berpa cavabi", "parol ipucu", "yadda qalan soz",
)

EMERGENCY_CONTACT_KEYWORDS = (
    "next of kin", "nok", "emergency contact", "emergency contact person",
    "emergency contact name", "emergency contact number", "emergency phone",
    "emergency address", "emergency email", "relative contact", "family contact",
    "guardian contact", "guardian phone", "guardian address", "parent contact",
    "spouse contact", "caregiver contact", "dependent contact",
    "contact in case of emergency", "ice contact", "primary emergency contact",
    "secondary emergency contact", "relationship to employee", "contact relationship",
    "kinship", "relative name", "relative phone", "relative address",
    "guardian name", "parent name", "spouse name", "medical emergency contact",
    "next of kin name", "next of kin phone", "nok name", "nok phone",
    "yaxin qohum", "qohum melumati", "qohum elaqesi", "qohum adi",
    "qohum telefonu", "qohum unvani", "tecili elaqe", "tecili elaqe sexsi",
    "tecili elaqe adi", "tecili elaqe nomresi", "tecili telefon",
    "qeyyum adi", "valideyn adi", "heyat yoldasi adi", "qohumluq derecesi",
)

IP_IDENTIFIER_KEYWORDS = (
    "ip address", "ip addr", "source ip", "src ip", "destination ip", "dst ip",
    "remote ip", "local ip", "client ip", "server ip", "host ip", "user ip",
    "customer ip", "visitor ip", "device ip", "endpoint ip", "public ip",
    "private ip", "external ip", "internal ip", "last login ip", "login ip",
    "session ip", "request ip", "origin ip", "forwarded ip", "x-forwarded-for",
    "x real ip", "true client ip", "cf connecting ip", "proxy ip", "vpn ip",
    "tor ip", "nat ip", "gateway ip", "router ip", "wan ip", "lan ip",
    "ipv4", "ipv4 address", "ipv6", "ipv6 address", "access log ip",
    "audit ip", "firewall ip", "dhcp ip", "geoip", "ip geolocation",
    "anonymized ip", "masked ip", "hashed ip", "ip unvan", "ip unvani",
    "ip adres", "ip adresi", "menbe ip", "teyinat ip", "uzaq ip",
    "lokal ip", "musteri ip", "istifadeci ip", "cihaz ip", "daxili ip",
    "xarici ip", "aciq ip", "ozel ip", "giris ip", "sessiya ip",
    "sorgu ip", "proksi ip", "sluz ip",
)

COOKIE_DEVICE_ID_KEYWORDS = (
    "cookie", "cookie id", "cookie value", "tracking cookie", "tracking id",
    "advertising id", "ad id", "mobile advertising id", "maid", "aaid",
    "google advertising id", "gaid", "android advertising id", "idfa", "idfv",
    "device id", "device identifier", "unique device id", "persistent id",
    "anonymous id", "user id", "visitor id", "client id", "customer id",
    "session id", "browser id", "installation id", "app instance id",
    "firebase installation id", "fcm token", "push token", "apns token",
    "device token", "google analytics id", "ga client id", "_ga", "_gid",
    "utm id", "campaign id", "pixel id", "_fbp", "_fbc", "click id",
    "gclid", "gbraid", "wbraid", "fbclid", "msclkid", "ttclid", "yclid",
    "affiliate id", "referral id", "consent string", "tc string", "tcf string",
    "euconsent", "fingerprint id", "browser fingerprint", "device fingerprint",
    "rfid", "beacon id", "bluetooth id", "wifi probe id", "tracking token",
    "analytics token", "pseudonymous id", "kuki", "cerez", "reklam id",
    "cihaz id", "anonim id", "istifadeci id", "sessiya id", "bildiris tokeni",
    "raziliq string", "barmaq izi id",
)

DEVICE_HARDWARE_KEYWORDS = (
    "mac address", "mac id", "hardware address", "physical address",
    "ethernet address", "wifi mac", "bluetooth mac", "bssid", "access point mac",
    "router mac", "device mac", "client mac", "host mac", "endpoint mac",
    "network adapter address", "nic address", "interface mac", "imei",
    "imei number", "device imei", "phone imei", "mobile imei", "imei1", "imei2",
    "meid", "esn", "electronic serial number", "serial number", "device serial",
    "hardware serial", "imsi", "imsi number", "subscriber identity", "sim imsi",
    "sim id", "sim serial", "iccid", "eid", "esim id", "msisdn",
    "mac unvan", "mac adresi", "fiziki unvan", "cihaz mac", "telefon mac",
    "imei nomresi", "cihaz imei", "seriya nomresi", "imsi nomresi",
    "abuneci identifikatoru", "sim kart id", "iccid nomresi",
)

GEOLOCATION_KEYWORDS = (
    "geolocation", "location data", "location history", "location tracking",
    "gps", "gps coordinates", "gps trail", "gps track", "latitude", "longitude",
    "lat", "lng", "coordinates", "coordinate pair", "current location",
    "last known location", "home location", "work location", "office location",
    "live location", "movement history", "route history", "trip log",
    "visited places", "check-in", "geofence", "cell tower location",
    "wifi location", "bluetooth location", "beacon location", "geoip location",
    "map pin", "delivery location", "pickup location", "dropoff location",
    "driver location", "tracking route", "location accuracy", "altitude",
    "bearing", "heading", "lokasiya", "yer melumati", "gps koordinat",
    "enlik", "uzunluq", "koordinat", "cari lokasiya", "son melum lokasiya",
    "ev lokasiyasi", "is lokasiyasi", "hereket tarixcesi", "marsrut tarixcesi",
)

BROWSING_HISTORY_KEYWORDS = (
    "browsing history", "browser history", "web history", "visited url",
    "visited page", "url history", "page view", "clickstream", "click path",
    "search history", "search query", "query history", "referrer", "referer",
    "utm source", "utm campaign", "landing page", "exit page", "session replay",
    "heatmap", "web analytics", "user journey", "navigation history",
    "page visited", "site visit", "history url", "browser url", "axtaris sorğusu",
    "axtaris sorgusu", "baxis tarixcesi", "klik axini", "ziyaret edilen sehife",
)

ACCOUNT_USERNAME_KEYWORDS = (
    "username", "user name", "login name", "user id", "account id",
    "profile id", "display name", "screen name", "public name", "handle",
    "social handle", "public handle", "alias", "nickname", "online alias",
    "telegram username", "whatsapp username", "signal username", "discord username",
    "skype id", "slack username", "teams username", "jira username",
    "confluence username", "github username", "gitlab username",
    "bitbucket username", "linkedin username", "twitter username", "x username",
    "instagram username", "facebook username", "tiktok username", "reddit username",
    "profile slug", "account slug", "vanity url", "employee username",
    "customer username", "created by username", "assigned username",
    "istifadeci adi", "istifadeci id", "hesab adi", "login adi", "profil adi",
    "ekran adi", "leqeb", "texellus", "telegram istifadeci adi",
)

HEALTH_MEDICAL_KEYWORDS = (
    "health data", "health information", "medical data", "medical information",
    "medical record", "health record", "patient record", "patient chart",
    "diagnosis", "disease", "condition", "symptom", "treatment", "therapy",
    "care plan", "clinical note", "doctor note", "nurse note", "discharge summary",
    "admission note", "progress note", "lab result", "blood test", "urine test",
    "radiology result", "imaging result", "x-ray", "mri", "ct scan", "prescription",
    "medication", "dosage", "allergy", "vaccination", "immunization", "vital signs",
    "blood pressure", "heart rate", "body temperature", "bmi", "patient id",
    "medical id", "health insurance", "medical claim", "icd code", "cpt code",
    "procedure code", "surgery", "operation", "hospitalization", "ambulance",
    "triage", "oncology", "cardiology", "neurology", "dental record",
    "medical certificate", "sick leave", "clinical assessment", "hospital",
    "clinic", "pharmacy", "tibbi melumat", "tibbi qeyd", "xeste", "diaqnoz",
    "mualice", "resept", "derman", "analiz", "laboratoriya", "peyvənd",
)

MENTAL_HEALTH_KEYWORDS = (
    "mental health", "mental illness", "mental disorder", "psychological health",
    "psychiatric record", "psychiatric diagnosis", "psychological evaluation",
    "psychiatric assessment", "psychotherapy", "therapy session", "counselling",
    "therapy note", "depression", "anxiety", "panic disorder", "bipolar",
    "schizophrenia", "ptsd", "ocd", "adhd", "autism", "eating disorder",
    "anorexia", "bulimia", "self-harm", "suicidal ideation", "suicide risk",
    "crisis assessment", "substance use", "substance abuse", "addiction",
    "dependence", "alcohol use", "drug use", "opioid", "cocaine", "heroin",
    "meth", "cannabis", "drug test", "toxicology", "blood alcohol", "bac",
    "rehab", "detox", "recovery program", "relapse", "overdose", "sobriety",
    "methadone", "buprenorphine", "naloxone", "naltrexone", "psixi saglamliq",
    "psixiatriya", "psixoloji", "depressiya", "narahatliq", "asılılıq", "asililiq",
)

DISABILITY_STATUS_KEYWORDS = (
    "disability", "disability status", "disabled", "person with disability",
    "disability certificate", "disability card", "disability document",
    "disability benefit", "disability allowance", "disability pension",
    "disability claim", "disability assessment", "physical impairment",
    "sensory impairment", "mobility impairment", "visual impairment",
    "hearing impairment", "cognitive disability", "intellectual disability",
    "developmental disability", "autism spectrum", "neurodivergence",
    "learning disability", "special needs", "special assistance",
    "accessibility need", "reasonable accommodation", "modified duty",
    "light duty", "work restriction", "functional limitation", "work capacity",
    "incapacity", "permanent disability", "temporary disability",
    "assistive device", "mobility aid", "wheelchair", "hearing aid",
    "prosthesis", "orthosis", "screen reader", "braille", "sign language",
    "occupational health", "rehabilitation assessment", "elillik", "elil",
    "elillik statusu", "elillik arayisi", "xususi ehtiyac", "reabilitasiya",
)

BIOMETRIC_SPECIAL_KEYWORDS = (
    "biometric", "biometric data", "biometric identifier", "biometric id",
    "biometric template", "biometric profile", "biometric record", "fingerprint",
    "thumbprint", "fingerprint scan", "palm print", "hand geometry", "faceprint",
    "face template", "facial recognition", "face scan", "face id",
    "facial geometry", "facial landmarks", "iris", "iris scan", "iris template",
    "retina", "retinal scan", "eye scan", "voiceprint", "voice biometric",
    "speaker recognition", "voice authentication", "gait", "walking pattern",
    "movement biometric", "behavioral biometric", "keystroke dynamics",
    "typing pattern", "signature dynamics", "handwriting biometric",
    "vein pattern", "palm vein", "finger vein", "liveness check",
    "anti-spoofing", "biometric match", "biometric score", "biometric hash",
    "biometric vector", "embedding", "biometric enrollment",
    "biometric verification", "biometric authentication", "biometrik",
    "barmaq izi", "uz tanima", "iris skani", "ses biometrik", "canliliq yoxlamasi",
)

GENETIC_DNA_KEYWORDS = (
    "genetic data", "genetic information", "genetic record", "genetic profile",
    "genetic test", "genetic testing", "genetic analysis", "genetic screening",
    "gene", "gene sequence", "genome", "genomic data", "whole genome sequencing",
    "exome", "whole exome sequencing", "dna data", "dna profile", "dna test",
    "dna sample", "biological sample", "dna sequence", "dna sequencing",
    "genetic marker", "dna marker", "snp", "allele", "genotype", "phenotype",
    "genetic variant", "mutation", "pathogenic variant", "vus", "variant report",
    "brca", "brca1", "brca2", "genetic disease", "inherited disease",
    "rare genetic disease", "genetic risk", "predisposition", "carrier status",
    "chromosome", "chromosomal abnormality", "karyotype", "haplogroup",
    "haplotype", "ancestry dna", "genealogy dna", "paternity dna",
    "maternity dna", "kinship dna", "forensic dna", "dna fingerprint",
    "pharmacogenetic", "pharmacogenomic", "pgx", "genetic consent",
    "genetic counseling", "genetik", "dna", "genom", "gen testi",
)

RACE_ETHNICITY_KEYWORDS = (
    "race", "racial origin", "racial identity", "ethnicity", "ethnic origin",
    "ethnic identity", "national origin", "ancestry", "descent", "tribal origin",
    "indigenous origin", "aboriginal origin", "cultural origin", "heritage",
    "ethno-cultural identity", "multiracial", "mixed race", "minority group",
    "minority status", "race declaration", "ethnicity declaration", "diversity",
    "dei", "equal opportunity data", "inferred race", "inferred ethnicity",
    "azerbaijani ethnicity", "armenian ethnicity", "georgian ethnicity",
    "russian ethnicity", "jewish ethnicity", "irqi", "irq", "etnik",
    "etnik mensubiyyet", "milli mensubiyyet", "soy kok", "azliq qrupu",
)

RELIGIOUS_BELIEF_KEYWORDS = (
    "religion", "religious data", "religious belief", "religious beliefs",
    "faith", "faith belief", "religious status", "religious affiliation",
    "religious membership", "religious community", "religious organization",
    "religious identity", "denomination", "sect", "spiritual belief",
    "spirituality", "atheism", "agnosticism", "christian", "muslim", "islam",
    "judaism", "jewish religion", "buddhist", "hindu", "catholic", "orthodox",
    "protestant", "sunni", "shia", "prayer", "fasting", "halal", "kosher",
    "religious holiday", "religious accommodation", "religious exemption",
    "religious certificate", "baptism record", "church marriage",
    "philosophical belief", "worldview", "ideology", "ethical belief",
    "moral belief", "conscience belief", "belief declaration", "din",
    "dini inanc", "dini mensubiyyet", "mezheb", "felsefi inanc",
)

POLITICAL_AFFILIATION_KEYWORDS = (
    "political data", "political opinion", "political view", "political belief",
    "political affiliation", "party affiliation", "political party",
    "party membership", "campaign membership", "campaign volunteer",
    "political donor", "political donation", "political contribution",
    "voting preference", "voting intention", "voting history", "ballot choice",
    "candidate preference", "political activism", "petition", "signed petition",
    "protest", "demonstration", "rally", "march", "political event",
    "lobbying", "lobbyist", "public policy position", "political ideology",
    "ideological position", "conservative", "liberal", "socialist",
    "political risk profile", "political declaration", "voter profile",
    "voter registration", "electoral register", "campaign list", "donor list",
    "political survey", "election survey", "polling", "siyasi", "siyasi fikir",
    "partiya", "partiya uzvluyu", "secici", "sesvermə", "sesverme",
)

SEXUAL_ORIENTATION_KEYWORDS = (
    "sexual orientation", "sexuality", "sexual identity", "sexual preference",
    "sex life", "sexual life", "romantic orientation", "gender identity",
    "gender expression", "lgbtq", "pride membership", "gay", "lesbian",
    "bisexual", "asexual", "same-sex relationship", "same-gender relationship",
    "domestic partner", "intimate partner", "sensitive relationship status",
    "sexual history", "sexual activity", "sexual behavior", "sexual health",
    "reproductive health", "contraception", "pregnancy", "abortion",
    "fertility treatment", "ivf", "sti", "std", "hiv status",
    "sexual assault", "sexual abuse", "gender transition", "transgender",
    "transsexual", "nonbinary", "intersex", "pronouns", "pronoun preference",
    "sexual counselling", "reproductive history", "cinsi orientasiya",
    "cinsi kimlik", "hamilelik", "abort", "hiv statusu",
)

TRADE_UNION_KEYWORDS = (
    "trade union", "labor union", "labour union", "union membership",
    "union member", "unionized worker", "union affiliation", "union representative",
    "union steward", "union delegate", "union official", "union officer",
    "union organizer", "collective bargaining", "collective agreement",
    "union dues", "union fees", "union subscription", "union card",
    "union id", "union number", "union register", "union registry",
    "union list", "union roster", "payroll deduction", "strike participation",
    "industrial action", "union grievance", "employee association",
    "staff association", "works council", "employee council", "labor committee",
    "union election", "union ballot", "union status", "bargaining unit",
    "union workplace", "union consent", "hemkarlar ittifaqi", "ittifaq uzvluyu",
)

IMMIGRATION_CITIZENSHIP_KEYWORDS = (
    "immigration", "immigration data", "immigration status", "migration status",
    "legal status", "residency status", "citizenship", "nationality",
    "non-citizen", "foreign national", "alien status", "permanent resident",
    "temporary resident", "green card", "residence permit", "residence card",
    "work permit", "employment authorization", "visa status", "visa details",
    "entry permit", "exit permit", "border crossing", "passport country",
    "naturalization", "naturalized citizen", "asylum", "refugee", "stateless",
    "deportation", "removal", "immigration detention", "overstay",
    "immigration case", "immigration file", "immigration application",
    "immigration petition", "immigration interview", "immigration court",
    "immigration appeal", "immigration sponsor", "family sponsorship",
    "i-94", "uscis", "a-number", "sevis", "ds-160", "schengen visa",
    "migration card", "visa refusal", "entry ban", "protected status",
    "travel document", "alien document", "border stamp", "foreigner registration",
    "miqrasiya", "vetendasliq", "viza statusu", "yasayis icazesi",
)

CRIMINAL_RECORD_KEYWORDS = (
    "criminal record", "criminal records", "criminal history", "criminal background",
    "background check", "background screening", "police record", "police certificate",
    "police clearance", "criminal conviction", "conviction status",
    "criminal offence", "criminal offense", "criminal charge", "pending charge",
    "arrest", "detention", "custody", "sentence", "sentencing", "probation",
    "parole", "bail", "court record", "court case", "legal case",
    "criminal proceedings", "prosecution", "indictment", "warrant",
    "wanted person", "criminal investigation", "police report", "incident report",
    "forensic report", "criminal fingerprint", "law enforcement data",
    "sex offender", "offender registry", "sanctions", "watchlist",
    "pep screening", "adverse media", "disciplinary record", "security clearance",
    "employee screening", "right to work", "background verification",
    "criminal disclosure", "dbs", "good conduct certificate", "no conviction",
    "acquittal", "dismissed", "expunged", "sealed records", "criminal registry",
    "fraud", "corruption", "bribery", "financial crime", "cinayet qeydi",
    "mehkeme", "polis arayisi", "mehkumluq", "hebs", "sanksiya",
)

PAYMENT_CARD_KEYWORDS = (
    "payment card", "card data", "payment card data", "cardholder data",
    "card number", "payment card number", "credit card number", "debit card number",
    "primary account number", "pan", "full pan", "raw pan", "clear pan",
    "unmasked pan", "masked pan", "card last four", "last 4 digits",
    "card token", "payment token", "tokenized card", "cardholder name",
    "name on card", "card issuer", "issuing bank", "card brand", "card type",
    "visa", "mastercard", "amex", "card expiry", "expiry date", "valid thru",
    "cvv", "cvc", "cid", "card security code", "card pin", "pin block",
    "track data", "track_1", "track_2", "magstripe", "emv", "service code",
    "card fingerprint", "card hash", "stored card", "card on file",
    "payment credential", "card authorization", "3d secure", "card transaction",
    "pos transaction", "online payment", "payment vault", "bin", "iin",
    "pci", "cardholder data environment", "odenis karti", "kart nomresi",
    "kart sahibi", "kart token", "kartin bitme tarixi",
)

BANK_ACCOUNT_KEYWORDS = (
    "bank account", "bank account number", "account number", "financial account",
    "deposit account", "checking account", "savings account", "iban",
    "swift", "swift bic", "bic", "routing number", "aba routing", "sort code",
    "account holder", "beneficiary", "recipient account", "wire transfer",
    "bank transfer", "payment instruction", "direct debit", "standing order",
    "sepa", "ach", "bank statement", "account statement", "account balance",
    "available balance", "ledger balance", "bank name", "branch code",
    "correspondent bank", "intermediary bank", "bank hesabi", "iban nomresi",
    "swift kodu", "hesab nomresi", "benefisiar",
)

TAX_RECORD_KEYWORDS = (
    "tax", "tax data", "tax information", "tax record", "tax records",
    "tax return", "tax filing", "tax declaration", "tax form", "taxpayer",
    "taxpayer id", "tax identification number", "tin", "vat", "vat number",
    "ein", "w-2", "w2", "1099", "1040", "tax year", "taxable income",
    "withholding", "tax withholding", "tax refund", "tax liability",
    "tax assessment", "tax audit", "tax payment", "income tax", "payroll tax",
    "social security tax", "tax certificate", "tax transcript", "tax residency",
    "tax residence", "fiscal code", "vergi", "voen", "vergi beyannamesi",
    "vergi odemesi", "vergi ili",
)

SALARY_COMPENSATION_KEYWORDS = (
    "salary", "salary data", "base salary", "gross salary", "net salary",
    "monthly salary", "annual salary", "salary amount", "salary band",
    "salary range", "salary grade", "pay", "base pay", "gross pay",
    "net pay", "take home pay", "hourly pay", "pay rate", "wage", "wages",
    "earnings", "income", "employee income", "compensation",
    "total compensation", "remuneration", "payroll", "payroll data",
    "payroll file", "payroll record", "pay slip", "payslip", "pay stub",
    "bonus", "performance bonus", "commission", "incentive", "stock compensation",
    "equity compensation", "rsu", "stock option", "vesting", "allowance",
    "overtime", "severance", "final pay", "salary increase", "pay increase",
    "compensation review", "payroll deduction", "tax withholding",
    "pension contribution", "employee benefits", "compensation plan",
    "pay grade", "salary budget", "payroll cost", "labor cost", "ctc",
    "maas", "emek haqqi", "gelir", "kompensasiya", "maas vereqi",
)

CREDIT_SCORE_REPORT_KEYWORDS = (
    "credit score", "credit scores", "credit report", "credit file",
    "credit history", "creditworthiness", "credit risk", "credit risk score",
    "bureau score", "credit bureau", "experian", "equifax", "transunion",
    "credit check", "credit inquiry", "hard inquiry", "soft inquiry",
    "credit pull", "credit assessment", "underwriting score", "application score",
    "fico", "fico score", "vantage score", "credit limit", "credit utilization",
    "delinquency", "late payment", "missed payment", "defaulted loan",
    "charge-off", "collections", "bankruptcy", "insolvency", "debt balance",
    "outstanding debt", "repayment history", "arrears", "past due",
    "days past due", "dpd", "non performing loan", "npl", "risk grade",
    "risk band", "affordability check", "debt to income", "dti ratio",
    "credit decision", "credit approval", "credit denial", "adverse action",
    "scorecard", "borrower score", "borrower profile", "credit profile",
    "payment behavior", "thin file", "credit freeze", "fraud alert",
    "probability of default", "pd", "lgd", "ead", "kredit skoru",
    "kredit hesabati", "kredit tarixcesi", "borc qaligi",
)

INVOICE_BILLING_TRANSACTION_KEYWORDS = (
    "invoice", "billing", "bill", "billing account", "invoice number",
    "invoice id", "billing statement", "statement", "transaction log",
    "transaction history", "payment log", "receipt", "merchant", "order id",
    "customer invoice", "client billing", "investment account", "brokerage account",
    "trading account", "securities account", "portfolio account", "custody account",
    "wealth account", "investment profile", "investor profile", "investor id",
    "brokerage id", "portfolio id", "portfolio holdings", "securities holdings",
    "stock holdings", "bond holdings", "crypto holdings", "asset allocation",
    "trading history", "order history", "trade confirmation", "execution report",
    "settlement instruction", "brokerage statement", "portfolio statement",
    "portfolio valuation", "capital gains", "dividend income", "realized gain",
    "unrealized gain", "pnl", "margin account", "margin call", "buying power",
    "collateral account", "restricted securities", "insider account",
    "faktura", "hesab faktura", "odenis hesabi", "tranzaksiya tarixcesi",
    "investisiya hesabi", "broker hesabi", "portfel",
)

PRERELEASE_FINANCIAL_KEYWORDS = (
    "pre-release financial statement", "pre release financial statement",
    "draft financial statement", "unreleased financial statement",
    "nonpublic financial statement", "internal financial statement",
    "financial statement", "balance sheet", "income statement", "profit and loss",
    "p&l", "cash flow statement", "trial balance", "general ledger",
    "management accounts", "monthly close", "quarterly close", "year end close",
    "financial results", "earnings", "revenue", "profit", "loss", "ebitda",
    "gross profit", "net income", "audit draft", "audit adjustment",
    "consolidation", "financial disclosure", "board pack", "earnings release",
    "preliminary results", "material nonpublic", "mnpi", "maliyye hesabatı",
    "daxili maliyye hesabatı", "ictimai olmayan maliyye",
)

PRICING_MARGIN_FORECAST_KEYWORDS = (
    "pricing", "pricing data", "price list", "price sheet", "price book",
    "rate card", "discount", "discount rate", "rebate", "quote", "quotation",
    "quoted price", "bid price", "tender price", "contract price",
    "negotiated price", "special price", "floor price", "target price",
    "minimum price", "maximum discount", "gross margin", "net margin",
    "profit margin", "margin analysis", "markup", "cost price", "unit cost",
    "cogs", "transfer price", "price elasticity", "revenue forecast",
    "sales forecast", "financial forecast", "budget", "budget model",
    "operating plan", "annual operating plan", "aop", "business plan",
    "strategic plan", "scenario analysis", "sensitivity analysis",
    "variance analysis", "run rate", "target revenue", "quota", "sales target",
    "territory plan", "sales plan", "pipeline plan", "competitive pricing",
    "competitor price", "confidential pricing", "internal pricing",
    "customer pricing", "partner pricing", "deal pricing", "bid model",
    "commercial model", "profitability analysis", "cost model", "cost forecast",
    "capex budget", "opex budget", "headcount budget", "financial model",
    "board forecast", "executive forecast", "nonpublic forecast",
    "qiymet", "endirim", "marja", "gelir proqnozu", "budce", "maliyye modeli",
)

PASSWORD_SECRET_KEYWORDS = (
    "password", "passwords", "password data", "passwd", "pwd", "passcode",
    "passphrase", "user password", "login password", "portal password",
    "application password", "admin password", "root password",
    "privileged password", "database password", "db password", "mysql password",
    "postgres password", "ldap password", "ad password", "domain password",
    "service account password", "smtp password", "email password",
    "ftp password", "sftp password", "ssh password", "vpn password",
    "wifi password", "router password", "keystore password",
    "truststore password", "backup password", "encryption password",
    "decryption password", "temporary password", "default password",
    "generated password", "new password", "current password",
    "password reset", "password recovery", "password hash", "hashed password",
    "credential hash", "ntlm hash", "bcrypt", "argon2", "pbkdf2", "scrypt",
    "password salt", "shadow file", "/etc/shadow", "htpasswd",
    "basic auth password", "pam password", "vault password", "sifre", "parol",
)

API_TOKEN_SECRET_KEYWORDS = (
    "api key", "api secret", "api token", "access token", "auth token",
    "bearer token", "personal access token", "pat", "oauth token",
    "oauth secret", "oauth client secret", "client secret", "refresh token",
    "id token", "jwt", "session token", "csrf token", "webhook secret",
    "signing secret", "shared secret", "integration secret", "service token",
    "bot token", "slack token", "github token", "gitlab token", "npm token",
    "aws access key", "aws secret key", "azure key", "google api key",
    "sendgrid key", "twilio token", "datadog api key", "sentry dsn",
    "stripe secret key", "stripe api key", "openai api key", "secret key",
    "token secret", "api acari", "giris tokeni", "oauth sirri",
)

PRIVATE_KEY_CERT_KEYWORDS = (
    "private key", "secret key", "cryptographic key", "ssh private key",
    "rsa private key", "dsa private key", "ec private key", "ed25519 private key",
    "pgp private key", "pem key", "key file", "identity file", "key pair",
    "key material", "ssh config", "ssh credential", "tls key", "ssl key",
    "ssl private key", "tls private key", "certificate", "x509 certificate",
    "ssl certificate", "tls certificate", "client certificate",
    "server certificate", "root certificate", "ca certificate",
    "certificate authority", "cert chain", "certificate bundle", "pfx", "p12",
    "pkcs12", "jks", "keystore", "truststore", "certificate password",
    "csr", "certificate signing request", "mutual tls", "mtls",
    "code signing certificate", "code signing key", "saml private key",
    "jwt signing key", "hmac secret", "symmetric key", "certificate private key",
    "begin private key", "begin rsa private key", "begin openssh private key",
    "id_rsa", "id_ed25519", "privkey.pem", "server.key", "client.key",
    "ozel acar", "sexsi acar", "sertifikat", "ssh acari",
)

DATABASE_CONNECTION_KEYWORDS = (
    "connection string", "database connection string", "db connection string",
    "jdbc connection", "jdbc url", "odbc connection", "dsn", "datasource",
    "database url", "database uri", "db url", "db uri", "connection uri",
    "postgres connection", "postgresql connection", "mysql connection",
    "mssql connection", "sql server connection", "oracle connection",
    "mongodb uri", "mongo uri", "redis url", "elasticsearch url",
    "cassandra connection", "snowflake connection", "bigquery connection",
    "server=", "user id=", "uid=", "pwd=", "password=", "host=", "port=",
    "database=", "initial catalog", "integrated security", "trustservercertificate",
    "veritabani baglanti", "db baglanti", "connectionstring",
)

ENCRYPTION_KEY_MATERIAL_KEYWORDS = (
    "encryption key", "decryption key", "crypto key", "cryptographic key",
    "secret key", "symmetric key", "aes key", "des key", "rsa key",
    "hmac key", "hmac secret", "signing key", "verification key",
    "master key", "data encryption key", "dek", "key encryption key", "kek",
    "kms key", "cmk", "customer managed key", "key material",
    "raw key", "base64 key", "key value", "key bytes", "key id",
    "key version", "key rotation", "key vault", "keyring", "nonce",
    "iv", "initialization vector", "salt key", "pepper", "fernet key",
    "age key", "gpg key", "pgp key", "sifreleme acari", "acar materiali",
)

SESSION_TOKEN_JWT_KEYWORDS = (
    "session token", "session id", "session cookie", "auth session",
    "login session", "jwt", "json web token", "id token", "access token",
    "refresh token", "bearer token", "csrf token", "xsrf token",
    "remember me token", "sso token", "saml token", "opaque token",
    "state token", "nonce token", "cookie token", "authorization bearer",
    "sid", "jti", "token id", "session secret", "sessiya tokeni",
    "jwt token", "giris sessiyasi",
)

MFA_RECOVERY_KEYWORDS = (
    "mfa seed", "mfa secret", "mfa recovery code", "mfa backup code",
    "mfa bypass code", "2fa seed", "2fa secret", "2fa recovery code",
    "totp seed", "totp secret", "hotp secret", "authenticator secret",
    "authenticator seed", "otp seed", "otp secret", "one time password",
    "recovery code", "backup code", "scratch code", "emergency code",
    "webauthn recovery", "fido recovery", "u2f recovery", "mfa reset code",
    "mfa enrollment secret", "qr secret", "otpauth", "mfa toxumu",
    "berpa kodu", "ehtiyat kod",
)

HR_EMPLOYEE_FILE_KEYWORDS = (
    "hr file", "human resources file", "employee file", "personnel file",
    "employee record", "hr record", "performance review", "performance appraisal",
    "review score", "manager feedback", "disciplinary action", "discipline",
    "warning letter", "grievance", "complaint", "employee complaint",
    "misconduct", "investigation", "workplace investigation", "termination",
    "dismissal", "resignation", "probation", "promotion", "demotion",
    "performance improvement plan", "pip", "employee evaluation", "talent review",
    "succession plan", "employee relation", "hr case", "hr note",
    "attendance record", "absence record", "leave record", "hr fayli",
    "isci fayli", "emekdas fayli", "intizam", "sikayet", "performans qiymetlendirme",
)

BENEFITS_INSURANCE_KEYWORDS = (
    "benefits", "benefit data", "employee benefits", "benefit enrollment",
    "insurance enrollment", "health insurance enrollment", "medical insurance",
    "life insurance", "dental insurance", "vision insurance", "beneficiary",
    "dependent", "dependent coverage", "spouse coverage", "family coverage",
    "pension", "retirement plan", "401k", "provident fund", "social insurance",
    "benefit election", "open enrollment", "enrollment form", "claim enrollment",
    "insurance policy", "policy number", "coverage", "premium", "deduction",
    "benefit allowance", "leave benefit", "sick leave", "maternity leave",
    "parental leave", "unemployment insurance", "workers compensation",
    "isci faydalari", "sigorta qeydiyyati", "pensiya", "fayda paketi",
)

BACKGROUND_DRUG_TEST_KEYWORDS = (
    "background check", "background screening", "employment screening",
    "pre employment screening", "criminal background", "police clearance",
    "reference check", "education verification", "employment verification",
    "right to work check", "identity verification", "sanctions screening",
    "watchlist screening", "drug test", "drug screening", "toxicology",
    "urine drug screen", "alcohol test", "breathalyzer", "substance test",
    "medical screening", "fitness for duty", "occupational health check",
    "credit check", "screening result", "screening status", "adverse finding",
    "clearance result", "background report", "dbs check", "good conduct",
    "drug test result", "narkotik test", "yoxlama neticesi", "polis arayisi",
)

TIMESHEET_ATTENDANCE_KEYWORDS = (
    "timesheet", "time sheet", "timecard", "time card", "attendance",
    "attendance record", "attendance log", "clock in", "clock out",
    "punch in", "punch out", "work hours", "hours worked", "shift",
    "shift schedule", "roster", "overtime hours", "late arrival",
    "early leave", "absence", "absenteeism", "leave record", "vacation",
    "sick leave", "pto", "time off", "remote work day", "work location",
    "employee schedule", "badge swipe", "entry log", "exit log",
    "attendance exception", "time approval", "time entry", "isci vaxti",
    "davamiyyet", "is saatlari", "novbe cedveli",
)

ORG_CHART_DIRECTORY_KEYWORDS = (
    "org chart", "organization chart", "organisation chart",
    "organizational chart", "employee directory", "staff directory",
    "corporate directory", "internal directory", "team directory",
    "reporting line", "manager", "line manager", "direct report",
    "supervisor", "department", "business unit", "job title", "role",
    "position", "employee profile", "work email", "work phone",
    "office location", "desk location", "cost center", "employee hierarchy",
    "headcount", "org unit", "organizational unit", "rehber", "struktur",
    "isci siyahisi", "emekdas kataloqu", "tabe olan",
)

TERMINATION_LAYOFF_KEYWORDS = (
    "termination", "employee termination", "termination data",
    "termination plan", "termination date", "termination reason",
    "layoff", "layoff plan", "redundancy", "redundancy plan",
    "dismissal", "separation", "separation agreement", "exit plan",
    "exit interview", "offboarding", "notice period", "severance",
    "severance package", "final pay", "garden leave", "non renewal",
    "contract end", "resignation", "involuntary termination",
    "voluntary termination", "reduction in force", "rif", "workforce reduction",
    "restructuring", "headcount reduction", "role elimination",
    "termination list", "layoff list", "impacted employee", "isden cixarma",
    "ixtisar", "xitam", "son is gunu",
)

SOURCE_CODE_ALGORITHM_KEYWORDS = (
    "source code", "source-code", "codebase", "repository", "repo",
    "algorithm", "algorithms", "proprietary algorithm", "model algorithm",
    "ranking algorithm", "matching algorithm", "source file", "function",
    "class", "method", "module", "library", "sdk", "api implementation",
    "backend code", "frontend code", "database schema", "stored procedure",
    "pseudocode", "technical design", "architecture code", "git repository",
    "commit", "pull request", "branch", "source map", "compiled artifact",
    "kod bazasi", "menbe kod", "alqoritm",
)

TRADE_SECRET_DESIGN_KEYWORDS = (
    "trade secret", "confidential know-how", "know how", "formula",
    "secret formula", "recipe", "process design", "manufacturing process",
    "product design", "industrial design", "prototype", "r&d", "research and development",
    "design document", "technical drawing", "blueprint", "cad file",
    "schematic", "bill of materials", "bom", "material specification",
    "supplier specification", "process parameter", "quality specification",
    "lab notebook", "experiment result", "invention disclosure", "competitive advantage",
    "commercial secret", "business secret", "kommersiya sirri", "formula", "dizayn",
)

PATENT_PENDING_KEYWORDS = (
    "patent pending", "pending patent", "unfiled patent", "patent application",
    "provisional patent", "invention disclosure", "patent draft",
    "patent filing", "patent claim", "claim chart", "prior art",
    "novelty search", "freedom to operate", "fto", "office action",
    "inventor", "invention", "patentability", "unpublished patent",
    "confidential invention", "ip disclosure", "intellectual property disclosure",
    "patent portfolio", "filing strategy", "patent family", "patent counsel",
    "patent agent", "patent attorney", "patentli", "ixtira", "patent muracieti",
)

MA_DUE_DILIGENCE_KEYWORDS = (
    "m&a", "mergers and acquisitions", "merger", "acquisition", "divestiture",
    "due diligence", "data room", "virtual data room", "vdr", "target company",
    "buyer", "seller", "term sheet", "letter of intent", "loi", "nda",
    "purchase agreement", "spa", "asset purchase agreement", "share purchase agreement",
    "valuation", "enterprise value", "ev", "ebitda multiple", "synergy",
    "integration plan", "deal pipeline", "deal memo", "investment memo",
    "confidential information memorandum", "cim", "quality of earnings", "qoe",
    "cap table", "ownership", "shareholder", "board approval", "regulatory approval",
    "due diligence request", "diligence finding", "merger control", "ma", "birlesme",
    "satin alma", "due diligence",
)

BOARD_MATERIALS_KEYWORDS = (
    "board materials", "board pack", "board package", "board deck",
    "board presentation", "board report", "board paper", "board memo",
    "board agenda", "board minutes", "meeting minutes", "minutes of meeting",
    "committee minutes", "board resolution", "written resolution",
    "board consent", "board approval", "board decision", "board vote",
    "board of directors", "audit committee", "risk committee",
    "governance committee", "company secretary", "corporate governance",
    "reserved matters", "delegation of authority", "approval matrix",
    "board action items", "director consent", "unanimous consent",
    "board confidential", "privileged board materials", "idare heyeti",
    "direktorlar surasi", "iclas protokolu", "idare heyeti protokolu",
)

STRATEGY_ROADMAP_PLAN_KEYWORDS = (
    "strategy", "strategic plan", "business strategy", "corporate strategy",
    "product strategy", "go to market strategy", "roadmap", "product roadmap",
    "technology roadmap", "platform roadmap", "strategic roadmap",
    "operating plan", "annual operating plan", "aop", "business plan",
    "long range plan", "three year plan", "five year plan", "okr",
    "strategic initiative", "growth plan", "market expansion",
    "launch plan", "transformation plan", "integration plan",
    "competitive strategy", "strategiya", "yol xeritesi", "inkisaf plani",
)

CONTRACT_NDA_LEGAL_KEYWORDS = (
    "contract", "agreement", "master services agreement", "msa",
    "statement of work", "sow", "service level agreement", "sla",
    "non disclosure agreement", "nda", "confidentiality agreement",
    "legal agreement", "legal contract", "terms and conditions",
    "contract clause", "indemnity", "limitation of liability",
    "termination clause", "governing law", "jurisdiction",
    "data processing agreement", "dpa", "legal review", "redline",
    "contract draft", "signed agreement", "muqavile", "sazis", "huquqi",
)

LITIGATION_PRIVILEGED_LEGAL_KEYWORDS = (
    "litigation", "lawsuit", "legal dispute", "claim", "complaint",
    "court filing", "court order", "subpoena", "deposition",
    "arbitration", "mediation", "settlement", "legal hold",
    "privileged", "attorney client privilege", "legal privilege",
    "work product", "outside counsel", "general counsel",
    "legal memo", "case strategy", "matter number", "discovery request",
    "evidence", "witness", "mehkeme", "iddia", "huquqi imtiyaz",
)

VENDOR_SUPPLIER_TERMS_KEYWORDS = (
    "vendor terms", "supplier terms", "vendor agreement", "supplier agreement",
    "procurement terms", "purchase order", "po terms", "supplier contract",
    "vendor contract", "master supplier agreement", "supply agreement",
    "supplier pricing", "vendor pricing", "rebate", "volume discount",
    "payment terms", "delivery terms", "service level", "sla",
    "supplier onboarding", "vendor risk", "third party risk",
    "preferred supplier", "approved vendor", "vendor scorecard",
    "supplier scorecard", "procurement", "techizatci", "tedarukcu",
)

NETWORK_ARCHITECTURE_KEYWORDS = (
    "network diagram", "network map", "network topology", "topology diagram",
    "infrastructure diagram", "architecture diagram", "system architecture",
    "technical architecture", "security architecture", "network architecture",
    "cloud architecture", "aws architecture", "azure architecture", "gcp architecture",
    "vpc diagram", "vnet diagram", "subnet diagram", "ip plan", "cidr plan",
    "firewall topology", "dmz architecture", "zero trust architecture",
    "ztna architecture", "vpn topology", "data flow diagram", "dfd",
    "traffic flow", "routing diagram", "vlan diagram", "hld", "lld",
    "kubernetes architecture", "service mesh architecture", "api gateway architecture",
    "siem architecture", "soc architecture", "ot architecture", "ics architecture",
    "scada architecture", "sebeke diaqrami", "sebeke topologiyasi",
    "arxitektura diaqrami", "sistem arxitekturasi",
)

VULNERABILITY_PENTEST_KEYWORDS = (
    "vulnerability scan", "vulnerability report", "vulnerability assessment",
    "vulnerability finding", "vulnerability list", "vulnerability register",
    "pentest report", "penetration test", "penetration testing",
    "security assessment", "security finding", "weakness", "exploit",
    "cve", "cvss", "critical vulnerability", "high vulnerability",
    "attack surface", "easm report", "exposure", "proof of concept",
    "poc", "remediation", "risk rating", "severity", "finding owner",
    "nessus", "qualys", "rapid7", "burp", "nuclei", "zaafliq",
    "tehlukesizlik qiymetlendirmesi",
)

SECURITY_CONFIG_FIREWALL_KEYWORDS = (
    "security config", "security configuration", "hardening", "baseline configuration",
    "firewall rule", "firewall rules", "firewall policy", "firewall configuration",
    "acl", "access control list", "network acl", "nacl", "security group",
    "nsg", "cloud firewall rule", "allow rule", "deny rule", "permit rule",
    "block rule", "ingress rule", "egress rule", "nat rule", "waf rule",
    "iptables", "ufw", "windows firewall", "cisco asa", "palo alto",
    "fortigate", "checkpoint", "aws security group", "azure nsg",
    "gcp firewall", "hardening baseline", "cis benchmark", "firewall qaydalari",
    "tehlukesizlik konfiqurasiyasi",
)

INCIDENT_ACCESS_AUDIT_LOG_KEYWORDS = (
    "incident report", "security incident report", "incident record",
    "incident ticket", "incident case", "incident timeline", "incident summary",
    "post incident report", "postmortem", "root cause analysis", "rca",
    "lessons learned", "security event", "security incident", "cyber incident",
    "data breach", "privacy breach", "security breach", "unauthorized access",
    "suspicious login", "indicators of compromise", "ioc", "threat actor",
    "forensic report", "incident response", "dfir", "evidence log",
    "chain of custody", "affected systems", "affected users", "exfiltration",
    "authentication logs", "login logs", "access logs", "audit logs",
    "event logs", "cloudtrail logs", "m365 audit logs", "edr telemetry",
    "insident hesabat", "tehlukesizlik insidenti", "giris loglari",
)

DISASTER_RECOVERY_BCP_KEYWORDS = (
    "disaster recovery", "dr plan", "drp", "business continuity",
    "bcp", "bcm", "business continuity plan", "continuity plan",
    "continuity strategy", "operational resilience", "cyber resilience",
    "crisis management", "crisis plan", "recovery plan", "failover plan",
    "backup plan", "restore plan", "rto", "rpo", "recovery time objective",
    "recovery point objective", "runbook", "dr test", "tabletop exercise",
    "continuity exercise", "alternate site", "hot site", "cold site",
    "disaster recovery site", "fovqelade berpa", "biznes davamlılığı",
)

PHYSICAL_SECURITY_BADGE_CCTV_KEYWORDS = (
    "physical security", "physical access", "facility security",
    "site security", "building security", "office security", "badge",
    "access badge", "badge id", "badge record", "badge log",
    "access card", "key card", "smart card", "rfid card", "door access",
    "access control system", "acs", "cctv", "camera", "surveillance",
    "video footage", "floor plan", "building floor plan", "site plan",
    "visitor log", "entry log", "exit log", "turnstile", "security guard",
    "server room access", "data center access", "fiziki tehlukesizlik",
    "giris karti", "kamera goruntusu",
)


NAME_KEYWORDS = _dedupe_keywords(NAME_KEYWORDS, RAW_NAME_KEYWORDS)
EMAIL_KEYWORDS = _dedupe_keywords(EMAIL_KEYWORDS, RAW_EMAIL_KEYWORDS)
PHONE_KEYWORDS = _dedupe_keywords(PHONE_KEYWORDS, RAW_PHONE_KEYWORDS)
ADDRESS_KEYWORDS = _dedupe_keywords(ADDRESS_KEYWORDS, RAW_ADDRESS_KEYWORDS)
BIRTH_KEYWORDS = _dedupe_keywords(BIRTH_KEYWORDS, RAW_BIRTH_KEYWORDS)
GOVERNMENT_ID_KEYWORDS = _dedupe_keywords(GOVERNMENT_ID_KEYWORDS, RAW_GOVERNMENT_ID_KEYWORDS)
SIGNATURE_KEYWORDS = _dedupe_keywords(SIGNATURE_KEYWORDS, RAW_SIGNATURE_KEYWORDS)
PHOTO_FACE_KEYWORDS = _dedupe_keywords(PHOTO_FACE_KEYWORDS, RAW_PHOTO_FACE_KEYWORDS)
VEHICLE_KEYWORDS = _dedupe_keywords(VEHICLE_KEYWORDS, RAW_VEHICLE_KEYWORDS)
ACCOUNT_RECOVERY_KEYWORDS = _dedupe_keywords(ACCOUNT_RECOVERY_KEYWORDS, RAW_ACCOUNT_RECOVERY_KEYWORDS)
EMERGENCY_CONTACT_KEYWORDS = _dedupe_keywords(EMERGENCY_CONTACT_KEYWORDS, RAW_EMERGENCY_CONTACT_KEYWORDS)
IP_IDENTIFIER_KEYWORDS = _dedupe_keywords(IP_IDENTIFIER_KEYWORDS, RAW_IP_IDENTIFIER_KEYWORDS)
COOKIE_DEVICE_ID_KEYWORDS = _dedupe_keywords(COOKIE_DEVICE_ID_KEYWORDS, RAW_COOKIE_DEVICE_ID_KEYWORDS)
DEVICE_HARDWARE_KEYWORDS = _dedupe_keywords(DEVICE_HARDWARE_KEYWORDS, RAW_DEVICE_HARDWARE_KEYWORDS)
GEOLOCATION_KEYWORDS = _dedupe_keywords(GEOLOCATION_KEYWORDS, RAW_GEOLOCATION_KEYWORDS)
BROWSING_HISTORY_KEYWORDS = _dedupe_keywords(BROWSING_HISTORY_KEYWORDS, RAW_BROWSING_HISTORY_KEYWORDS)
ACCOUNT_USERNAME_KEYWORDS = _dedupe_keywords(ACCOUNT_USERNAME_KEYWORDS, RAW_ACCOUNT_USERNAME_KEYWORDS)
HEALTH_MEDICAL_KEYWORDS = _dedupe_keywords(HEALTH_MEDICAL_KEYWORDS, RAW_HEALTH_MEDICAL_KEYWORDS)
MENTAL_HEALTH_KEYWORDS = _dedupe_keywords(MENTAL_HEALTH_KEYWORDS, RAW_MENTAL_HEALTH_KEYWORDS)
DISABILITY_STATUS_KEYWORDS = _dedupe_keywords(DISABILITY_STATUS_KEYWORDS, RAW_DISABILITY_STATUS_KEYWORDS)
BIOMETRIC_SPECIAL_KEYWORDS = _dedupe_keywords(BIOMETRIC_SPECIAL_KEYWORDS, RAW_BIOMETRIC_SPECIAL_KEYWORDS)
GENETIC_DNA_KEYWORDS = _dedupe_keywords(GENETIC_DNA_KEYWORDS, RAW_GENETIC_DNA_KEYWORDS)
RACE_ETHNICITY_KEYWORDS = _dedupe_keywords(RACE_ETHNICITY_KEYWORDS, RAW_RACE_ETHNICITY_KEYWORDS)
RELIGIOUS_BELIEF_KEYWORDS = _dedupe_keywords(RELIGIOUS_BELIEF_KEYWORDS, RAW_RELIGIOUS_BELIEF_KEYWORDS)
POLITICAL_AFFILIATION_KEYWORDS = _dedupe_keywords(POLITICAL_AFFILIATION_KEYWORDS, RAW_POLITICAL_AFFILIATION_KEYWORDS)
SEXUAL_ORIENTATION_KEYWORDS = _dedupe_keywords(SEXUAL_ORIENTATION_KEYWORDS, RAW_SEXUAL_ORIENTATION_KEYWORDS)
TRADE_UNION_KEYWORDS = _dedupe_keywords(TRADE_UNION_KEYWORDS, RAW_TRADE_UNION_KEYWORDS)
IMMIGRATION_CITIZENSHIP_KEYWORDS = _dedupe_keywords(IMMIGRATION_CITIZENSHIP_KEYWORDS, RAW_IMMIGRATION_CITIZENSHIP_KEYWORDS)
CRIMINAL_RECORD_KEYWORDS = _dedupe_keywords(CRIMINAL_RECORD_KEYWORDS, RAW_CRIMINAL_RECORD_KEYWORDS)
PAYMENT_CARD_KEYWORDS = _dedupe_keywords(PAYMENT_CARD_KEYWORDS, RAW_PAYMENT_CARD_KEYWORDS)
BANK_ACCOUNT_KEYWORDS = _dedupe_keywords(BANK_ACCOUNT_KEYWORDS, RAW_BANK_ACCOUNT_KEYWORDS)
TAX_RECORD_KEYWORDS = _dedupe_keywords(TAX_RECORD_KEYWORDS, RAW_TAX_RECORD_KEYWORDS)
SALARY_COMPENSATION_KEYWORDS = _dedupe_keywords(SALARY_COMPENSATION_KEYWORDS, RAW_SALARY_COMPENSATION_KEYWORDS)
CREDIT_SCORE_REPORT_KEYWORDS = _dedupe_keywords(CREDIT_SCORE_REPORT_KEYWORDS, RAW_CREDIT_SCORE_REPORT_KEYWORDS)
INVOICE_BILLING_TRANSACTION_KEYWORDS = _dedupe_keywords(INVOICE_BILLING_TRANSACTION_KEYWORDS, RAW_INVOICE_BILLING_TRANSACTION_KEYWORDS)
PRERELEASE_FINANCIAL_KEYWORDS = _dedupe_keywords(PRERELEASE_FINANCIAL_KEYWORDS, RAW_PRERELEASE_FINANCIAL_KEYWORDS)
PRICING_MARGIN_FORECAST_KEYWORDS = _dedupe_keywords(PRICING_MARGIN_FORECAST_KEYWORDS, RAW_PRICING_MARGIN_FORECAST_KEYWORDS)
PASSWORD_SECRET_KEYWORDS = _dedupe_keywords(PASSWORD_SECRET_KEYWORDS, RAW_PASSWORD_SECRET_KEYWORDS)
API_TOKEN_SECRET_KEYWORDS = _dedupe_keywords(API_TOKEN_SECRET_KEYWORDS, RAW_API_TOKEN_SECRET_KEYWORDS)
PRIVATE_KEY_CERT_KEYWORDS = _dedupe_keywords(PRIVATE_KEY_CERT_KEYWORDS, RAW_PRIVATE_KEY_CERT_KEYWORDS)
DATABASE_CONNECTION_KEYWORDS = _dedupe_keywords(DATABASE_CONNECTION_KEYWORDS, RAW_DATABASE_CONNECTION_KEYWORDS)
ENCRYPTION_KEY_MATERIAL_KEYWORDS = _dedupe_keywords(ENCRYPTION_KEY_MATERIAL_KEYWORDS, RAW_ENCRYPTION_KEY_MATERIAL_KEYWORDS)
SESSION_TOKEN_JWT_KEYWORDS = _dedupe_keywords(SESSION_TOKEN_JWT_KEYWORDS, RAW_SESSION_TOKEN_JWT_KEYWORDS)
MFA_RECOVERY_KEYWORDS = _dedupe_keywords(MFA_RECOVERY_KEYWORDS, RAW_MFA_RECOVERY_KEYWORDS)
HR_EMPLOYEE_FILE_KEYWORDS = _dedupe_keywords(HR_EMPLOYEE_FILE_KEYWORDS, RAW_HR_EMPLOYEE_FILE_KEYWORDS)
BENEFITS_INSURANCE_KEYWORDS = _dedupe_keywords(BENEFITS_INSURANCE_KEYWORDS, RAW_BENEFITS_INSURANCE_KEYWORDS)
BACKGROUND_DRUG_TEST_KEYWORDS = _dedupe_keywords(BACKGROUND_DRUG_TEST_KEYWORDS, RAW_BACKGROUND_DRUG_TEST_KEYWORDS)
TIMESHEET_ATTENDANCE_KEYWORDS = _dedupe_keywords(TIMESHEET_ATTENDANCE_KEYWORDS, RAW_TIMESHEET_ATTENDANCE_KEYWORDS)
ORG_CHART_DIRECTORY_KEYWORDS = _dedupe_keywords(ORG_CHART_DIRECTORY_KEYWORDS, RAW_ORG_CHART_DIRECTORY_KEYWORDS)
TERMINATION_LAYOFF_KEYWORDS = _dedupe_keywords(TERMINATION_LAYOFF_KEYWORDS, RAW_TERMINATION_LAYOFF_KEYWORDS)
SOURCE_CODE_ALGORITHM_KEYWORDS = _dedupe_keywords(SOURCE_CODE_ALGORITHM_KEYWORDS, RAW_SOURCE_CODE_ALGORITHM_KEYWORDS)
TRADE_SECRET_DESIGN_KEYWORDS = _dedupe_keywords(TRADE_SECRET_DESIGN_KEYWORDS, RAW_TRADE_SECRET_DESIGN_KEYWORDS)
PATENT_PENDING_KEYWORDS = _dedupe_keywords(PATENT_PENDING_KEYWORDS, RAW_PATENT_PENDING_KEYWORDS)
MA_DUE_DILIGENCE_KEYWORDS = _dedupe_keywords(MA_DUE_DILIGENCE_KEYWORDS, RAW_MA_DUE_DILIGENCE_KEYWORDS)
BOARD_MATERIALS_KEYWORDS = _dedupe_keywords(BOARD_MATERIALS_KEYWORDS, RAW_BOARD_MATERIALS_KEYWORDS)
STRATEGY_ROADMAP_PLAN_KEYWORDS = _dedupe_keywords(STRATEGY_ROADMAP_PLAN_KEYWORDS, RAW_STRATEGY_ROADMAP_PLAN_KEYWORDS)
CONTRACT_NDA_LEGAL_KEYWORDS = _dedupe_keywords(CONTRACT_NDA_LEGAL_KEYWORDS, RAW_CONTRACT_NDA_LEGAL_KEYWORDS)
LITIGATION_PRIVILEGED_LEGAL_KEYWORDS = _dedupe_keywords(LITIGATION_PRIVILEGED_LEGAL_KEYWORDS, RAW_LITIGATION_PRIVILEGED_LEGAL_KEYWORDS)
VENDOR_SUPPLIER_TERMS_KEYWORDS = _dedupe_keywords(VENDOR_SUPPLIER_TERMS_KEYWORDS, RAW_VENDOR_SUPPLIER_TERMS_KEYWORDS)
NETWORK_ARCHITECTURE_KEYWORDS = _dedupe_keywords(NETWORK_ARCHITECTURE_KEYWORDS, RAW_NETWORK_ARCHITECTURE_KEYWORDS)
VULNERABILITY_PENTEST_KEYWORDS = _dedupe_keywords(VULNERABILITY_PENTEST_KEYWORDS, RAW_VULNERABILITY_PENTEST_KEYWORDS)
SECURITY_CONFIG_FIREWALL_KEYWORDS = _dedupe_keywords(SECURITY_CONFIG_FIREWALL_KEYWORDS, RAW_SECURITY_CONFIG_FIREWALL_KEYWORDS)
INCIDENT_ACCESS_AUDIT_LOG_KEYWORDS = _dedupe_keywords(INCIDENT_ACCESS_AUDIT_LOG_KEYWORDS, RAW_INCIDENT_ACCESS_AUDIT_LOG_KEYWORDS)
DISASTER_RECOVERY_BCP_KEYWORDS = _dedupe_keywords(DISASTER_RECOVERY_BCP_KEYWORDS, RAW_DISASTER_RECOVERY_BCP_KEYWORDS)
PHYSICAL_SECURITY_BADGE_CCTV_KEYWORDS = _dedupe_keywords(PHYSICAL_SECURITY_BADGE_CCTV_KEYWORDS, RAW_PHYSICAL_SECURITY_BADGE_CCTV_KEYWORDS)
