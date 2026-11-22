# 🛡️ BACHAO+ | Defence & Security Platform

> **Tagline:** *Your Safety. Our Priority.*  
> **Category:** Defence & Security (Hackathon MVP)  
> **Interface Aesthetic:** Sophisticated Warm Ivory & Porcelain palette (`#F9F6F0`) with navy typography (`#0F172A`) and subtle tactical green/red defensive status indicators.

---

## 📌 Problem Statement & Overview

In high-density campus environments and distributed organizational infrastructure, security threats occur across physical and digital vectors simultaneously:
- **Physical Incidents:** Students and personnel face harassment, medical crises, and safety hazards, yet conventional reporting channels are fragmented and slow.
- **Cyber Phishing:** Attackers prey on students and faculty with spoofed university portals, deceptive SMS notices, and credential-harvesting pages.
- **Credential Vulnerability:** Weak, predictable, and historically breached passwords remain the primary entry vector for institutional network intrusions.

**BACHAO+** is a unified, defensive mission platform that bridges physical campus overwatch with digital asset hardening. Engineered in pure Python, Streamlit, and SQLite, BACHAO+ delivers zero-trust access control, privacy-first breach verification via k-anonymity, explainable phishing heuristics, and real-time incident dispatch without external infrastructure dependencies.

---

## 🗂️ Project Architecture

```text
Bachao+/
├── app.py                      # Mission Command Shell, routing, telemetry charts & theme
├── requirements.txt            # Python dependencies (Streamlit, Plotly, Requests, etc.)
├── README.md                   # Platform documentation and operation guide
├── Procfile                    # Deployment command for web platforms
├── .gitignore                  # Git exclusion rules (venv, secrets, cache, SQLite DBs)
├── .env.example                # Template for administrative environment variables
├── .streamlit/
│   └── config.toml             # Streamlit server and warm-cream theme configuration
├── database/
│   └── db.py                   # SQLite engine, parameterized queries, schema & indexes
├── modules/
│   ├── phishing.py             # URL heuristics, social engineering & deception analyzer
│   ├── password_safety.py      # Entropy calculator, HIBP k-Anonymity breach verifier
│   ├── campus_safety.py        # SOS panic trigger, incident triage & officer terminal
│   └── secure_access.py        # PBKDF2 authentication, RBAC, session management & admin setup
├── utils/
│   ├── security.py             # PBKDF2-SHA256, input sanitization, entropy & magic-bytes
│   └── event_logger.py         # Central Security Event Engine writing to SQLite & stream
├── tests/
│   ├── __init__.py             # Test package initialization
│   └── test_bachao.py          # Automated test suite (crypto, heuristics, HIBP, DB)
└── assets/
    └── uploads/                # Directory for incident photographic evidence (.gitkeep)
```

---

## 🚀 Key Functional Modules

### 1. 📊 Central Mission Command Dashboard (`app.py`)
- **Live Platform Metrics:** Displays verified SQLite data (Total Users, URLs Analyzed, High-Risk Threats, Breach Matches, Reported Incidents, Resolved Cases). No fabricated statistics.
- **Interactive Visualizations:**
  - *Threat Level Distribution:* Plotly visualization categorizing phishing risks (Low, Medium, High, Critical).
  - *Incident Lifecycle Distribution:* Plotly donut chart visualizing incident workflow (*Submitted*, *Acknowledged*, *In Progress*, *Resolved*).
- **Security Activity Stream:** Real-time chronological audit trail of all platform events.
- **Interactive Directives:** Clickable navigation buttons that instantly jump to each module.
- **8-Step Demonstration Guide:** Built-in guidance for hackathon judges to verify all workflows quickly.

### 2. 🎣 Phishing & Scam Detection Console (`modules/phishing.py`)
- **Multi-Vector Heuristic Inspection:**
  - Raw IP hostname detection (e.g. `http://192.168.1.1/login.php`).
  - URL shortener identification (`bit.ly`, `tinyurl.com`, `t.co`, etc.).
  - Brand spoofing & deceptive subdomain stacking (e.g. `paypal.com.verify-billing-update.xyz`).
  - Detection of missing HTTPS, high-risk TLDs (`.xyz`, `.top`, `.tk`), and `@` authority tricks.
  - Non-standard consumer ports (`:8080`, `:8888`) and executable download targets (`.exe`, `.apk`, `.iso`).
- **Email & Message Body Analyzer:** Scans raw text for psychological coercion (artificial urgency, fear triggers, greed lures, generic greetings, and credential harvesting).
- **Risk Scoring (0–100):** Categorized into Low (0–25), Medium (26–55), High (56–80), and Critical (81–100).
- **Heuristic Transparency:** Explicitly differentiates heuristic anomaly detection from verified domain blacklist reputation.
- **Defensive Safety Actions:** Actionable mitigation guidance without executing untrusted external code.
- **1-Click Demo Samples:** Load test phishing links, IP links, and fake emails with a single click.

### 3. 🔑 Password Safety & Credential Hardening (`modules/password_safety.py`)
- **Cryptographic Strength Evaluation:** Calculates true Shannon entropy in bits, validates character variety, and enforces defense baselines.
- **Predictable Pattern Detection:** Flags repeated characters (`aaaa`), sequential numbers (`123456`), keyboard walks (`qwerty`), and calendar year patterns.
- **Have I Been Pwned (HIBP) k-Anonymity Integration:**
  - Computes SHA-1 hash locally in memory.
  - Sends only the first **5 hex characters** to `api.pwnedpasswords.com/range/{prefix}`.
  - Compares the returned hash suffixes locally in memory.
  - Plaintext password is **never transmitted or logged**.
  - Gracefully handles offline environments or connectivity drops.
  - Clarifies that breach matches indicate presence in historical third-party leaks, not that the user's specific account was penetrated.
- **High-Entropy Passphrase Generator:** Generates Diceware-style memorable passphrases yielding >70 bits of entropy.

### 4. 🏫 Campus Safety & Perimeter Overwatch (`modules/campus_safety.py`)
- **Emergency SOS Panic Trigger:**
  - High-visibility red distress button for immediate geo-tagged campus dispatch.
  - Statutory Platform Notice: *SOS initiates high-priority alerts within the platform to campus officers; it does not automatically call external municipal police (112).*
- **Role-Based Incident Lifecycle:**
  - Categories: *Medical Emergency, Harassment, Suspicious Activity, Theft, Accident, Other*.
  - Upload photographic evidence (verified by file extension and binary **magic-bytes** header).
  - Automatic unique Incident ID generation (`INC-YYYYMMDD-XXXX` or `SOS-YYYYMMDD-XXXX`).
  - **Student Privacy:** Students can submit and track the status and notes of only their own confidential reports.
  - **Security Officer / Admin Terminal:** Authorized staff filter and review all campus reports, update incident status (*Submitted → Acknowledged → In Progress → Resolved*), and append resolution notes.

### 5. 🔒 Secure Access & Identity Management (`modules/secure_access.py`)
- **Cryptographic Hashing:** PBKDF2-HMAC-SHA256 with 100,000 iterations and unique 16-byte cryptographically random salt. Constant-time verification (`hmac.compare_digest`). Plaintext passwords are never stored.
- **Role-Based Access Control (RBAC):** Supports `Student`, `Campus Security`, and `Admin` tiers.
- **Anti-Role-Escalation:** Self-registration is strictly for `Student`. Registering for `Campus Security` or `Admin` requires a supervisor clearance passcode.
- **Brute-Force Rate Limiting:** Consecutive failed login attempts trigger an automatic 5-minute lockout on the identifier.
- **Initial Administrator Bootstrap:**
  - Configured safely via environment variables (`ADMIN_USERNAME`, `ADMIN_PASSWORD`, `ADMIN_EMAIL`).
  - Safe one-time setup form when no admin user exists in the database.
- **Input Sanitization:** Strips HTML script tags and null bytes. Validates usernames and email patterns.

---

## 🛠️ Installation & Setup

### 1. Prerequisites
- Python 3.9+ (Python 3.11 recommended)
- `pip` package manager

### 2. Clone and Prepare Virtual Environment

**Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**macOS / Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. (Optional) Configure Environment Variables
Copy `.env.example` to `.env` to configure initial admin and clearance keys:
```bash
cp .env.example .env
```

Default demo keys in `.env.example`:
- `SECURITY_CLEARANCE_KEY=your_security_clearance_key`
- `ADMIN_REGISTRATION_KEY=your_admin_registration_key`

---

## 🖥️ Running the Application

Launch the Streamlit mission console:
```bash
streamlit run app.py
```
Open your web browser and navigate to:
```text
http://localhost:8501
```

---

## 🧪 Running Automated Tests

Run the full automated test suite covering PBKDF2 hashing, entropy, phishing heuristics, k-anonymity partitioning, magic-bytes validation, student privacy isolation, brute-force rate-limiting, and the end-to-end hackathon demonstration smoke test:

```bash
python tests/test_bachao.py
```

Expected output:
```text
.............
----------------------------------------------------------------------
Ran 13 tests in 5.521s

OK
```

---

## 🎯 Hackathon Demonstration Workflow (For Judges)

1. **Register as Student**: Open **Secure Access** → Select `New User Registration` → Create student account (e.g. `cadet_sharma`) → Log in.
2. **Scan Suspicious Link**: Go to **Phishing & Scam Detection** → Click *"Brand Spoofing Link"* demo button → Run Analysis. Observe the heuristic breakdown and risk score.
3. **Analyze Social Engineering Text**: Switch to *Email & Message Body Analyzer* → Click *"Load Sample Phishing Email Demo"* → Notice detected urgency and coercion cues.
4. **Audit Password Safely**: Go to **Password Safety** → Click *"Leaked: P@ssword1"* → Run Audit. See the k-anonymity breach count without plaintext transmission.
5. **Submit Incident Report**: Go to **Campus Safety** → Submit an incident report (or trigger Emergency SOS). Check the *My Reported Incidents* tab.
6. **Log in as Campus Security**: Go to **Secure Access** → Log out → Register a new user as `Campus Security` using Clearance Key `your_security_clearance_key` → Log in.
7. **Officer Triage**: Return to **Campus Safety** → Open the *Security Officer Terminal* → Update the incident status from `Submitted` to `In Progress` or `Resolved` with resolution remarks.
8. **Verify Central Telemetry**: Return to the **Dashboard** to see live updated metrics, charts, and the audit stream reflecting all actions.

---

## 🔒 Security Audit & Safeguards

1. **Zero Plaintext Password Exposure:** Passwords tested in the credential auditor operate strictly in memory and are never written to disk, SQLite, or telemetry logs.
2. **k-Anonymity Privacy Guarantee:** The HIBP query transmits only the first 5 characters of the SHA-1 hash. The server cannot determine the user's actual password.
3. **Parameterized SQL Queries:** Every database interaction in `database/db.py` uses parameterized SQL queries (`?`), preventing SQL injection.
4. **Defensive File Validation:** Uploaded evidence is validated for MIME type, file extension, and binary **magic bytes** (JPEG `\xff\xd8\xff`, PNG `\x89PNG\r\n\x1a\n`) to prevent executable file upload attacks.
5. **Anti-Role Escalation:** Users cannot self-assign Security or Admin tiers without valid supervisor clearance keys.
6. **Brute-Force Lockout:** Consecutive failed logins trigger a 5-minute lockout on the targeted identifier.
7. **Student Privacy Protection:** Students are strictly restricted to viewing only their own submitted incident records.

---

## 🌐 Deployment Instructions

BACHAO+ is ready for deployment on **Streamlit Community Cloud**, **Render**, **Railway**, or **Heroku**:

### Deploying on Streamlit Community Cloud:
1. Push repository to GitHub.
2. Connect repository on [share.streamlit.io](https://share.streamlit.io).
3. Set Main file path: `app.py`.
4. Add environment variables from `.env.example` under **Advanced Settings → Secrets**.
5. Deploy.

### Hosting Limitations & Considerations:
- **Ephemeral Filesystems:** In cloud container environments (e.g. free-tier Heroku/Render), SQLite files and local image uploads are reset upon container restarts. For long-term production deployments beyond a hackathon, mount a persistent volume (e.g., Render Disks, AWS EBS) or configure a remote PostgreSQL database.

---

## ⚖️ Known Limitations

1. **Heuristics vs. Real-Time Threat Intelligence:** Phishing detection uses structural heuristics and keyword analysis. It does not actively resolve live domain DNS records or query commercial reputation feeds (VirusTotal) to avoid latency during hackathon presentations.
2. **In-Platform SOS Dispatch:** The Emergency SOS broadcast alerts campus security officers logged into the platform; it does not automatically call municipal emergency services (112/911).

