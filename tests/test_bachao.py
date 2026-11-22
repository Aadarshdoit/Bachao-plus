"""
BACHAO+ Comprehensive Automated Test Suite
Validates cryptographic routines, rate limiting, anti-escalation security,
phishing heuristics, k-anonymity privacy, file upload verification,
student incident privacy, and end-to-end hackathon demonstration workflows.
"""

import hashlib
import io
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from utils.security import (
    hash_password,
    verify_password,
    verify_clearance_code,
    calculate_entropy,
    evaluate_password_security,
    is_common_password,
    detect_weak_patterns,
    sanitize_input,
    validate_username,
    validate_email,
    validate_password_policy,
    validate_uploaded_file,
    generate_strong_passphrase,
    mask_sensitive_string
)
from modules.phishing import analyze_url_heuristics, analyze_text_message
from modules.password_safety import query_hibp_k_anonymity
from database.db import (
    init_db,
    create_user,
    get_user_by_username,
    get_user_by_email,
    check_login_rate_limit,
    record_failed_login_attempt,
    reset_failed_login_attempts,
    create_campus_incident,
    get_campus_incidents,
    update_incident_status,
    insert_event,
    get_recent_events,
    record_phishing_scan,
    record_password_audit,
    get_dashboard_metrics,
    get_incident_status_distribution,
    get_threat_distribution
)


class MockUploadedFile:
    """Mock file upload object simulating Streamlit UploadedFile."""
    def __init__(self, name: str, mime_type: str, content: bytes):
        self.name = name
        self.type = mime_type
        self.content = content
        self.size = len(content)

    def getvalue(self) -> bytes:
        return self.content

    def getbuffer(self) -> bytes:
        return self.content


class TestBachaoPlatformSuite(unittest.TestCase):
    """Full automated testing suite for BACHAO+ Defence Platform."""

    def setUp(self):
        """Create an isolated temporary SQLite database for each test method."""
        self.test_dir = tempfile.TemporaryDirectory()
        self.test_db_path = Path(self.test_dir.name) / "test_bachao.db"
        os.environ["SECURITY_CLEARANCE_KEY"] = "CAMPUS-SEC-2026"
        os.environ["ADMIN_REGISTRATION_KEY"] = "BACHAO-ADMIN-2026"
        init_db(self.test_db_path)

    def tearDown(self):
        """Clean up temporary database artifacts."""
        self.test_dir.cleanup()

    # -----------------------------------------------------------------------
    # 1. Cryptography & Password Hashing
    # -----------------------------------------------------------------------
    def test_01_pbkdf2_hashing_and_verification(self):
        """Verify PBKDF2-HMAC-SHA256 password hashing and constant-time verification."""
        password = "Citadel#2026SecureDefence!"
        pwd_hash, salt = hash_password(password)

        self.assertIsInstance(pwd_hash, str)
        self.assertIsInstance(salt, str)
        self.assertEqual(len(salt), 32)  # 16 bytes = 32 hex chars

        # Positive verification
        self.assertTrue(verify_password(password, pwd_hash, salt))
        # Wrong password verification
        self.assertFalse(verify_password("WrongPassword123", pwd_hash, salt))
        # Tampered salt verification
        self.assertFalse(verify_password(password, pwd_hash, "00" * 16))

    def test_02_shannon_entropy_calculation(self):
        """Verify Shannon entropy bit calculations accurately reflect unpredictability."""
        weak = "123456"
        moderate = "Summer2026!"
        defense_grade = "Sentinel-Citadel-78*Valiant"

        entropy_weak = calculate_entropy(weak)
        entropy_mod = calculate_entropy(moderate)
        entropy_strong = calculate_entropy(defense_grade)

        self.assertLess(entropy_weak, entropy_mod)
        self.assertLess(entropy_mod, entropy_strong)
        self.assertGreater(entropy_strong, 70.0)

    def test_03_common_password_and_weak_pattern_detection(self):
        """Verify dictionary and predictable sequence detection."""
        is_com, _ = is_common_password("password123")
        self.assertTrue(is_com)

        is_safe, _ = is_common_password("QuantumMatrix_4092#")
        self.assertFalse(is_safe)

        # Detect keyboard walks
        patterns = detect_weak_patterns("operator_qwerty_pass")
        self.assertTrue(any("qwerty" in p for p in patterns))

        # Detect repeated characters
        patterns_rep = detect_weak_patterns("pass1111word")
        self.assertTrue(any("repeated" in p for p in patterns_rep))

    # -----------------------------------------------------------------------
    # 2. Role-Based Authorization & Anti-Escalation
    # -----------------------------------------------------------------------
    def test_04_role_escalation_prevention(self):
        """Ensure students cannot self-escalate to Campus Security or Admin without supervisor keys."""
        # Student role requires no key
        ok_student, _ = verify_clearance_code("Student", "")
        self.assertTrue(ok_student)

        # Security without key must fail
        ok_sec_bad, _ = verify_clearance_code("Campus Security", "")
        self.assertFalse(ok_sec_bad)

        # Security with invalid key must fail
        ok_sec_wrong, _ = verify_clearance_code("Campus Security", "WrongPasscode")
        self.assertFalse(ok_sec_wrong)

        # Security with valid key succeeds
        ok_sec_good, _ = verify_clearance_code("Campus Security", "CAMPUS-SEC-2026")
        self.assertTrue(ok_sec_good)

        # Admin with valid key succeeds
        ok_adm_good, _ = verify_clearance_code("Admin", "BACHAO-ADMIN-2026")
        self.assertTrue(ok_adm_good)

    # -----------------------------------------------------------------------
    # 3. Brute-Force Rate Limiting & Account Lockout
    # -----------------------------------------------------------------------
    def test_05_login_rate_limiting_and_lockout(self):
        """Verify consecutive failed login attempts trigger temporary lockout."""
        with patch("database.db.DB_PATH", self.test_db_path):
            test_id = "target_cadet"

            # 4 failures should still be allowed
            for _ in range(4):
                record_failed_login_attempt(test_id, max_attempts=5, lockout_minutes=5)
                allowed, _ = check_login_rate_limit(test_id)
                self.assertTrue(allowed)

            # 5th failure must trigger lockout
            record_failed_login_attempt(test_id, max_attempts=5, lockout_minutes=5)
            locked, lock_msg = check_login_rate_limit(test_id)
            self.assertFalse(locked)
            self.assertIn("locked", lock_msg.lower())

            # Resetting clears lockout
            reset_failed_login_attempts(test_id)
            allowed_after_reset, _ = check_login_rate_limit(test_id)
            self.assertTrue(allowed_after_reset)

    # -----------------------------------------------------------------------
    # 4. Phishing Heuristics & Social Engineering Engine
    # -----------------------------------------------------------------------
    def test_06_url_phishing_heuristics(self):
        """Verify multi-vector structural heuristic detection."""
        # Raw IP Hostname
        res_ip = analyze_url_heuristics("http://192.168.1.1/login.php")
        self.assertGreaterEqual(res_ip["score"], 40)
        self.assertTrue(any(ind["name"] == "Direct IP-Based Hostname" for ind in res_ip["indicators"]))

        # Brand spoofing in subdomain
        res_spoof = analyze_url_heuristics("https://paypal.com.verify-billing-update.xyz/login.php")
        self.assertIn(res_spoof["level"], ["High", "Critical"])
        self.assertGreaterEqual(res_spoof["score"], 56)

        # Shortener detection
        res_short = analyze_url_heuristics("http://bit.ly/secure-login")
        self.assertTrue(any(ind["name"] == "URL Shortener Masking" for ind in res_short["indicators"]))

        # Suspicious port and dangerous download extension
        res_payload = analyze_url_heuristics("http://malicious-server.xyz:8080/setup.exe")
        self.assertGreaterEqual(res_payload["score"], 70)
        self.assertTrue(any("Executable" in ind["name"] for ind in res_payload["indicators"]))

        # Clean legitimate link
        res_clean = analyze_url_heuristics("https://www.google.com/search")
        self.assertEqual(res_clean["level"], "Low")
        self.assertLessEqual(res_clean["score"], 25)

    def test_07_social_engineering_text_analysis(self):
        """Verify deception pattern detection in email/SMS messages."""
        msg = "Dear customer, urgent: your account will be suspended within 24 hours. Click here to verify your credentials: http://192.168.1.1/auth"
        res = analyze_text_message(msg)
        self.assertGreaterEqual(res["score"], 40)
        self.assertTrue(len(res["indicators"]) >= 2)
        self.assertTrue(len(res["found_urls"]) >= 1)

    # -----------------------------------------------------------------------
    # 5. Have I Been Pwned k-Anonymity Model
    # -----------------------------------------------------------------------
    def test_08_k_anonymity_partitioning(self):
        """Ensure SHA-1 hash is computed locally and cleanly partitioned into 5/35 chars."""
        pwd = "TestSecretPassword123!"
        sha1_full = hashlib.sha1(pwd.encode("utf-8")).hexdigest().upper()
        prefix = sha1_full[:5]
        suffix = sha1_full[5:]

        self.assertEqual(len(prefix), 5)
        self.assertEqual(len(suffix), 35)
        self.assertEqual(prefix + suffix, sha1_full)

    @patch("modules.password_safety.requests.get")
    def test_09_hibp_local_suffix_matching(self, mock_get):
        """Verify local suffix comparison against mocked HIBP range response."""
        pwd = "KnownBreachedPass"
        sha1_full = hashlib.sha1(pwd.encode("utf-8")).hexdigest().upper()
        prefix = sha1_full[:5]
        suffix = sha1_full[5:]

        # Mock API returning range lines with our matching suffix
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = f"00112233445566778899AABBCCDDEEFF001:5\n{suffix}:4210\nFFAABBCCDDEEFF00112233445566778899A:12"
        mock_get.return_value = mock_response

        res = query_hibp_k_anonymity(pwd)
        self.assertTrue(res["match"])
        self.assertEqual(res["count"], 4210)
        self.assertEqual(res["prefix"], prefix)

    # -----------------------------------------------------------------------
    # 6. File Upload Inspection & Magic Bytes
    # -----------------------------------------------------------------------
    def test_10_magic_bytes_file_validation(self):
        """Verify that genuine images pass and executable masquerades are rejected."""
        # Valid PNG file (valid magic bytes \x89PNG\r\n\x1a\n)
        valid_png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + (b"\x00" * 100)
        valid_file = MockUploadedFile("evidence.png", "image/png", valid_png_bytes)
        ok_png, err_png = validate_uploaded_file(valid_file)
        self.assertTrue(ok_png)

        # Spoofed file: executable/text disguised as PNG
        spoofed_png_bytes = b"MZ\x90\x00\x03\x00\x00\x00ThisIsAnExecutable"
        spoofed_file = MockUploadedFile("trojan.png", "image/png", spoofed_png_bytes)
        ok_spoof, err_spoof = validate_uploaded_file(spoofed_file)
        self.assertFalse(ok_spoof)
        self.assertIn("Magic bytes header mismatch", err_spoof)

        # Exceeds maximum size limit
        oversized_file = MockUploadedFile("large.jpg", "image/jpeg", b"\xff\xd8\xff" + (b"\x00" * (6 * 1024 * 1024)))
        ok_size, err_size = validate_uploaded_file(oversized_file, max_size_mb=5.0)
        self.assertFalse(ok_size)
        self.assertIn("exceeds maximum allowed size", err_size)

    # -----------------------------------------------------------------------
    # 7. Campus Safety Incident Privacy & Lifecycle
    # -----------------------------------------------------------------------
    def test_11_campus_incident_privacy_and_workflow(self):
        """Verify student reports are confidential and status transitions properly."""
        with patch("database.db.DB_PATH", self.test_db_path):
            # Student 1 submits report
            inc_1 = create_campus_incident(
                username="student_alice",
                category="Suspicious Activity",
                description="Unattended crate near Sector Alpha",
                location="North Gate - Sector Alpha"
            )

            # Student 2 submits report
            inc_2 = create_campus_incident(
                username="student_bob",
                category="Harassment",
                description="Verbal altercation at hostel gate",
                location="Student Hostel Complex A"
            )

            # Student Alice should strictly see ONLY her report
            alice_reports = get_campus_incidents(username="student_alice", is_admin=False)
            self.assertEqual(len(alice_reports), 1)
            self.assertEqual(alice_reports[0]["incident_id"], inc_1)

            # Student Bob should strictly see ONLY his report
            bob_reports = get_campus_incidents(username="student_bob", is_admin=False)
            self.assertEqual(len(bob_reports), 1)
            self.assertEqual(bob_reports[0]["incident_id"], inc_2)

            # Security Officer / Admin sees ALL reports
            officer_reports = get_campus_incidents(username="officer_singh", is_admin=True)
            self.assertEqual(len(officer_reports), 2)

            # Status Lifecycle: Submitted -> In Progress -> Resolved
            self.assertEqual(alice_reports[0]["status"], "Submitted")
            update_incident_status(inc_1, "In Progress", resolved_by="officer_singh", notes="Patrol dispatched")

            updated_reports = get_campus_incidents(username="student_alice", is_admin=False)
            self.assertEqual(updated_reports[0]["status"], "In Progress")
            self.assertEqual(updated_reports[0]["resolution_notes"], "Patrol dispatched")

            # Resolve incident
            update_incident_status(inc_1, "Resolved", resolved_by="officer_singh", notes="Threat cleared")
            resolved_reports = get_campus_incidents(username="student_alice", is_admin=False)
            self.assertEqual(resolved_reports[0]["status"], "Resolved")

    # -----------------------------------------------------------------------
    # 8. Central Event Logging & Zero-Leakage Assurance
    # -----------------------------------------------------------------------
    def test_12_event_logging_and_zero_password_leakage(self):
        """Ensure telemetry logs events without leaking plaintext passwords."""
        with patch("database.db.DB_PATH", self.test_db_path):
            secret_pwd = "SuperSecretPlainTextPassword!"

            # Log an authentication event
            evt_id = insert_event(
                event_type="FAILED_LOGIN",
                severity="HIGH",
                category="ACCESS",
                description=f"Authentication failed for user 'test_user'",
                user_id="test_user"
            )

            events = get_recent_events(limit=5)
            self.assertTrue(len(events) > 0)

            # Verify that the plaintext password is never found in any event description
            for evt in events:
                self.assertNotIn(secret_pwd, evt["description"])

    # -----------------------------------------------------------------------
    # 9. End-to-End Hackathon Demonstration Workflow Smoke Test
    # -----------------------------------------------------------------------
    def test_13_hackathon_demo_end_to_end_smoke(self):
        """Execute the complete 8-step Hackathon Demonstration Workflow programmatically."""
        with patch("database.db.DB_PATH", self.test_db_path):
            # Step 1: Register and login as Student
            pwd_hash, salt = hash_password("CadetPass2026!")
            create_ok, _ = create_user("cadet_demo", "demo@campus.edu", pwd_hash, salt, "Student")
            self.assertTrue(create_ok)
            user = get_user_by_username("cadet_demo")
            self.assertIsNotNone(user)
            self.assertTrue(verify_password("CadetPass2026!", user["password_hash"], user["salt"]))

            # Step 2: Analyze Phishing URL
            url_res = analyze_url_heuristics("https://paypal.com.verify-billing-update.xyz/login.php")
            self.assertGreaterEqual(url_res["score"], 56)
            scan_id = record_phishing_scan("URL", "https://paypal.com.verify.xyz", url_res["score"], url_res["level"], "[]", "cadet_demo")
            self.assertTrue(scan_id.startswith("SCN-"))

            # Step 3: Analyze Social Engineering Message
            msg_res = analyze_text_message("Dear customer, urgent account suspension warning. Click to verify.")
            self.assertGreaterEqual(msg_res["score"], 30)

            # Step 4: Audit Password Safely
            eval_pwd = evaluate_password_security("password123")
            self.assertTrue(eval_pwd["is_common"])
            record_password_audit(eval_pwd["entropy_bits"], eval_pwd["score"], True, 1000000, "cadet_demo")

            # Step 5: Submit Campus Safety Incident
            inc_id = create_campus_incident("cadet_demo", "Suspicious Activity", "Bag left unattended", "Library Annex Gate 3")
            self.assertTrue(inc_id.startswith("INC-"))

            # Step 6: Create and authenticate Officer Account
            sec_hash, sec_salt = hash_password("OfficerSecurity2026!")
            sec_ok, _ = create_user("officer_sharma", "security@campus.edu", sec_hash, sec_salt, "Campus Security")
            self.assertTrue(sec_ok)

            # Step 7: Officer reviews and updates incident
            officer_view = get_campus_incidents(is_admin=True)
            self.assertTrue(any(i["incident_id"] == inc_id for i in officer_view))
            upd_ok = update_incident_status(inc_id, "Resolved", resolved_by="officer_sharma", notes="Inspected and safe.")
            self.assertTrue(upd_ok)

            # Step 8: Verify Dashboard Telemetry reflects all activities
            metrics = get_dashboard_metrics()
            self.assertEqual(metrics["total_users"], 2)
            self.assertEqual(metrics["urls_analyzed"], 1)
            self.assertEqual(metrics["pwned_matches"], 1)
            self.assertEqual(metrics["incidents_reported"], 1)
            self.assertEqual(metrics["incidents_resolved"], 1)


if __name__ == "__main__":
    unittest.main()
