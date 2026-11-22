"""
BACHAO+ Secure Access & Identity Module
Implements user registration, PBKDF2 authentication, brute-force rate limiting,
anti-role-escalation verification, and session lifecycle management.
"""

import os
import streamlit as st
from database.db import (
    create_user,
    get_user_by_username,
    get_user_by_email,
    update_user_last_login,
    has_admin_user,
    check_login_rate_limit,
    record_failed_login_attempt,
    reset_failed_login_attempts,
    get_all_users
)
from utils.event_logger import log_auth_event, SecurityEventEngine
from utils.security import (
    hash_password,
    verify_password,
    validate_username,
    validate_email,
    validate_password_policy,
    verify_clearance_code,
    sanitize_input
)


def render_secure_access_page() -> None:
    """Render the Secure Access, Authentication, and Identity module."""
    st.markdown("""
        <div class="module-header">
            <h2>🔒 Secure Access & Identity Control</h2>
            <p class="subtitle">Cryptographic PBKDF2 credential management, Role-Based Access Control (RBAC), and session verification.</p>
        </div>
    """, unsafe_allow_html=True)

    is_authenticated = st.session_state.get("authenticated", False)
    current_user = st.session_state.get("username", "Guest")
    current_role = st.session_state.get("role", "Unauthenticated")
    current_email = st.session_state.get("email", "")

    # If already logged in, show User Profile & Session Terminal
    if is_authenticated:
        render_user_profile(current_user, current_role, current_email)
        return

    admin_exists = has_admin_user()

    tab_login, tab_register, tab_admin_setup = st.tabs([
        "🔑 Operator Login",
        "📝 New User Registration",
        "⚙️ Initial Admin Bootstrap"
    ])

    # -----------------------------------------------------------------------
    # TAB 1: User Login
    # -----------------------------------------------------------------------
    with tab_login:
        col_l1, col_l2 = st.columns([3, 2])

        with col_l1:
            st.markdown("### 🪪 Identity Verification Terminal")
            st.caption("Enter registered username or campus email to authenticate.")

            with st.form("user_login_form"):
                login_identifier = st.text_input("Username or Email Address", placeholder="e.g. cadet_sharma or cadet@campus.edu")
                login_password = st.text_input("Password", type="password", placeholder="Enter your password")

                btn_login = st.form_submit_button("🛡️ Authenticate & Launch Session", use_container_width=True)

                if btn_login:
                    clean_id = sanitize_input(login_identifier)
                    if not clean_id or not login_password:
                        st.error("⚠️ Please provide both identifier and password.")
                    else:
                        # 1. Check Rate-Limiting & Brute-Force Lockout
                        allowed, lock_reason = check_login_rate_limit(clean_id)
                        if not allowed:
                            SecurityEventEngine.log(
                                "LOCKED_ACCOUNT_LOGIN_ATTEMPT", "HIGH", "ACCESS",
                                f"Login attempted on locked identifier '{clean_id}'", clean_id
                            )
                            st.error(f"⛔ {lock_reason}")
                        else:
                            # 2. Look up user record
                            user = get_user_by_username(clean_id)
                            if not user:
                                user = get_user_by_email(clean_id)

                            if not user:
                                failures = record_failed_login_attempt(clean_id)
                                log_auth_event("FAILED_LOGIN", clean_id, success=False, reason="Account does not exist")
                                st.error("⛔ Authentication Failed: Invalid credentials.")
                                if failures >= 5:
                                    st.warning("⚠️ Threshold reached: This identifier is now temporarily locked.")
                            else:
                                # 3. Verify cryptographic PBKDF2 hash
                                stored_hash = user["password_hash"]
                                stored_salt = user["salt"]

                                if verify_password(login_password, stored_hash, stored_salt):
                                    # Reset failed attempts on success
                                    reset_failed_login_attempts(clean_id)
                                    reset_failed_login_attempts(user["username"])

                                    # Update database and session state
                                    update_user_last_login(user["id"])
                                    st.session_state["authenticated"] = True
                                    st.session_state["user_id"] = user["id"]
                                    st.session_state["username"] = user["username"]
                                    st.session_state["email"] = user["email"]
                                    st.session_state["role"] = user["role"]

                                    log_auth_event("USER_LOGGED_IN", user["username"], success=True, reason=f"Role: {user['role']}")
                                    st.success(f"✅ Welcome back, **{user['username']}** ({user['role']})!")
                                    st.rerun()
                                else:
                                    failures = record_failed_login_attempt(user["username"])
                                    record_failed_login_attempt(clean_id)
                                    log_auth_event("FAILED_LOGIN", user["username"], success=False, reason=f"Incorrect password (attempt {failures})")
                                    st.error("⛔ Authentication Failed: Invalid credentials.")
                                    if failures >= 5:
                                        SecurityEventEngine.log(
                                            "BRUTE_FORCE_LOCKOUT", "CRITICAL", "ACCESS",
                                            f"Identifier '{user['username']}' locked for 5 minutes after {failures} consecutive failed attempts",
                                            user["username"]
                                        )
                                        st.warning("⚠️ Maximum attempts exceeded: Account temporarily locked for 5 minutes.")

            # Quick Demo Guidance
            with st.expander("💡 Access & Clearance Tier Guidance"):
                st.markdown("""
                - **Student Account**: Self-register any username in the **New User Registration** tab (no clearance key needed).
                - **Campus Security**: Enter the security clearance key configured on your server (see `.env.example`).
                - **Administrator**: Enter the admin authorization key configured on your server, or use the **Initial Admin Bootstrap** tab.
                """)

        with col_l2:
            st.markdown("""
                <div class="info-box">
                    <h4>RBAC Clearance Tiers</h4>
                    <p style="font-size: 0.9rem; color: #475569;">Access privileges are strictly segmented by operational role:</p>
                    <ul style="font-size: 0.9rem; line-height: 1.6;">
                        <li><strong>Student:</strong> Submit safety incident reports, track personal submissions, run threat analysis.</li>
                        <li><strong>Campus Security:</strong> Full view of all campus alerts, incident triage, live status updating.</li>
                        <li><strong>Admin:</strong> System configuration, personnel directory review, root policy controls.</li>
                    </ul>
                </div>
            """, unsafe_allow_html=True)

    # -----------------------------------------------------------------------
    # TAB 2: User Registration
    # -----------------------------------------------------------------------
    with tab_register:
        st.markdown("### 📝 Register New Personnel / Student Account")
        st.caption("Enroll a new member account into the local defense database.")

        with st.form("user_registration_form"):
            reg_username = st.text_input("Username (3–30 characters, alphanumeric)", placeholder="e.g. rahul_verma")
            reg_email = st.text_input("Campus Email Address", placeholder="e.g. rahul.verma@campus.edu")
            reg_password = st.text_input("Password (min 8 characters)", type="password", placeholder="Choose strong passphrase")
            reg_password_confirm = st.text_input("Confirm Password", type="password", placeholder="Repeat chosen passphrase")

            reg_role = st.selectbox(
                "Requested Role",
                ["Student", "Campus Security", "Admin"],
                help="Students require no authorization key. Security and Admin tiers require supervisor clearance keys."
            )

            clearance_key = ""
            if reg_role in ("Campus Security", "Admin"):
                clearance_key = st.text_input(
                    f"Supervisor Clearance Key for '{reg_role}' *",
                    type="password",
                    placeholder="Enter security clearance passcode (prevents unauthorized role escalation)",
                    help="Enter the supervisor authorization key configured on the server (see .env.example)."
                )

            btn_register = st.form_submit_button("✍️ Create Account", use_container_width=True)

            if btn_register:
                # 1. Format validation
                val_u_ok, val_u_msg = validate_username(reg_username)
                val_e_ok, val_e_msg = validate_email(reg_email)
                val_p_ok, val_p_msg = validate_password_policy(reg_password)

                # 2. Clearance code validation to prevent unauthorized role escalation
                clearance_ok, clearance_msg = verify_clearance_code(reg_role, clearance_key)

                if not val_u_ok:
                    st.error(f"⚠️ {val_u_msg}")
                elif not val_e_ok:
                    st.error(f"⚠️ {val_e_msg}")
                elif not val_p_ok:
                    st.error(f"⚠️ {val_p_msg}")
                elif reg_password != reg_password_confirm:
                    st.error("⚠️ Passwords do not match. Please re-enter identical passphrases.")
                elif not clearance_ok:
                    SecurityEventEngine.log(
                        "ROLE_ESCALATION_ATTEMPT_BLOCKED", "HIGH", "ACCESS",
                        f"Registration as '{reg_role}' blocked for '{reg_username}': {clearance_msg}",
                        reg_username
                    )
                    st.error(f"⛔ Authorization Denied: {clearance_msg}")
                else:
                    # Hash password with PBKDF2-HMAC-SHA256 and unique 16-byte salt
                    pwd_hash, salt = hash_password(reg_password)

                    success, msg = create_user(
                        username=reg_username,
                        email=reg_email,
                        password_hash=pwd_hash,
                        salt=salt,
                        role=reg_role
                    )

                    if success:
                        SecurityEventEngine.log(
                            event_type="USER_REGISTERED",
                            severity="INFO",
                            category="ACCESS",
                            description=f"New user '{reg_username}' registered with verified role '{reg_role}'",
                            user_id=reg_username
                        )
                        st.success("🎉 Account created successfully! You can now log in via the Operator Login tab.")
                    else:
                        st.error(f"⚠️ Registration error: {msg}")

    # -----------------------------------------------------------------------
    # TAB 3: Safe Initial Admin Bootstrap
    # -----------------------------------------------------------------------
    with tab_admin_setup:
        st.markdown("### ⚙️ Initial Administrator Setup")
        st.caption("Securely initialize the primary platform administrator without hardcoding credentials.")

        if admin_exists:
            st.success("✅ **Administrator Account Configured**: An active administrator account exists in the database.")
            st.info("Additional administrators can be provisioned through standard registration using the Administrator Key or by existing Admins.")
        else:
            st.warning("⚠️ **No Administrator Detected**: The platform currently lacks a root administrator account.")
            st.markdown("""
                You can bootstrap the administrator account in one of two safe ways:
                
                **Method 1: Environment Variables (Recommended for Production)**
                Set the following variables before launching:
                ```bash
                export ADMIN_USERNAME="root_admin"
                export ADMIN_PASSWORD="YourSecurePasswordHere123!"
                export ADMIN_EMAIL="admin@campus.defence"
                ```
                
                **Method 2: One-Time Initialization Form (Direct)**
            """)

            with st.form("admin_bootstrap_form"):
                boot_user = st.text_input("Admin Username", value="root_admin")
                boot_email = st.text_input("Admin Email", value="admin@campus.defence")
                boot_pass = st.text_input("Admin Password (min 12 chars)", type="password")
                btn_boot = st.form_submit_button("🚀 Initialize Root Administrator")

                if btn_boot:
                    if len(boot_pass) < 12:
                        st.error("Administrator passwords must be at least 12 characters.")
                    else:
                        pwd_hash, salt = hash_password(boot_pass)
                        succ, msg = create_user(
                            username=boot_user,
                            email=boot_email,
                            password_hash=pwd_hash,
                            salt=salt,
                            role="Admin"
                        )
                        if succ:
                            st.success("Root administrator initialized! Please log in via the Operator Login tab.")
                            st.rerun()
                        else:
                            st.error(msg)


def render_user_profile(username: str, role: str, email: str) -> None:
    """Render the active user profile, session details, and administrative controls."""
    st.markdown("### 👤 Active Operator Session")

    c1, c2 = st.columns([3, 2])

    with c1:
        role_color = "#DC2626" if role == "Admin" else ("#B45309" if role == "Campus Security" else "#0F766E")

        st.markdown(f"""
            <div style="background: #FFFFFF; border: 1px solid #E5DCCE; border-radius: 10px; padding: 24px; box-shadow: 0 2px 6px rgba(0,0,0,0.02);">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div style="font-size: 1.5rem; font-weight: 800; color: #0F172A;">{username}</div>
                    <span style="background: {role_color}20; color: {role_color}; padding: 4px 12px; border-radius: 20px; font-weight: 800; font-size: 0.85rem; border: 1px solid {role_color};">
                        {role.upper()}
                    </span>
                </div>
                <div style="color: #64748B; font-size: 0.95rem; margin-top: 6px;">
                    Email: <strong>{email}</strong>
                </div>
                <div style="margin-top: 16px; padding-top: 14px; border-top: 1px solid #F1EBE1; font-size: 0.85rem; color: #475569;">
                    🔒 <strong>Session Security:</strong> In-memory state active • Cryptographic authorization validated
                </div>
            </div>
        """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        btn_logout = st.button("🚪 Terminate Session & Log Out", type="secondary", use_container_width=True)

        if btn_logout:
            log_auth_event("USER_LOGGED_OUT", username, success=True, reason="User initiated session termination")
            for key in ["authenticated", "user_id", "username", "email", "role"]:
                if key in st.session_state:
                    del st.session_state[key]
            st.success("Session closed safely.")
            st.rerun()

    with c2:
        st.markdown("""
            <div class="info-box">
                <h4>Active Clearance Permissions</h4>
                <ul>
                    <li><strong>Phishing Diagnostic Suite:</strong> Unrestricted</li>
                    <li><strong>Password Hardening Suite:</strong> Unrestricted</li>
                    <li><strong>Campus Incident Reporting:</strong> Active</li>
                    <li><strong>Overwatch Terminal:</strong> Enabled for Security / Admin tiers</li>
                </ul>
            </div>
        """, unsafe_allow_html=True)

    # If Admin, show User Directory tab
    if role == "Admin":
        st.markdown("---")
        st.markdown("### 👥 Institutional Personnel Directory (Admin Overwatch)")
        users = get_all_users()
        if users:
            import pandas as pd
            df_users = pd.DataFrame(users)[["id", "username", "email", "role", "created_at", "last_login"]]
            df_users.columns = ["ID", "Username", "Email", "Clearance Role", "Enrolled At", "Last Login"]
            st.dataframe(df_users, use_container_width=True, hide_index=True)
        else:
            st.info("No registered personnel found.")
