"""
BACHAO+ Password Safety Module
Evaluates cryptographic strength, detects weak patterns, and queries the Have I Been Pwned
k-anonymity API without transmitting the candidate password.
"""

import hashlib
import requests
import streamlit as st
from database.db import record_password_audit
from utils.event_logger import log_password_breach
from utils.security import (
    evaluate_password_security,
    generate_strong_passphrase
)


def query_hibp_k_anonymity(password: str) -> dict:
    """
    Check if candidate password has been exposed in publicly catalogued data breaches
    using Cloudflare / Troy Hunt's mathematical k-Anonymity model.

    Protocol:
    1. Compute SHA-1 hash locally in memory.
    2. Split into 5-character prefix and 35-character suffix.
    3. Send ONLY the 5-character prefix over HTTPS to Have I Been Pwned API.
    4. Receive ~500-1000 hash suffixes matching that prefix.
    5. Search for matching suffix entirely LOCALLY.
    6. Plaintext password is NEVER transmitted or persisted anywhere.
    """
    if not password:
        return {"status": "empty", "match": False, "count": 0}

    # 1. Compute SHA-1 hash locally
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    api_url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {
        "User-Agent": "BACHAO-Defence-Security-Platform-MVP",
        "Add-Padding": "true"  # Enhanced k-anonymity resistance against traffic analysis
    }

    try:
        response = requests.get(api_url, headers=headers, timeout=4.0)
        if response.status_code != 200:
            return {
                "status": "api_error",
                "match": False,
                "count": 0,
                "message": f"HIBP service responded with status {response.status_code}."
            }

        # Parse suffix list
        lines = response.text.splitlines()
        for line in lines:
            parts = line.strip().split(":")
            if len(parts) == 2:
                resp_suffix, count_str = parts[0].strip(), parts[1].strip()
                if resp_suffix == suffix:
                    return {
                        "status": "success",
                        "match": True,
                        "count": int(count_str),
                        "prefix": prefix
                    }

        return {
            "status": "success",
            "match": False,
            "count": 0,
            "prefix": prefix
        }

    except requests.exceptions.Timeout:
        return {
            "status": "offline",
            "match": False,
            "count": 0,
            "message": "HIBP check timed out. Network latency or offline operation active."
        }
    except Exception as e:
        return {
            "status": "offline",
            "match": False,
            "count": 0,
            "message": f"HIBP check offline: {str(e)}"
        }


def render_password_safety_page() -> None:
    """Render the interactive Password Safety & Credential Hardening module."""
    st.markdown("""
        <div class="module-header">
            <h2>🔑 Password Safety & Credential Hardening</h2>
            <p class="subtitle">Cryptographic entropy calculation, dictionary pattern detection, and private k-Anonymity breach verification.</p>
        </div>
    """, unsafe_allow_html=True)

    tab_audit, tab_generator, tab_policy = st.tabs([
        "🔐 Interactive Credential Audit",
        "🎲 Defence Passphrase Generator",
        "📜 Institutional Security Standards"
    ])

    current_user = st.session_state.get("username", "ANONYMOUS")

    # -----------------------------------------------------------------------
    # TAB 1: Password Audit
    # -----------------------------------------------------------------------
    with tab_audit:
        col_main, col_sidebar = st.columns([3, 2])

        with col_main:
            st.markdown("### 🛡️ Credential Hardening Diagnostic")
            st.caption("Input a candidate password or passphrase to audit its entropy, patterns, and breach exposure.")

            # Quick demo pills
            st.markdown("**💡 Demonstration Samples (Click to test):**")
            p_c1, p_c2, p_c3 = st.columns(3)
            if p_c1.button("⚠️ Common: password123", key="demo_pwd_weak"):
                st.session_state["pwd_audit_val"] = "password123"
            if p_c2.button("🚨 Leaked: P@ssword1", key="demo_pwd_leaked"):
                st.session_state["pwd_audit_val"] = "P@ssword1"
            if p_c3.button("🛡️ Strong: Citadel#92Overwatch!", key="demo_pwd_strong"):
                st.session_state["pwd_audit_val"] = "Citadel#92Overwatch!"

            candidate_pwd = st.text_input(
                "Candidate Password",
                value=st.session_state.get("pwd_audit_val", ""),
                type="password",
                placeholder="Enter password to evaluate (never stored or logged)...",
                key="input_audit_password"
            )

            col_check1, col_check2 = st.columns(2)
            with col_check1:
                enable_hibp = st.checkbox("Query HIBP via k-Anonymity", value=True, help="Queries Have I Been Pwned using only a 5-char SHA1 prefix.")
            with col_check2:
                show_pwd_preview = st.checkbox("Reveal candidate text for inspection", value=False)

            if show_pwd_preview and candidate_pwd:
                st.code(candidate_pwd, language="text")

            btn_run_audit = st.button("🔐 Run Cryptographic Audit", key="btn_run_pwd_audit", use_container_width=True)

            if btn_run_audit:
                if not candidate_pwd:
                    st.warning("⚠️ Please provide a password to audit.")
                else:
                    with st.spinner("Calculating Shannon entropy and checking vulnerability databases..."):
                        # 1. Local Security Evaluation (Entropy, length, patterns, dictionary)
                        eval_data = evaluate_password_security(candidate_pwd)
                        score = eval_data["score"]
                        entropy = eval_data["entropy_bits"]
                        rating = eval_data["rating"]

                        # 2. HIBP Check via k-Anonymity
                        hibp_result = {"status": "skipped", "match": False, "count": 0}
                        if enable_hibp:
                            hibp_result = query_hibp_k_anonymity(candidate_pwd)

                        pwned_match = hibp_result.get("match", False)
                        pwned_count = hibp_result.get("count", 0)

                        # Record anonymized statistics in SQLite (NEVER store candidate password!)
                        record_password_audit(
                            entropy_bits=entropy,
                            score=score,
                            pwned_match=pwned_match,
                            pwned_count=pwned_count,
                            user_id=current_user
                        )

                        # If breach exposure is confirmed, log high-priority event to Central Engine
                        if pwned_match:
                            log_password_breach(
                                description=f"Audited credential hash matched {pwned_count:,} exposures in public breach databases",
                                user_id=current_user
                            )

                        st.markdown("<br>", unsafe_allow_html=True)
                        st.markdown("#### 📊 Diagnostic Metrics")

                        m1, m2, m3 = st.columns(3)
                        with m1:
                            st.markdown(f"""
                                <div class="metric-card">
                                    <div class="metric-label">Strength Score</div>
                                    <div class="metric-value" style="color: {eval_data['color']};">{score} / 100</div>
                                    <div class="metric-sub">{rating}</div>
                                </div>
                            """, unsafe_allow_html=True)

                        with m2:
                            st.markdown(f"""
                                <div class="metric-card">
                                    <div class="metric-label">Shannon Entropy</div>
                                    <div class="metric-value">{entropy} <span style="font-size: 0.9rem; color: #64748B;">bits</span></div>
                                    <div class="metric-sub">Keyspace Hardness</div>
                                </div>
                            """, unsafe_allow_html=True)

                        with m3:
                            breach_text = f"{pwned_count:,} Matches" if pwned_match else ("Clean" if hibp_result.get("status") == "success" else "Offline")
                            breach_color = "#DC2626" if pwned_match else "#0F766E"
                            st.markdown(f"""
                                <div class="metric-card">
                                    <div class="metric-label">Breach Exposure</div>
                                    <div class="metric-value" style="color: {breach_color}; font-size: 1.5rem;">{breach_text}</div>
                                    <div class="metric-sub">Have I Been Pwned</div>
                                </div>
                            """, unsafe_allow_html=True)

                        st.markdown("<br>", unsafe_allow_html=True)

                        # Have I Been Pwned Detailed Status Banner
                        if pwned_match:
                            st.error(f"""
                                🚨 **CRITICAL BREACH EXPOSURE DETECTED**:
                                This password has appeared **{pwned_count:,} times** across previously published data breach dumps!
                            """)
                        elif hibp_result.get("status") == "success":
                            st.success("✅ **Zero Exposure in Known Breach Datasets**: No matching hash suffixes were found in the Have I Been Pwned database.")
                        else:
                            st.info(f"ℹ️ **Breach Lookup Notice**: {hibp_result.get('message', 'Check skipped or network unavailable. Local evaluation remains active.')}")

                        # Crucial Required Transparency Explanation
                        st.markdown("""
                            <div style="background: #FAF7F2; border: 1px solid #E5DCCE; border-radius: 6px; padding: 12px 16px; margin: 12px 0; font-size: 0.88rem; color: #334155;">
                                <strong>⚠️ Verification Disclaimer:</strong>
                                A matching password hash indicates that this exact string was present in historical third-party compromised databases.
                                It does <em>not</em> confirm or imply that your specific email or account was directly breached, but demonstrates that attackers already possess this credential in standard automated dictionary attacks.
                            </div>
                        """, unsafe_allow_html=True)

                        # Actionable Guidance & Suggestions
                        st.markdown("#### 🛠️ Corrective Hardening Guidance")
                        if eval_data["suggestions"]:
                            for sug in eval_data["suggestions"]:
                                st.markdown(f"- {sug}")
                        else:
                            st.success("🎯 Excellent configuration. Password satisfies institutional defence criteria.")

        with col_sidebar:
            st.markdown("""
                <div class="info-box">
                    <h4>🔒 Privacy & Zero-Knowledge Guarantee</h4>
                    <p>BACHAO+ strictly enforces zero password storage:</p>
                    <ul>
                        <li><strong>Never Logged:</strong> Passwords tested here are never written to disk, SQLite, or telemetry logs.</li>
                        <li><strong>k-Anonymity Model:</strong> When querying breach data, your browser/server generates a SHA-1 hash and sends only the first <strong>5 hex characters</strong>. The remaining 35 characters remain strictly local.</li>
                        <li><strong>Mathematical Privacy:</strong> The remote server cannot reverse the 5 characters to reconstruct your actual password.</li>
                    </ul>
                </div>
            """, unsafe_allow_html=True)

    # -----------------------------------------------------------------------
    # TAB 2: Defence Passphrase Generator
    # -----------------------------------------------------------------------
    with tab_generator:
        st.markdown("### 🎲 High-Entropy Defence Passphrase Generator")
        st.caption("Generate cryptographically random multi-word passphrases that provide >70 bits of entropy while remaining human-memorable.")

        col_w, col_btn_gen = st.columns([2, 1])
        with col_w:
            word_count = st.slider("Word Count in Passphrase", min_value=3, max_value=6, value=4)
        with col_btn_gen:
            st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
            btn_generate = st.button("🔄 Generate Passphrase", use_container_width=True)

        if btn_generate or "generated_phrase" not in st.session_state:
            st.session_state["generated_phrase"] = generate_strong_passphrase(num_words=word_count)

        phrase = st.session_state.get("generated_phrase", "")
        st.markdown(f"""
            <div style="background: #FFFFFF; border: 2px solid #0F766E; border-radius: 8px; padding: 18px 24px; text-align: center; margin: 16px 0;">
                <div style="font-size: 0.85rem; font-weight: 700; color: #0F766E; text-transform: uppercase; letter-spacing: 1px;">Suggested Defence Passphrase</div>
                <div style="font-size: 1.6rem; font-family: 'JetBrains Mono', monospace; font-weight: 800; color: #0F172A; margin: 8px 0;">
                    {phrase}
                </div>
                <div style="font-size: 0.82rem; color: #64748B;">High resistance against GPU cluster dictionary brute-force</div>
            </div>
        """, unsafe_allow_html=True)

    # -----------------------------------------------------------------------
    # TAB 3: Institutional Standards
    # -----------------------------------------------------------------------
    with tab_policy:
        st.markdown("""
            <div class="info-box">
                <h4>🏛️ BACHAO+ Institutional Security Baseline</h4>
                <table style="width: 100%; border-collapse: collapse; font-size: 0.9rem; margin-top: 10px;">
                    <tr style="border-bottom: 1px solid #E5DCCE; background: #FAF7F2;">
                        <th style="padding: 8px; text-align: left;">Clearance Tier</th>
                        <th style="padding: 8px; text-align: left;">Min Length</th>
                        <th style="padding: 8px; text-align: left;">Min Entropy</th>
                        <th style="padding: 8px; text-align: left;">MFA Requirement</th>
                    </tr>
                    <tr style="border-bottom: 1px solid #E5DCCE;">
                        <td style="padding: 8px;"><strong>Student / Cadet</strong></td>
                        <td style="padding: 8px;">10 characters</td>
                        <td style="padding: 8px;">50 bits</td>
                        <td style="padding: 8px;">Recommended</td>
                    </tr>
                    <tr style="border-bottom: 1px solid #E5DCCE;">
                        <td style="padding: 8px;"><strong>Campus Security</strong></td>
                        <td style="padding: 8px;">14 characters</td>
                        <td style="padding: 8px;">65 bits</td>
                        <td style="padding: 8px;">Mandatory (Hardware/TOTP)</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px;"><strong>Platform Admin</strong></td>
                        <td style="padding: 8px;">16+ characters</td>
                        <td style="padding: 8px;">80+ bits</td>
                        <td style="padding: 8px;">Strict Multi-Factor Key</td>
                    </tr>
                </table>
            </div>
        """, unsafe_allow_html=True)
