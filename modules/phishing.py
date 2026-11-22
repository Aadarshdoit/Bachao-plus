"""
BACHAO+ Phishing & Scam Detection Module
Comprehensive defensive analysis for URLs, suspicious sender patterns, and deceptive messages.
"""

import json

# Initialize session state for persistent scan result
import streamlit as st
# Initialize session state for persistent scan result
if "latest_url_scan_result" not in st.session_state:
    st.session_state["latest_url_scan_result"] = None
import re
import urllib.parse
from database.db import record_phishing_scan
from utils.event_logger import log_phishing_analysis
from utils.security import sanitize_input

# Known URL shortener domains
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly",
    "rb.gy", "cutt.ly", "shorturl.at", "tiny.cc", "rebrand.ly", "v.gd", "clck.ru"
}

# High-risk / disposable TLDs commonly abused by campaign kits
HIGH_RISK_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".click",
    ".cam", ".zip", ".mov", ".loan", ".surf", ".support", ".rest", ".fit",
    ".buzz", ".monster", ".icu", ".space"
}

# High-profile brand names frequently spoofed in credential-harvesting attacks
TARGETED_BRANDS = [
    "paypal", "apple", "google", "microsoft", "amazon", "netflix", "sbi",
    "hdfc", "icici", "chase", "wellsfargo", "bankofamerica", "binance",
    "coinbase", "meta", "facebook", "instagram", "whatsapp", "dropbox"
]

# Sensitive phishing intent keywords
PHISHING_KEYWORDS = [
    "verify", "suspended", "urgent", "account-alert", "action-required",
    "kyc", "refund", "tax-rebate", "claim", "secure-login", "unlock",
    "credential", "wallet-connect", "security-update", "confirm-identity",
    "billing-error", "password-reset", "unusual-activity", "winner", "prize"
]

# Dangerous file extensions commonly delivered through malicious drive-by links
DANGEROUS_DOWNLOAD_EXTENSIONS = [
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".ps1", ".apk", ".iso", ".msi", ".jar"
]

# Suspicious non-standard ports commonly bound to rogue servers
SUSPICIOUS_PORTS = {"8080", "8888", "2082", "2083", "2086", "7080", "4444", "9999"}

# Social engineering triggers for email/message text
SOCIAL_ENG_TRIGGERS = [
    (r"(urgent|immediate action|within 24 hours|account will be (closed|suspended|locked))", "High-pressure urgency coercion tactic", 20),
    (r"(verify your (identity|password|pin|otp|credentials)|enter your login)", "Direct credential harvesting solicitation", 25),
    (r"(unauthorized (transaction|access|charge)|suspicious activity detected)", "Fear-inducing false security warning", 15),
    (r"(won a (lottery|gift card|prize)|exclusive cash bonus|free voucher)", "Greed lure / unsolicited reward hook", 20),
    (r"(dear (customer|user|account holder|client|member))", "Impersonal generic greeting indicating mass-phishing", 10),
    (r"(click (here|the link below|this secure button) to (prevent|claim|confirm))", "Coercive call-to-action link directive", 15),
    (r"(tax refund|crypto (airdrop|payout)|bitcoin deposit)", "Financial windfall impersonation lure", 15)
]


def analyze_url_heuristics(url: str) -> dict:
    """
    Perform deep structural heuristic examination of a target URL.
    Returns calculated threat score (0-100), risk level, and detailed indicators.
    """
    clean_url = (url or "").strip()
    indicators = []
    score = 0

    if not clean_url:
        return {
            "score": 0,
            "level": "Low",
            "indicators": [],
            "is_ip": False,
            "has_https": False,
            "hostname": ""
        }

    # Ensure protocol for parsing
    has_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", clean_url))
    parsed_target = clean_url if has_scheme else "http://" + clean_url

    try:
        parsed = urllib.parse.urlparse(parsed_target)
        netloc = (parsed.netloc or "").lower()
        path = (parsed.path or "").lower()
        query = (parsed.query or "").lower()
    except Exception:
        return {
            "score": 85,
            "level": "High",
            "indicators": [{"name": "Malformed URL Structure", "desc": "URL syntax violates RFC-3986 standards.", "severity": "HIGH"}],
            "is_ip": False,
            "has_https": False,
            "hostname": ""
        }

    # Extract port and hostname
    if ":" in netloc:
        parts = netloc.rsplit(":", 1)
        hostname = parts[0].strip("[]")
        port = parts[1]
    else:
        hostname = netloc.strip("[]")
        port = ""

    # 1. IP Address in Hostname (High Confidence Marker)
    is_ip = False
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
        is_ip = True
        score += 35
        indicators.append({
            "name": "Direct IP-Based Hostname",
            "desc": f"Host identifies as raw IP address '{hostname}' rather than a verified domain name.",
            "severity": "CRITICAL"
        })

    # 2. Absence of HTTPS Encryption
    has_https = clean_url.lower().startswith("https://")
    if not has_https:
        score += 15
        indicators.append({
            "name": "Missing HTTPS Encryption",
            "desc": "Target uses unencrypted HTTP communication or lacks an explicit SSL/TLS protocol prefix.",
            "severity": "MEDIUM"
        })

    # 3. URL Shortener Detection
    if hostname in SHORTENER_DOMAINS:
        score += 25
        indicators.append({
            "name": "URL Shortener Masking",
            "desc": f"Host '{hostname}' obfuscates the true destination server.",
            "severity": "HIGH"
        })

    # 4. Excessive Length / Obfuscation
    if len(clean_url) > 75:
        score += 15
        indicators.append({
            "name": "Excessive URL Length",
            "desc": f"URL length is {len(clean_url)} characters, exceeding standard legitimate service thresholds.",
            "severity": "LOW"
        })

    # 5. Misleading Subdomain Chains & Excessive Dots
    dot_count = hostname.count(".")
    if dot_count > 3:
        score += 20
        indicators.append({
            "name": "Excessive Subdomain Stacking",
            "desc": f"Domain contains {dot_count} dots, often used to disguise malicious target hosts.",
            "severity": "HIGH"
        })

    # 6. High-Risk TLD Detection
    for tld in HIGH_RISK_TLDS:
        if hostname.endswith(tld):
            score += 20
            indicators.append({
                "name": "High-Risk Top-Level Domain (TLD)",
                "desc": f"Domain utilizes '{tld}', statistically associated with disposable phishing campaigns.",
                "severity": "MEDIUM"
            })
            break

    # 7. Targeted Brand Spoofing / Typosquatting in Subdomain or Path
    for brand in TARGETED_BRANDS:
        if brand in hostname:
            parts = hostname.split(".")
            # Legitimate only if brand is exactly the second-level domain (e.g. google.com)
            if len(parts) >= 2 and parts[-2] != brand:
                score += 30
                indicators.append({
                    "name": f"Impersonation of Brand '{brand.capitalize()}'",
                    "desc": f"Brand token '{brand}' detected in subdomain or auxiliary path to deceive users.",
                    "severity": "CRITICAL"
                })
                break

    # 8. Deceptive Characters and Encoding Tricks
    if "@" in netloc or "@" in clean_url.split("?")[0]:
        score += 30
        indicators.append({
            "name": "Embedded '@' Authority Trick",
            "desc": "Contains '@' character before host; browsers route to content after '@', ignoring front string.",
            "severity": "CRITICAL"
        })

    if "xn--" in hostname:
        score += 25
        indicators.append({
            "name": "Punycode / IDN Homograph Marker",
            "desc": "Contains internationalized character mapping (Punycode), commonly used for lookalike spoofing.",
            "severity": "HIGH"
        })

    if "%20" in clean_url or "%2e" in clean_url.lower():
        score += 10
        indicators.append({
            "name": "Hexadecimal URL Encoding",
            "desc": "Contains percent-encoded tokens designed to evade simple string pattern filters.",
            "severity": "LOW"
        })

    # 9. Hyphen Density in Hostname (common in spoofed domains e.g. secure-login-bank-update.com)
    hyphen_count = hostname.count("-")
    if hyphen_count >= 2:
        score += 15
        indicators.append({
            "name": "High Hyphen Density in Hostname",
            "desc": f"Hostname contains {hyphen_count} hyphens, a common pattern in synthesized campaign domains.",
            "severity": "MEDIUM"
        })

    # 10. Suspicious Consumer Port
    if port and port in SUSPICIOUS_PORTS:
        score += 20
        indicators.append({
            "name": "Suspicious Port Number",
            "desc": f"URL binds to non-standard consumer port ':{port}'.",
            "severity": "HIGH"
        })

    # 11. Dangerous Download Extension in Path
    for ext in DANGEROUS_DOWNLOAD_EXTENSIONS:
        if path.endswith(ext):
            score += 35
            indicators.append({
                "name": f"Executable/Dangerous Download Target ({ext})",
                "desc": f"URL directly downloads an executable payload '{ext}'.",
                "severity": "CRITICAL"
            })
            break

    # 12. Phishing Keywords in Path or Parameters
    found_keywords = [kw for kw in PHISHING_KEYWORDS if kw in (path + " " + query)]
    if found_keywords:
        score += min(25, len(found_keywords) * 10)
        indicators.append({
            "name": "Credential / Urgency Keywords Present",
            "desc": f"URL path/query includes suspicious parameters: {', '.join(found_keywords[:3])}.",
            "severity": "MEDIUM"
        })

    final_score = min(score, 100)

    # Classify Risk Level
    if final_score >= 81:
        level = "Critical"
    elif final_score >= 56:
        level = "High"
    elif final_score >= 26:
        level = "Medium"
    else:
        level = "Low"

    return {
        "score": final_score,
        "level": level,
        "indicators": indicators,
        "is_ip": is_ip,
        "has_https": has_https,
        "hostname": hostname
    }


def analyze_text_message(text: str) -> dict:
    """
    Inspect message or email body for social engineering triggers and deceptive cues.
    Extracts embedded URLs and combines message heuristic scores.
    """
    indicators = []
    score = 0
    clean_text = (text or "").strip()

    if not clean_text:
        return {"score": 0, "level": "Low", "indicators": [], "found_urls": []}

    # Extract all embedded URLs
    found_urls = re.findall(r"(https?://[^\s<>\"']+|www\.[^\s<>\"']+|[a-zA-Z0-9-]+\.(?:com|org|net|xyz|top|cc|tk|work)[^\s<>\"']*)", clean_text)
    
    if found_urls:
        indicators.append({
            "name": "Contains Web Hyperlinks",
            "desc": f"Detected {len(found_urls)} external link(s) embedded in message body.",
            "severity": "INFO"
        })
        # Evaluate primary URL heuristics
        url_eval = analyze_url_heuristics(found_urls[0])
        score += int(url_eval["score"] * 0.6)
        for ind in url_eval["indicators"][:2]:
            indicators.append(ind)

    # Check social engineering pattern regexes
    for pattern, label, weight in SOCIAL_ENG_TRIGGERS:
        if re.search(pattern, clean_text, re.IGNORECASE):
            score += weight
            indicators.append({
                "name": label,
                "desc": "Matched deceptive psychological manipulation phrasing in message text.",
                "severity": "HIGH" if weight >= 20 else "MEDIUM"
            })

    final_score = min(score, 100)

    if final_score >= 81:
        level = "Critical"
    elif final_score >= 56:
        level = "High"
    elif final_score >= 26:
        level = "Medium"
    else:
        level = "Low"

    return {
        "score": final_score,
        "level": level,
        "indicators": indicators,
        "found_urls": found_urls
    }


def render_phishing_page() -> None:
    """Render the Phishing & Scam Detection interactive defensive console."""
    st.markdown("""
        <div class="module-header">
            <h2>🎣 Phishing & Scam Detection Console</h2>
            <p class="subtitle">Defensive heuristic inspection of candidate URLs, deceptive email bodies, and social engineering payloads.</p>
        </div>
    """, unsafe_allow_html=True)

    tab_url, tab_message, tab_defense_guide = st.tabs([
        "🔗 URL & Domain Scanner",
        "✉️ Email & Message Body Analyzer",
        "🛡️ Safety Advisory & Action Rules"
    ])

    current_user = st.session_state.get("username", "ANONYMOUS")

    # -----------------------------------------------------------------------
    # TAB 1: URL Scanner
    # -----------------------------------------------------------------------
    with tab_url:
        st.markdown("### 🔍 Target URL Diagnostic Probe")
        st.caption("Paste a candidate web address or domain to analyze its structural risk markers and deception signals.")


        target_url = st.text_input(
            "Target URL to Inspect",
            value=st.session_state.get("phish_url_val", ""),
            placeholder="e.g., http://192.168.1.1/login.php or https://paypal.com.verify-billing-update.xyz",
            key="input_phish_url"
        )

        col_btn_scan, col_btn_clear = st.columns([4, 1])
        with col_btn_scan:
            btn_scan_url = st.button("🛡️ Run URL Analysis", key="btn_scan_url", use_container_width=True)
        with col_btn_clear:
            if st.session_state.get("latest_url_scan_result"):
                if st.button("🔄 Clear Result", key="btn_clear_url_scan", use_container_width=True):
                    st.session_state.pop("latest_url_scan_result", None)
                    st.rerun()

        if btn_scan_url:
            sanitized_url = sanitize_input(target_url)
            if not sanitized_url:
                st.warning("⚠️ Please provide a URL or hostname to inspect.")
            else:
                with st.spinner("Executing multi-vector heuristic inspection..."):
                    result = analyze_url_heuristics(sanitized_url)
                    score = result["score"]
                    level = result["level"]
                    indicators = result["indicators"]

                    # Persist scan to SQLite
                    record_phishing_scan(
                        target_type="URL",
                        target_content=sanitized_url,
                        risk_score=score,
                        risk_level=level,
                        indicators_json=json.dumps(indicators),
                        user_id=current_user
                    )

                    # Log to Central Security Event Engine
                    is_high = level in ("High", "Critical")
                    log_phishing_analysis(
                        description=f"Target: {sanitized_url} | Risk: {score}/100 ({level}) | Indicators: {len(indicators)}",
                        is_high_risk=is_high,
                        user_id=current_user
                    )

                    # Store latest analysis persistently in session state
                    st.session_state["latest_url_scan_result"] = {
                        "target_url": sanitized_url,
                        "score": score,
                        "level": level,
                        "indicators": indicators
                    }

        # Render latest analysis persistently across Streamlit reruns
        url_scan_res = st.session_state.get("latest_url_scan_result")
        if url_scan_res:
            score = url_scan_res["score"]
            level = url_scan_res["level"]
            indicators = url_scan_res["indicators"]
            target_inspected = url_scan_res["target_url"]

            # Display Score and Badge
            st.markdown("<br>", unsafe_allow_html=True)
            res_c1, res_c2, res_c3 = st.columns(3)

            with res_c1:
                st.markdown(f"""
                    <div class="metric-card">
                        <div class="metric-label">Threat Risk Score</div>
                        <div class="metric-value" style="color: {'#DC2626' if score >= 56 else ('#D97706' if score >= 26 else '#0F766E')};">
                            {score} <span style="font-size: 1.0rem; color: #64748B;">/ 100</span>
                        </div>
                        <div class="metric-sub">Heuristic Calculation</div>
                    </div>
                """, unsafe_allow_html=True)

            with res_c2:
                badge_bg = "#FEE2E2" if level in ("High", "Critical") else ("#FEF3C7" if level == "Medium" else "#DCFCE7")
                badge_color = "#991B1B" if level in ("High", "Critical") else ("#92400E" if level == "Medium" else "#115E59")
                st.markdown(f"""
                    <div class="metric-card">
                        <div class="metric-label">Risk Classification</div>
                        <div style="margin-top: 8px;">
                            <span style="background: {badge_bg}; color: {badge_color}; padding: 6px 14px; border-radius: 6px; font-weight: 800; font-size: 1.1rem;">
                                {level.upper()} RISK
                            </span>
                        </div>
                        <div class="metric-sub" style="margin-top: 10px;">Defensive Category</div>
                    </div>
                """, unsafe_allow_html=True)

            with res_c3:
                st.markdown(f"""
                    <div class="metric-card">
                        <div class="metric-label">Detected Indicators</div>
                        <div class="metric-value">{len(indicators)}</div>
                        <div class="metric-sub">Structural Anomalies</div>
                    </div>
                """, unsafe_allow_html=True)

            st.markdown("<br>", unsafe_allow_html=True)

            # Heuristic vs Verified Reputation Distinction (Crucial Requirement)
            st.info(f"""
                ℹ️ **Diagnostic Transparency & Advisory (Inspected: `{target_inspected}`)**:
                This evaluation is produced via structural heuristic analysis and behavioral pattern matching.
                Heuristic analysis identifies abnormal threat indicators and does **not** claim or substitute for a verified domain reputation blacklist entry.
            """)

            # Breakdown of Detected Indicators
            st.markdown("#### 📋 Indicator Breakdown")
            if indicators:
                for ind in indicators:
                    sev = ind.get("severity", "MEDIUM")
                    sev_color = "#DC2626" if sev == "CRITICAL" else ("#B45309" if sev == "HIGH" else "#0F766E")
                    st.markdown(f"""
                        <div style="background: #FFFFFF; border: 1px solid #E8DFD0; border-left: 5px solid {sev_color}; border-radius: 6px; padding: 12px 16px; margin-bottom: 8px;">
                            <div style="display: flex; justify-content: space-between;">
                                <strong style="color: #0F172A;">{ind['name']}</strong>
                                <span style="font-size: 0.75rem; font-weight: 700; color: {sev_color};">[{sev}]</span>
                            </div>
                            <div style="color: #475569; font-size: 0.9rem; margin-top: 4px;">{ind['desc']}</div>
                        </div>
                    """, unsafe_allow_html=True)
            else:
                st.success("✅ No suspicious structural heuristics detected. The URL appears structurally standard.")

            # Recommended Safety Actions
            st.markdown("#### 🛡️ Recommended Safety Actions")
            if level in ("High", "Critical"):
                st.error("""
                    **Immediate Protective Steps:**
                    1. **DO NOT** click or open this link in a standard browser session.
                    2. **DO NOT** submit credentials, payment data, or OTP codes on pages originating from this address.
                    3. Never download or execute attached software from unverified servers.
                    4. Report the incident directly to campus IT or security administrators.
                """)
            elif level == "Medium":
                st.warning("""
                    **Cautionary Steps:**
                    1. Verify the link's legitimacy by navigating directly to the organization's official domain.
                    2. Inspect whether the domain has legitimate SSL certificates from recognized Certificate Authorities.
                    3. Verify sender credentials before proceeding.
                """)
            else:
                st.info("""
                    **Routine Hygiene Steps:**
                    - Confirm you expected communication from this service.
                    - Ensure multi-factor authentication (MFA) is enabled on your accounts.
                """)

    # -----------------------------------------------------------------------
    # TAB 2: Email & Message Analyzer
    # -----------------------------------------------------------------------
    with tab_message:
        st.markdown("### ✉️ Social Engineering & Message Payload Analyzer")
        st.caption("Paste suspicious email headers, SMS text, or chat messages to detect deception triggers and urgency manipulation.")

        # Quick prefill button for social engineering message demo
        if st.button("📋 Load Sample Phishing Email Demo", key="btn_sample_email"):
            st.session_state["phish_msg_val"] = (
                "Dear customer, unauthorized transaction detected on your campus account. "
                "Immediate action required! Your services will be suspended within 24 hours. "
                "Click here to verify your credentials: http://192.168.1.1/verify-account"
            )

        msg_input = st.text_area(
            "Paste Message Text / Email Content Here",
            value=st.session_state.get("phish_msg_val", ""),
            height=160,
            placeholder="e.g. Dear customer, unusual transaction observed on your account. Your services will be suspended within 24 hours...",
            key="input_phish_msg"
        )

        btn_scan_msg = st.button("🔎 Analyze Message Text", key="btn_scan_msg", use_container_width=True)

        if btn_scan_msg:
            sanitized_msg = sanitize_input(msg_input)
            if not sanitized_msg:
                st.warning("⚠️ Please paste message text to analyze.")
            else:
                with st.spinner("Scanning message for psychological coercion and threat markers..."):
                    res_msg = analyze_text_message(sanitized_msg)
                    score = res_msg["score"]
                    level = res_msg["level"]
                    indicators = res_msg["indicators"]

                    # Persist scan to SQLite
                    record_phishing_scan(
                        target_type="MESSAGE",
                        target_content=sanitized_msg[:200] + "...",
                        risk_score=score,
                        risk_level=level,
                        indicators_json=json.dumps(indicators),
                        user_id=current_user
                    )

                    # Log to Event Engine
                    log_phishing_analysis(
                        description=f"Message scanned | Risk: {score}/100 ({level}) | Triggers: {len(indicators)}",
                        is_high_risk=(level in ("High", "Critical")),
                        user_id=current_user
                    )

                    st.markdown("<br>", unsafe_allow_html=True)
                    m1, m2 = st.columns(2)
                    with m1:
                        st.metric("Social Engineering Risk Score", f"{score} / 100", delta=f"{level.upper()} RISK", delta_color="inverse")
                    with m2:
                        st.metric("Extracted Web Links", len(res_msg.get("found_urls", [])))

                    st.markdown("#### 🚨 Detected Psychological Manipulation Cues")
                    if indicators:
                        for ind in indicators:
                            st.markdown(f"- **{ind['name']}**: {ind['desc']}")
                    else:
                        st.success("✅ No urgent social engineering triggers or obvious coercion patterns identified.")

    # -----------------------------------------------------------------------
    # TAB 3: Defense Advisory & Guidelines
    # -----------------------------------------------------------------------
    with tab_defense_guide:
        st.markdown("""
            <div class="info-box">
                <h4>🛡️ Tactical Defense Checklist for Campus Operators</h4>
                <ul>
                    <li><strong>Never rely on link display text:</strong> Attackers often format visible text as <code>https://mybank.com</code> while hyperlinking to a deceptive third-party address.</li>
                    <li><strong>Look at the top-level domain:</strong> A genuine service like <code>google.com</code> is distinct from <code>google.com.attacker.xyz</code>.</li>
                    <li><strong>Beware artificial urgency:</strong> High-pressure deadlines ("within 1 hour") are the primary behavioral lever in 90% of scam campaigns.</li>
                    <li><strong>Zero Execution Policy:</strong> BACHAO+ analyzes patterns strictly without resolving malicious payload scripts or establishing interactive socket handshakes.</li>
                </ul>
            </div>
        """, unsafe_allow_html=True)
