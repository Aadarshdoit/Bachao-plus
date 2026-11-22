"""
BACHAO+ Campus Safety & Incident Overwatch Module
Handles physical campus security, emergency SOS panic broadcasts, role-based incident reporting,
and real-time incident lifecycle management for campus officers.
"""

import os
from pathlib import Path
import streamlit as st
from database.db import (
    create_campus_incident,
    get_campus_incidents,
    update_incident_status,
    UPLOADS_DIR
)
from utils.event_logger import log_emergency_sos, log_incident_resolution, SecurityEventEngine
from utils.security import sanitize_input, validate_uploaded_file

# Verified incident categories
INCIDENT_CATEGORIES = [
    "Medical Emergency",
    "Harassment",
    "Suspicious Activity",
    "Theft",
    "Accident",
    "Other"
]

# Standard campus zones for quick SOS and location tags
CAMPUS_ZONES = [
    "North Gate - Sector Alpha",
    "Science & Engineering Quad",
    "Main Library & Central Annex",
    "Student Hostel Complex A",
    "Student Hostel Complex B",
    "Sports Ground & Gymnasium",
    "Cafeteria & Student Center",
    "Perimeter Fence West",
    "Administrative Block",
    "Other / Unlisted Location"
]

# Standard Incident Status Workflow
STATUS_WORKFLOW = ["Submitted", "Acknowledged", "In Progress", "Resolved"]


def render_campus_safety_page() -> None:
    """Render the Campus Safety & Incident Overwatch module."""
    st.markdown("""
        <div class="module-header">
            <h2>🏫 Campus Safety & Perimeter Overwatch</h2>
            <p class="subtitle">Real-time zone monitoring, emergency distress signal routing, and security incident dispatch.</p>
        </div>
    """, unsafe_allow_html=True)

    # User context and role resolution
    is_authenticated = st.session_state.get("authenticated", False)
    current_user = st.session_state.get("username", "Guest_User")
    current_role = st.session_state.get("role", "Student" if is_authenticated else "Guest")
    is_staff = current_role in ("Campus Security", "Admin")

    tab_sos, tab_submit, tab_history, tab_officer = st.tabs([
        "🚨 Emergency SOS Panic",
        "📝 Submit Incident Report",
        "📂 My Reported Incidents",
        "👮 Security Officer Terminal" if is_staff else "🔒 Security Terminal (Restricted)"
    ])

    # -----------------------------------------------------------------------
    # TAB 1: Emergency SOS Panic Button
    # -----------------------------------------------------------------------
    with tab_sos:
        st.markdown("### 🚨 Emergency Distress Broadcast")

        # Explicit Statutory Notice Required by Specifications
        st.error("""
            ⚠️ **CRITICAL PLATFORM NOTICE**:
            Activating this Emergency SOS initiates an instantaneous high-priority dispatch alert to on-duty **Campus Security personnel within this platform**.
            **It does NOT automatically contact municipal police (112 / 911), fire departments, or civil emergency services.**
            If you are in immediate life-threatening physical peril, dial municipal emergency numbers (112) directly.
        """)

        col_sos_box, col_sos_info = st.columns([3, 2])

        with col_sos_box:
            st.markdown("""
                <div style="background: #FFFFFF; border: 2px solid #DC2626; border-radius: 10px; padding: 20px; text-align: center;">
                    <div style="font-size: 1.1rem; font-weight: 800; color: #DC2626; margin-bottom: 8px;">
                        IMMEDIATE DISTRESS DISPATCH
                    </div>
                    <div style="color: #64748B; font-size: 0.9rem; margin-bottom: 14px;">
                        Broadcasts your location ping directly to campus patrol units.
                    </div>
                </div>
            """, unsafe_allow_html=True)

            sos_zone = st.selectbox("Select Your Current Campus Zone", CAMPUS_ZONES, key="sos_zone_select")
            sos_notes = st.text_input("Quick Details / Landmark (Optional)", placeholder="e.g. Near Stairwell 2, 3rd Floor", key="sos_quick_notes")

            btn_sos_trigger = st.button("🚨 TRIGGER EMERGENCY SOS", type="primary", use_container_width=True)

            if btn_sos_trigger:
                details_text = f"SOS Triggered at {sos_zone}."
                if sos_notes.strip():
                    details_text += f" Notes: {sanitize_input(sos_notes)}"

                sos_username = current_user if is_authenticated else "Anonymous_Distress"

                incident_id = create_campus_incident(
                    username=sos_username,
                    category="Medical Emergency" if "medical" in sos_notes.lower() else "Suspicious Activity",
                    description=details_text,
                    location=sos_zone,
                    is_sos=True,
                    user_id=st.session_state.get("user_id")
                )

                # Log to Central Event Engine
                log_emergency_sos(zone=sos_zone, user_id=sos_username)

                st.success(f"🚨 **DISTRESS SIGNAL BROADCASTED!** Incident ID: `{incident_id}`")
                st.info("Campus security control room has received your location ping and dispatched nearest personnel.")

        with col_sos_info:
            st.markdown("""
                <div class="info-box">
                    <h4>Campus Emergency Direct Hotlines</h4>
                    <p style="font-size: 0.9rem; color: #475569;">Save these direct numbers for offline situations:</p>
                    <ul style="font-size: 0.9rem; line-height: 1.6;">
                        <li><strong>Campus Security Control Room:</strong> +91 11-2345-6789</li>
                        <li><strong>Campus Medical Center:</strong> +91 11-2345-6700</li>
                        <li><strong>Women's Safety Helpline:</strong> 1091 / Internal: Ext 404</li>
                        <li><strong>National Emergency Responder:</strong> 112</li>
                    </ul>
                </div>
            """, unsafe_allow_html=True)

    # -----------------------------------------------------------------------
    # TAB 2: Submit Incident Report Form
    # -----------------------------------------------------------------------
    with tab_submit:
        st.markdown("### 📝 Incident Report Submission")
        st.caption("Submit non-distress safety concerns, observed disturbances, equipment damage, or security issues.")

        if not is_authenticated:
            st.info("💡 **Tip**: You are currently submitting as Guest. Sign in under **Secure Access** to track your report progress.")

        with st.form("incident_report_form", clear_on_submit=True):
            col_c1, col_c2 = st.columns(2)
            with col_c1:
                category = st.selectbox("Incident Category *", INCIDENT_CATEGORIES)
            with col_c2:
                location = st.selectbox("Campus Location *", CAMPUS_ZONES)

            custom_loc = st.text_input("Specific Room / Landmark (Optional)", placeholder="e.g., Room 304, South Wing")
            description = st.text_area(
                "Incident Description *",
                height=130,
                placeholder="Provide accurate, factual details of what occurred, individuals involved, and current situation..."
            )

            evidence_file = st.file_uploader(
                "Optional Photographic Evidence (PNG, JPG, max 5MB - Magic-bytes verified)",
                type=["png", "jpg", "jpeg"]
            )

            submit_report = st.form_submit_button("📤 Submit Incident to Security Desk", use_container_width=True)

            if submit_report:
                clean_desc = sanitize_input(description)
                if not clean_desc:
                    st.error("⚠️ Please provide an incident description.")
                else:
                    # Validate optional image with magic bytes verification
                    is_valid_file, file_err = validate_uploaded_file(evidence_file, max_size_mb=5.0)
                    if not is_valid_file:
                        st.error(f"⚠️ {file_err}")
                    else:
                        saved_img_path = None
                        if evidence_file is not None:
                            try:
                                UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
                                ext = os.path.splitext(evidence_file.name)[1].lower()
                                filename = f"evidence_{st.session_state.get('user_id', 0)}_{os.urandom(4).hex()}{ext}"
                                full_path = UPLOADS_DIR / filename
                                with open(full_path, "wb") as f:
                                    f.write(evidence_file.getbuffer())
                                saved_img_path = str(full_path)
                            except Exception as e:
                                st.warning(f"Note: Could not save image evidence ({e}), proceeding with report submission.")

                        loc_str = location
                        if custom_loc.strip():
                            loc_str = f"{location} ({sanitize_input(custom_loc)})"

                        reporter_username = current_user if is_authenticated else "Guest_Reporter"

                        inc_id = create_campus_incident(
                            username=reporter_username,
                            category=category,
                            description=clean_desc,
                            location=loc_str,
                            image_path=saved_img_path,
                            is_sos=False,
                            user_id=st.session_state.get("user_id")
                        )

                        # Log event
                        SecurityEventEngine.log(
                            event_type="CAMPUS_INCIDENT_REPORTED",
                            severity="MEDIUM" if category in ("Theft", "Accident") else "HIGH",
                            category="CAMPUS_SAFETY",
                            description=f"Incident {inc_id} ({category}) submitted at {loc_str}",
                            user_id=reporter_username
                        )

                        st.success(f"✅ Incident registered under ID: `{inc_id}` with status **Submitted**.")

    # -----------------------------------------------------------------------
    # TAB 3: My Reported Incidents (Student Privacy Protection)
    # -----------------------------------------------------------------------
    with tab_history:
        if not is_authenticated:
            st.warning("🔒 **Authentication Required**: Please sign in to view and track your private submitted incident reports.")
            st.info("Enforcing student privacy: Incident records are confidential and accessible only to their authenticated author.")
        else:
            st.markdown(f"### 📂 Confidential Incident Tracking for **{current_user}**")
            my_reports = get_campus_incidents(username=current_user, is_admin=False)

            if not my_reports:
                st.info("You have not submitted any incidents yet.")
            else:
                for report in my_reports:
                    st_val = report["status"]
                    st_color = "#0F766E" if st_val == "Resolved" else ("#B45309" if st_val in ("In Progress", "Acknowledged") else "#DC2626")
                    sos_badge = "🚨 [EMERGENCY SOS] " if report["is_sos"] else ""

                    st.markdown(f"""
                        <div style="background: #FFFFFF; border: 1px solid #E5DCCE; border-left: 5px solid {st_color}; border-radius: 8px; padding: 14px 18px; margin-bottom: 12px;">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <div>
                                    <span style="font-weight: 800; color: #0F172A; font-size: 1.05rem;">{sos_badge}{report['category']}</span>
                                    <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; background: #FAF7F2; padding: 2px 6px; border-radius: 4px; margin-left: 8px;">{report['incident_id']}</span>
                                </div>
                                <span style="font-weight: 700; color: {st_color}; font-size: 0.9rem;">Status: {st_val}</span>
                            </div>
                            <div style="font-size: 0.85rem; color: #64748B; margin: 4px 0;">
                                📍 {report['location']} • 🕒 {report['created_at']}
                            </div>
                            <div style="color: #334155; font-size: 0.95rem; margin-top: 8px;">
                                {report['description']}
                            </div>
                            {f'<div style="background: #F8F5EE; border-radius: 4px; padding: 8px 12px; margin-top: 8px; font-size: 0.85rem;"><strong>Officer Remarks ({report.get("resolved_by", "Staff")}):</strong> {report["resolution_notes"]}</div>' if report.get("resolution_notes") else ''}
                        </div>
                    """, unsafe_allow_html=True)

    # -----------------------------------------------------------------------
    # TAB 4: Officer Terminal (Security / Admin only)
    # -----------------------------------------------------------------------
    with tab_officer:
        if not is_staff:
            st.warning("🔒 **Access Restricted**: The Incident Overwatch Terminal requires **Campus Security** or **Admin** clearance.")
            st.info(f"Your current clearance: **{current_role}**. Authorize or sign in via the **Secure Access** module.")
        else:
            st.markdown("### 👮 Campus Security Overwatch Command Console")
            st.caption("Authorized security personnel interface to review all reports and manage resolution lifecycles.")

            all_incidents = get_campus_incidents(is_admin=True)

            # Filter controls
            f_col1, f_col2 = st.columns(2)
            with f_col1:
                status_filter = st.selectbox("Filter by Status", ["All Incidents"] + STATUS_WORKFLOW)
            with f_col2:
                cat_filter = st.selectbox("Filter by Category", ["All Categories"] + INCIDENT_CATEGORIES)

            filtered = all_incidents
            if status_filter != "All Incidents":
                filtered = [i for i in filtered if i["status"] == status_filter or (status_filter == "Submitted" and i["status"] == "Reported")]
            if cat_filter != "All Categories":
                filtered = [i for i in filtered if i["category"] == cat_filter]

            st.markdown(f"**Showing {len(filtered)} Incident Records Across Campus:**")

            if not filtered:
                st.info("No incidents matching the active filter criteria.")

            for inc in filtered:
                with st.expander(f"[{inc['status'].upper()}] {inc['incident_id']} - {inc['category']} ({inc['location']})", expanded=(inc['status'] in ('Submitted', 'Reported'))):
                    st.markdown(f"**Reported By:** `{inc['username']}` | **Timestamp:** {inc['created_at']}")
                    st.markdown(f"**Location:** {inc['location']}")
                    st.markdown(f"**Details:** {inc['description']}")

                    if inc.get("image_path") and os.path.exists(inc["image_path"]):
                        st.image(inc["image_path"], caption="Photographic Evidence Attached", width=320)

                    st.markdown("---")
                    st.markdown("#### Update Incident Status")

                    with st.form(f"update_form_{inc['incident_id']}"):
                        curr_stat = inc["status"]
                        # Map legacy 'Reported' to 'Submitted'
                        curr_stat_norm = "Submitted" if curr_stat == "Reported" else curr_stat
                        stat_idx = STATUS_WORKFLOW.index(curr_stat_norm) if curr_stat_norm in STATUS_WORKFLOW else 0

                        new_stat = st.selectbox(
                            "Transition Status To",
                            STATUS_WORKFLOW,
                            index=stat_idx
                        )
                        notes = st.text_input("Officer Action / Resolution Remarks", value=inc.get("resolution_notes") or "")
                        btn_update = st.form_submit_button("💾 Save Status Update", use_container_width=True)

                        if btn_update:
                            update_incident_status(
                                incident_id=inc["incident_id"],
                                new_status=new_stat,
                                resolved_by=current_user,
                                notes=notes
                            )

                            # Log event
                            if new_stat == "Resolved":
                                log_incident_resolution(inc["incident_id"], current_user)
                            else:
                                SecurityEventEngine.log(
                                    "INCIDENT_STATUS_UPDATED", "INFO", "CAMPUS_SAFETY",
                                    f"Incident {inc['incident_id']} moved to {new_stat} by {current_user}",
                                    current_user
                                )

                            st.success(f"Status for {inc['incident_id']} updated to {new_stat}!")
                            st.rerun()
