from __future__ import annotations

import html
from pathlib import Path

import streamlit as st

from src.graph import advance_incident, prepare_current_action, reopen_action, run_incident
from src.state import IncidentIntake, IncidentState, RecoveryAction, Risk, Severity, ToolResult
from src.utils.images import ImageValidationError, NormalizedImage, normalize_uploads
from src.utils.llm import get_analysis_configuration


EXPOSURE_OPTIONS = {
    "Card or bank details": "card_details", "One-time password (OTP)": "otp",
    "Singpass details": "singpass_details", "Email or password": "email_password",
    "Identity information": "personal_information", "Not sure": "unsure",
}
CHANNEL_OPTIONS = {
    "Phone call": "phone_call", "WhatsApp": "whatsapp", "SMS": "sms", "Telegram": "telegram",
    "Website": "website", "Email": "email", "Social media": "social_media", "Other": "other",
}
SEVERITY_LABELS = {
    Severity.critical: ("Critical", "🔴"), Severity.high: ("High", "🟠"),
    Severity.medium: ("Medium", "🔵"), Severity.low: ("Low", "⚪"),
}
STATUS_LABELS = {"pending": "Pending", "prepared": "Guidance ready", "skipped": "Skipped", "completed": "Completed"}
ACTION_ICONS = {
    "prepare_bank_freeze": "💳", "prepare_singpass_security": "🪪", "prepare_email_security": "✉️",
    "create_evidence_summary": "📸", "prepare_police_report": "📄", "draft_contact_notification": "📣",
}
INTAKE_WIDGET_KEYS = (
    "intake_narrative", "intake_date_time", "intake_channels", "intake_impersonated", "intake_contact",
    "intake_url", "intake_bank", "intake_transfer", "intake_amount", "intake_discovery", "intake_actions",
    "intake_exposures", "intake_image_consent",
)


def load_styles() -> None:
    css = (Path(__file__).parent / "src" / "ui" / "styles.css").read_text(encoding="utf-8")
    st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)


def render_brandbar() -> None:
    state: IncidentState | None = st.session_state.get("incident")
    if not state:
        badge = "No active case"
    elif state.status == "completed":
        badge = f"Case {state.case_revision} · Complete"
    elif state.status == "needs_attention":
        badge = f"Case {state.case_revision} · Review needed"
    else:
        badge = f"Case {state.case_revision} · In progress"
    st.markdown(
        f'<div class="f30-brandbar"><div class="f30-brand"><span class="f30-mark">30</span> First30</div>'
        f'<div class="f30-case-badge">{html.escape(badge)}</div></div>', unsafe_allow_html=True,
    )


def section_intro(title: str, description: str) -> None:
    st.markdown(f'<div class="f30-card-title">{html.escape(title)}</div>', unsafe_allow_html=True)
    st.markdown(f'<div class="f30-card-help">{html.escape(description)}</div>', unsafe_allow_html=True)


def restore_intake_draft() -> None:
    for key, value in st.session_state.get("intake_draft", {}).items():
        if key not in st.session_state:
            st.session_state[key] = value


def save_intake_draft() -> None:
    st.session_state.intake_draft = {
        key: st.session_state.get(key) for key in INTAKE_WIDGET_KEYS if key in st.session_state
    }


def action_reason(state: IncidentState, action: RecoveryAction) -> str:
    if action.tool_name == "prepare_singpass_security":
        return "Singpass-related access or an identity-verification OTP was identified, so identity containment is the first priority."
    if action.tool_name == "prepare_bank_freeze":
        return "Bank/card exposure, a financial OTP, or a reported transfer creates an immediate financial-loss risk."
    if action.tool_name == "prepare_email_security":
        return "An exposed email account can reset other accounts and conceal security alerts."
    if action.tool_name == "create_evidence_summary":
        return "Original files and a clear timeline can disappear or be altered, so preserve them before reporting."
    if action.tool_name == "prepare_police_report":
        return "The incident can be organised into the fields used by the official SPF reporting flow."
    return "Exposed identity or account details can be used for impersonation, so trusted contacts may need a warning."


def result_for_action(state: IncidentState, action: RecoveryAction) -> ToolResult | None:
    return next((result for result in reversed(state.tool_results) if result.action == action.tool_name), None)


def copyable_text(label: str, value: str, key: str, height: int = 150) -> None:
    safe_id = "copy_" + "".join(character if character.isalnum() else "_" for character in key)
    safe_class = f"copy_card_{safe_id}"
    st.html(
        f"""<style>.{safe_class}{{margin:.25rem 0 1rem;font-family:system-ui,-apple-system,sans-serif;color:#17324d}}.{safe_class} .label{{font-size:14px;font-weight:650;margin-bottom:7px}}.{safe_class} textarea{{box-sizing:border-box;width:100%;height:{height}px;resize:vertical;padding:12px;border:1px solid #cbd8e2;border-radius:10px;background:#fff;color:#17324d;font:14px/1.45 system-ui,-apple-system,sans-serif}}.{safe_class} textarea:focus{{outline:3px solid #9bc8e4;border-color:#1769aa}}.{safe_class} button{{margin-top:7px;border:1px solid #b8c9d6;border-radius:8px;background:#fff;color:#17324d;padding:7px 12px;font-weight:650;cursor:pointer}}</style>
        <div class="{safe_class}"><div class="label">{html.escape(label)}</div><textarea id="{safe_id}">{html.escape(value)}</textarea>
        <button onclick="navigator.clipboard.writeText(document.getElementById('{safe_id}').value);this.textContent='Copied'">Copy text</button></div>""",
        unsafe_allow_javascript=True,
    )


def report_fields(metadata: dict[str, str], revision: int) -> None:
    st.markdown(f"**Suggested entries for the SPF {metadata.get('report_type', 'scam')} form**")
    st.caption("Review these against your records. Missing details are labelled instead of invented.")
    labels = {
        "field_when_where": "When and where it happened", "field_what_happened": "Description of what happened",
        "field_discovery": "How the incident was discovered", "field_money_transactions": "Transactions or money involved",
        "field_items_involved": "Items or information involved", "field_victims": "Victims involved",
        "field_suspects": "Suspects involved", "field_attachments": "Attachments to prepare",
    }
    for field, label in labels.items():
        copyable_text(label, metadata.get(field, "Not recorded"), f"r{revision}_{field}", 100 if field == "field_what_happened" else 74)


def render_artifact(state: IncidentState, action: RecoveryAction, result: ToolResult) -> None:
    metadata = result.metadata
    st.success("Guidance prepared locally. Nothing has been submitted, sent, or changed in an external account.")
    official_url = metadata.get("official_guidance_url") or metadata.get("official_contact_url") or metadata.get("official_report_url")
    if metadata.get("contact_route"):
        st.info(metadata["contact_route"])
    if metadata.get("support_note"):
        st.info(metadata["support_note"])
    if official_url:
        st.link_button("Open official service", official_url, use_container_width=True)
    if metadata.get("security_checklist"):
        st.markdown("**Account-security checklist**")
        for item in metadata["security_checklist"].split("; "):
            st.markdown(f"- {item.strip().rstrip('.')}.")
    if metadata.get("call_script"):
        copyable_text("Suggested support script", metadata["call_script"], f"r{state.case_revision}_{action.id}_script")
    if action.tool_name == "create_evidence_summary":
        st.markdown("**How to preserve evidence**")
        for step in metadata.get("preservation_steps", "").splitlines():
            st.markdown(f"- {step}")
        st.caption(f"Already mentioned: {metadata.get('evidence_available', 'None identified yet')}.")
    if action.tool_name == "prepare_police_report":
        report_fields(metadata, state.case_revision)
    if metadata.get("content"):
        copyable_text("Editable message draft", metadata["content"], f"r{state.case_revision}_{action.id}_message", 175)


def risk_evidence(state: IncidentState, risk: Risk) -> list[str]:
    evidence: list[str] = []
    label = next((label for label, value in EXPOSURE_OPTIONS.items() if value == risk.source_exposure), risk.source_exposure)
    if risk.source_exposure in state.selected_exposures:
        evidence.append(f"You selected “{label}” in the intake form.")
    if risk.source_exposure == "singpass_details" and state.facts.otp_context == "singpass":
        evidence.append("The OTP context was identified as Singpass or identity verification.")
    if risk.source_exposure == "card_details" and state.facts.money_transferred == "yes":
        evidence.append("You reported that money was transferred.")
    evidence.extend(state.facts.risk_evidence.get(risk.source_exposure, [])[:2])
    evidence.extend(state.facts.image_observations[:2])
    return evidence or ["The category was identified from the incident narrative."]


@st.dialog("Risk details", width="large")
def risk_dialog(state: IncidentState, risk: Risk) -> None:
    label, icon = SEVERITY_LABELS[risk.severity]
    st.markdown(f"## {icon} {risk.title}")
    st.markdown(f"**Severity: {label}**")
    st.write(risk.rationale)
    st.markdown("**Why this risk was identified**")
    for item in risk_evidence(state, risk):
        st.markdown(f"- {item}")
    st.markdown("**Affected information**")
    st.write(risk.source_exposure.replace("_", " ").title())
    st.markdown("**Uncertainty**")
    uncertainty = list(dict.fromkeys([*state.facts.needs_review, *state.facts.uncertainties]))
    if uncertainty:
        for item in uncertainty:
            st.warning(item)
    else:
        st.caption("No specific conflict was identified. Confirm the assessment against your own records.")


@st.dialog("ScamShield guidance", width="large")
def scamshield_dialog() -> None:
    st.markdown("## Official ScamShield support")
    st.write("Use ScamShield to check suspicious messages and get guidance. If money or account access is at risk, also use the relevant bank, Singpass, email-provider, and police routes in your plan.")
    st.info("Call 1799 if you are unsure whether something is a scam or need scam-related guidance.")
    st.link_button("Open ScamShield: I have been scammed", "https://www.scamshield.gov.sg/i-have-been-scammed/", use_container_width=True)


@st.dialog("Recovery step", width="large")
def action_dialog(state: IncidentState, action_id: str) -> None:
    action = next(item for item in state.actions if item.id == action_id)
    st.markdown(f"## {ACTION_ICONS.get(action.tool_name, '✓')} {action.title}")
    st.info(f"Why this step is included: {action_reason(state, action)}")
    st.caption("Never enter passwords, OTPs, PINs, recovery codes, or full card numbers into First30.")
    if action.status == "skipped":
        st.warning("This step is skipped and still prevents the plan from reaching 100%.")
        if st.button("Reopen this step", type="primary", use_container_width=True, key=f"reopen_{state.case_revision}_{action.id}"):
            st.session_state.incident = reopen_action(state, action.id)
            st.rerun()
        return

    result = result_for_action(state, action)
    if action.status in {"prepared", "completed"} and result:
        render_artifact(state, action, result)
    elif action.id == state.current_action_id:
        prepared_state = state.model_copy(deep=True)
        if action.tool_name == "prepare_bank_freeze":
            banks = ["I don't know yet", "DBS / POSB", "OCBC", "UOB"]
            initial = prepared_state.selected_bank if prepared_state.selected_bank in banks else "I don't know yet"
            selected = st.selectbox("Affected bank", banks, index=banks.index(initial), key=f"bank_r{state.case_revision}_{action.id}")
            prepared_state.selected_bank = "" if selected == "I don't know yet" else selected
        if action.tool_name == "draft_contact_notification":
            prepared_state.notification_channel = st.selectbox("Message channel", ["WhatsApp", "SMS", "Telegram", "Email"], key=f"channel_r{state.case_revision}_{action.id}")
        if st.button("Prepare tailored guidance", type="primary", use_container_width=True, key=f"prepare_r{state.case_revision}_{action.id}"):
            st.session_state.incident = prepare_current_action(prepared_state)
            st.rerun()
        return
    elif action.status == "pending":
        st.caption("This step is upcoming. Complete or skip the current-priority step first.")

    if action.status == "completed":
        st.success("You confirmed this step as completed.")
        return
    if action.status == "prepared" and action.id == state.current_action_id:
        complete_label = "I completed this external step" if action.requires_confirmation else "I reviewed and completed this step"
        complete, skip = st.columns(2)
        if complete.button(complete_label, type="primary", use_container_width=True, key=f"complete_r{state.case_revision}_{action.id}"):
            st.session_state.incident = advance_incident(state, completed_action_ids=[action.id])
            st.rerun()
        if skip.button("Skip for now", use_container_width=True, key=f"skip_r{state.case_revision}_{action.id}"):
            st.session_state.incident = advance_incident(state, skipped_action_ids=[action.id])
            st.rerun()


@st.dialog("Developer details")
def developer_dialog(state: IncidentState) -> None:
    config = get_analysis_configuration()
    st.markdown("**Analysis configuration**")
    st.write(f"Provider: {str(config['provider']).title()}")
    st.write(f"Model: {config['model']}")
    st.write(f"Mode used: {state.assessment_source.replace('_', ' ')}")
    st.write(f"Screenshots supplied: {len(state.image_metadata)}")
    if state.image_metadata:
        st.write(f"Screenshot status: {'Analysed' if state.images_analyzed else 'Not analysed'}")
    st.write(f"Case revision: {state.case_revision}")
    if state.analysis_warning:
        st.warning(state.analysis_warning)
    elif state.assessment_source == "curated_rules_plus_llm":
        st.success("The structured model assessment completed successfully.")
    else:
        st.info("This case used the local curated assessment.")


def incident_details_page() -> None:
    restore_intake_draft()
    render_brandbar()
    st.markdown('<div class="f30-eyebrow">Incident intake</div>', unsafe_allow_html=True)
    st.title("Tell us what happened")
    st.markdown('<div class="f30-lead">Share what you know. Only the incident description is required; every other field can be left blank.</div>', unsafe_allow_html=True)
    st.warning("Do not type passwords, OTP values, PINs, recovery codes, or full card numbers.")
    with st.container(border=True):
        section_intro("What happened", "Describe the sequence in your own words. Use at least 30 non-whitespace characters.")
        narrative = st.text_area("Incident description", key="intake_narrative", height=180, placeholder="For example: A caller claimed to be from the police and asked me to verify my Singpass account...")
        count = len("".join(narrative.split()))
        st.caption(f"{count} / 30 minimum characters")
    with st.container(border=True):
        section_intro("Incident context", "Optional details help tailor the plan and pre-fill reporting guidance.")
        first, second = st.columns(2)
        with first:
            incident_date_time = st.text_input("Approximate date and time", key="intake_date_time", placeholder="e.g. 6 Sep 2026, around 2:30 pm")
            scam_channel_labels = st.multiselect("Scam channel(s)", list(CHANNEL_OPTIONS), key="intake_channels")
            impersonated = st.text_input("Impersonated organisation or person", key="intake_impersonated", placeholder="e.g. Singapore Police Force")
            suspicious_contact = st.text_input("Suspicious phone, email, or username", key="intake_contact")
            suspicious_url = st.text_input("Suspicious website or profile URL", key="intake_url")
        with second:
            bank_provider = st.text_input("Affected bank or service provider", key="intake_bank", placeholder="e.g. DBS / POSB, Singpass, Gmail")
            transfer_label = st.selectbox("Was money transferred?", ["Not sure", "No", "Yes"], key="intake_transfer")
            amount = st.text_input("Amount and currency, if relevant", key="intake_amount", placeholder="e.g. S$250")
            discovery = st.text_area("How did you discover it?", key="intake_discovery", height=92)
            actions_taken = st.text_area("Actions already taken", key="intake_actions", height=92, placeholder="e.g. ended the call and changed my password")
    with st.container(border=True):
        section_intro("Information exposed", "Select every category that might be involved. Choose “Not sure” if unclear.")
        exposure_labels = st.pills("Exposure categories", list(EXPOSURE_OPTIONS), selection_mode="multi", key="intake_exposures", label_visibility="collapsed") or []
    with st.container(border=True):
        section_intro("Evidence screenshots", "Optional. Add up to five PNG, JPG, or WebP images; 5 MB each and 20 MB total.")
        upload_nonce = int(st.session_state.get("intake_upload_nonce", 0))
        uploads = st.file_uploader("Upload screenshots", type=["png", "jpg", "jpeg", "webp"], accept_multiple_files=True, key=f"intake_uploads_{upload_nonce}", label_visibility="collapsed")
        persisted_images: list[NormalizedImage] = st.session_state.get("intake_draft_images", [])
        normalised: list[NormalizedImage] = list(persisted_images)
        upload_error = ""
        if uploads:
            try:
                newly_normalised = normalize_uploads(uploads)
                unique = {(item.name, item.data): item for item in [*persisted_images, *newly_normalised]}
                normalised = list(unique.values())
                if len(normalised) > 5:
                    raise ImageValidationError("Upload no more than 5 screenshots.")
                if sum(len(item.data) for item in normalised) > 20 * 1024 * 1024:
                    raise ImageValidationError("Screenshots exceed the 20 MB total limit.")
            except ImageValidationError as exc:
                upload_error = str(exc)
                st.error(upload_error)
        if normalised:
            preview_columns = st.columns(min(3, len(normalised)))
            for index, image in enumerate(normalised):
                with preview_columns[index % len(preview_columns)]:
                    st.image(image.data, use_container_width=True)
                    st.caption(f"{image.name} · {len(image.data) / 1024:.0f} KB")
                    if st.button("Remove", key=f"remove_image_{upload_nonce}_{index}", use_container_width=True):
                        st.session_state.intake_draft_images = [item for position, item in enumerate(normalised) if position != index]
                        st.session_state.intake_upload_nonce = upload_nonce + 1
                        st.rerun()
            st.markdown('<div class="f30-privacy"><strong>Privacy notice:</strong> these images stay in this Streamlit session, but will be sent to AWS Bedrock for analysis. Crop or redact passwords, OTP values, PINs, full card numbers, and unrelated personal information.</div>', unsafe_allow_html=True)
            image_consent = st.checkbox("I have reviewed the screenshots and agree to send them to AWS Bedrock for this analysis.", key="intake_image_consent")
        else:
            image_consent = False

    if not upload_error:
        st.session_state.intake_draft_images = normalised
    save_intake_draft()

    config = get_analysis_configuration()
    image_model_error = ""
    if normalised and (config["provider"] != "bedrock" or not config["image_capable"]):
        image_model_error = "Screenshot analysis requires AWS Bedrock with an image-capable Amazon Nova Lite, Pro, or Premier model. Update the configuration or remove the screenshots."
        st.error(image_model_error)
    elif normalised and not config["credentials_available"]:
        st.info("Bedrock credentials are not detected. You can submit safely, but screenshots will be marked “Not analysed” and the written-details fallback will be used.")
    disabled = count < 30 or bool(upload_error) or bool(image_model_error) or (bool(normalised) and not image_consent)
    if st.button("Analyse incident and build my plan", type="primary", use_container_width=True, disabled=disabled, key="submit_incident"):
        transfer = {"Yes": "yes", "No": "no", "Not sure": "unknown"}[transfer_label]
        intake = IncidentIntake(
            narrative=narrative.strip(), incident_date_time=incident_date_time.strip(),
            scam_channels=[CHANNEL_OPTIONS[label] for label in scam_channel_labels],
            impersonated_organisation=impersonated.strip(), suspicious_contact=suspicious_contact.strip(),
            suspicious_url=suspicious_url.strip(), bank_or_provider=bank_provider.strip(), money_transfer_status=transfer,
            amount=amount.strip(), discovery_method=discovery.strip(), actions_already_taken=actions_taken.strip(),
            exposure_tags=[EXPOSURE_OPTIONS[label] for label in exposure_labels],
        )
        revision = int(st.session_state.get("case_revision", 0)) + 1
        with st.spinner("Analysing the incident and building a safe response plan..."):
            st.session_state.incident = run_incident(
                intake.narrative, selected_exposures=intake.exposure_tags, use_llm=True,
                intake=intake, images=normalised, case_revision=revision,
            )
        st.session_state.case_revision = revision
        st.switch_page(DASHBOARD_PAGE)


def render_progress_hero(state: IncidentState) -> None:
    total = len(state.actions)
    completed = sum(action.status == "completed" for action in state.actions)
    percent = round((completed / total) * 100) if total else 0
    current = next((action.title for action in state.actions if action.id == state.current_action_id), "Review skipped steps" if state.skipped_action_ids else "No remaining step")
    segments = "".join(
        f'<span class="f30-segment {html.escape(action.status if action.status in {"completed", "skipped"} else "current" if action.id == state.current_action_id else "")}"></span>'
        for action in state.actions
    )
    status = "Plan completed" if percent == 100 else "Skipped steps need review" if state.skipped_action_ids else "Response in progress"
    success_class = " success" if percent == 100 else ""
    st.markdown(
        f'<div class="f30-hero{success_class}"><div class="f30-hero-row"><div><div class="f30-eyebrow">{status}</div>'
        f'<h2>{completed} of {total} required steps completed</h2><div>Current priority: <strong>{html.escape(current)}</strong></div></div>'
        f'<div class="f30-percent">{percent}%</div></div><div class="f30-segments" style="--segments:{max(total, 1)}">{segments}</div></div>',
        unsafe_allow_html=True,
    )


def response_dashboard_page() -> None:
    render_brandbar()
    state: IncidentState | None = st.session_state.get("incident")
    if not state:
        st.markdown('<div class="f30-eyebrow">Response dashboard</div>', unsafe_allow_html=True)
        st.title("No response plan yet")
        st.write("Describe the incident first. Your risk assessment and recovery steps will appear here.")
        if st.button("Go to Incident Details", type="primary"):
            st.switch_page(INCIDENT_PAGE)
        return
    render_progress_hero(state)
    if state.analysis_warning:
        st.warning(state.analysis_warning)
    st.markdown('<h2 class="f30-section-head">Risks identified</h2><div class="f30-section-copy">Open a tile to see supporting evidence and uncertainty.</div>', unsafe_allow_html=True)
    risk_columns = st.columns(3)
    for index, risk in enumerate(state.risks):
        label, icon = SEVERITY_LABELS[risk.severity]
        with risk_columns[index % 3]:
            if st.button(f"{icon}  {label.upper()}\n\n{risk.title}\n\nOpen risk details →", key=f"risk_tile_{risk.severity.value}_{state.case_revision}_{risk.id}", use_container_width=True):
                risk_dialog(state, risk)
    st.markdown('<h2 class="f30-section-head">Official support</h2><div class="f30-section-copy">ScamShield guidance remains available throughout your response.</div>', unsafe_allow_html=True)
    support_col, _ = st.columns([1, 2])
    with support_col:
        if st.button("🛡️  SCAMSHIELD\n\nOfficial scam guidance and 1799 helpline\n\nOpen guidance →", key=f"scamshield_tile_{state.case_revision}", use_container_width=True):
            scamshield_dialog()
    st.markdown('<h2 class="f30-section-head">Your First30 plan</h2><div class="f30-section-copy">Open the current step, prepare its guidance, then confirm what you completed yourself.</div>', unsafe_allow_html=True)
    step_columns = st.columns(2)
    for index, action in enumerate(state.actions, start=1):
        current = action.id == state.current_action_id
        status = STATUS_LABELS.get(action.status, action.status.title())
        key_status = "current" if current else action.status
        with step_columns[(index - 1) % 2]:
            if st.button(
                f"{ACTION_ICONS.get(action.tool_name, '✓')}  STEP {index} · {status.upper()}\n\n{action.title}\n\n{action.description}",
                key=f"step_tile_{key_status}_{state.case_revision}_{action.id}", use_container_width=True,
            ):
                action_dialog(state, action.id)
    st.divider()
    if st.button("Developer details", key=f"developer_{state.case_revision}"):
        developer_dialog(state)
    st.caption("Prototype only. First30 does not access accounts, submit reports, upload evidence to official services, or send messages.")


st.set_page_config(page_title="First30", page_icon="🛡️", layout="wide", initial_sidebar_state="collapsed")
load_styles()
INCIDENT_PAGE = st.Page(incident_details_page, title="Incident Details", icon="📝", default=True)
DASHBOARD_PAGE = st.Page(response_dashboard_page, title="Response Dashboard", icon="📊")
navigation = st.navigation([INCIDENT_PAGE, DASHBOARD_PAGE], position="top")
navigation.run()
