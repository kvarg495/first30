from __future__ import annotations

import html
from pathlib import Path

import streamlit as st

from src.graph import advance_incident, prepare_current_action, reopen_action, run_incident
from src.data.singapore_guidance import OFFICIAL_HANDOFFS
from src.state import ExposureFinding, IncidentIntake, IncidentState, RecoveryAction, Risk, Severity, ToolResult
from src.ui.checklists import render_checklist
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
    Severity.critical: ("Critical", ":material/error:"), Severity.high: ("High", ":material/warning:"),
    Severity.medium: ("Medium", ":material/info:"), Severity.low: ("Low", ":material/check_circle:"),
}
STATUS_LABELS = {"pending": "Pending", "prepared": "Guidance ready", "skipped": "Skipped", "completed": "Completed"}
ACTION_ICONS = {
    "prepare_bank_freeze": ":material/credit_card:", "prepare_singpass_security": ":material/badge:",
    "prepare_email_security": ":material/mark_email_unread:", "create_evidence_summary": ":material/photo_library:",
    "prepare_police_report": ":material/description:", "draft_contact_notification": ":material/campaign:",
}
INTAKE_WIDGET_KEYS = (
    "intake_narrative", "intake_date_time", "intake_channels", "intake_impersonated", "intake_contact",
    "intake_url", "intake_bank", "intake_transfer", "intake_amount", "intake_discovery", "intake_actions",
    "intake_exposures", "intake_image_consent",
)


def load_styles() -> None:
    css = (Path(__file__).parent / "src" / "ui" / "styles.css").read_text(encoding="utf-8")
    st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)


def render_header_badge() -> None:
    state: IncidentState | None = st.session_state.get("incident")
    if not state:
        badge = "No active case"
    elif state.status == "completed":
        badge = f"Case {state.case_revision} · Complete"
    elif state.status == "needs_attention":
        badge = f"Case {state.case_revision} · Review needed"
    else:
        badge = f"Case {state.case_revision} · In progress"
    st.markdown(f'<div class="f30-case-badge">{html.escape(badge)}</div>', unsafe_allow_html=True)


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
    edit_key = f"editable_{key}"
    edited = st.text_area(label, value=value, key=edit_key, height=height)
    st.caption("Use the copy icon in the top-right of the panel below to copy the current text.")
    st.code(edited, language=None, wrap_lines=True, height=min(height, 180))


def report_fields(result: ToolResult, revision: int, action_id: str, *, completed: bool = False) -> None:
    metadata = result.metadata
    fields = result.artifact.report_fields if result.artifact else metadata
    st.markdown(f"**Suggested entries for the SPF {metadata.get('report_type', 'scam')} form**")
    st.caption("Review these against your records. Missing details are labelled instead of invented.")
    labels = {
        "field_when_where": "When and where it happened", "field_what_happened": "Description of what happened",
        "field_discovery": "How the incident was discovered", "field_money_transactions": "Transactions or money involved",
        "field_items_involved": "Items or information involved", "field_victims": "Victims involved",
        "field_suspects": "Suspects involved",
    }
    for field, label in labels.items():
        copyable_text(label, fields.get(field, "Not recorded"), f"r{revision}_{field}", 100 if field == "field_what_happened" else 74)
    compiled = "\n\n".join(
        f"{label}\n{st.session_state.get(f'editable_r{revision}_{field}', fields.get(field, 'Not recorded'))}"
        for field, label in labels.items()
    )
    st.markdown("**Copy the complete report draft**")
    st.code(compiled, language=None, wrap_lines=True, height=240)

    attachment_items = metadata.get("attachment_checklist", [])
    if not isinstance(attachment_items, list):
        attachment_items = []
    st.markdown("**Attachments to prepare**")
    st.caption("Check these off as you gather the original files for the official report.")
    render_checklist(
        [str(item) for item in attachment_items],
        f"report_attachments_r{revision}_{action_id}",
        disabled=completed,
    )


def render_artifact(state: IncidentState, action: RecoveryAction, result: ToolResult) -> bool:
    metadata = result.metadata
    st.success("Guidance prepared locally. Nothing has been submitted, sent, or changed in an external account.")
    completion_ready = True
    if result.artifact:
        artifact = result.artifact
        st.write(artifact.summary)
        if artifact.instructions:
            st.markdown("**What to do**")
            if action.tool_name == "create_evidence_summary":
                completion_ready = render_checklist(
                    artifact.instructions,
                    f"evidence_check_r{state.case_revision}_{action.id}",
                    disabled=action.status == "completed",
                )
            else:
                for index, instruction in enumerate(artifact.instructions, start=1):
                    st.write(f"{index}. {instruction}")
        for route in artifact.official_routes:
            if route.phone:
                st.info(route.phone)
            if route.note:
                st.caption(route.note)
            if route.url:
                st.link_button(route.label, route.url, icon=":material/open_in_new:", width="content")
        if artifact.report_fields:
            report_fields(
                result,
                state.case_revision,
                action.id,
                completed=action.status == "completed",
            )
        for block in artifact.copy_blocks:
            copyable_text(block.title, block.text, f"r{state.case_revision}_{action.id}_{block.id}", 175)
        return completion_ready
    official_url = metadata.get("official_guidance_url") or metadata.get("official_contact_url") or metadata.get("official_report_url")
    if metadata.get("contact_route"):
        st.info(metadata["contact_route"])
    if metadata.get("support_note"):
        st.info(metadata["support_note"])
    if official_url:
        st.link_button("Open official service", official_url, width="content")
    if metadata.get("security_checklist"):
        st.markdown("**Account-security checklist**")
        for item in metadata["security_checklist"].split("; "):
            st.markdown(f"- {item.strip().rstrip('.')}.")
    if metadata.get("call_script"):
        copyable_text("Suggested support script", metadata["call_script"], f"r{state.case_revision}_{action.id}_script")
    if action.tool_name == "create_evidence_summary":
        st.markdown("**How to preserve evidence**")
        completion_ready = render_checklist(
            metadata.get("preservation_steps", "").splitlines(),
            f"evidence_check_r{state.case_revision}_{action.id}",
            disabled=action.status == "completed",
        )
        st.caption(f"Already mentioned: {metadata.get('evidence_available', 'None identified yet')}.")
    if action.tool_name == "prepare_police_report":
        report_fields(
            result,
            state.case_revision,
            action.id,
            completed=action.status == "completed",
        )
    if metadata.get("content"):
        copyable_text("Editable message draft", metadata["content"], f"r{state.case_revision}_{action.id}_message", 175)
    return completion_ready


def risk_evidence(state: IncidentState, risk: Risk) -> list[str]:
    finding = next((item for item in state.facts.exposure_findings if item.category == risk.source_exposure), None)
    if finding and finding.evidence:
        return [item.excerpt for item in finding.evidence]
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


@st.dialog("Risk details", width="medium", icon=":material/shield:")
def risk_dialog(state: IncidentState, risk: Risk) -> None:
    label, _ = SEVERITY_LABELS[risk.severity]
    finding = next((item for item in state.facts.exposure_findings if item.category == risk.source_exposure), None)
    st.markdown(f"## {risk.title}")
    st.markdown(f"**Severity: {label}**")
    st.write(risk.rationale)
    st.markdown("**Why this risk was identified**")
    for item in risk_evidence(state, risk):
        st.markdown(f"- {item}")
    st.markdown("**Affected information**")
    st.write(risk.source_exposure.replace("_", " ").title())
    st.markdown("**Uncertainty**")
    uncertainty = list(dict.fromkeys([*state.facts.needs_review, *state.facts.uncertainties, *(finding.conflict_notes if finding else [])]))
    if uncertainty:
        for item in uncertainty:
            st.warning(item)
    else:
        st.caption("No specific conflict was identified. Confirm the assessment against your own records.")


@st.dialog("Finding needs confirmation", width="medium", icon=":material/help:")
def possible_finding_dialog(finding: ExposureFinding) -> None:
    st.markdown(f"## {finding.category.replace('_', ' ').title()}")
    st.warning("This was not confirmed and did not create a required recovery step.")
    for item in finding.evidence:
        st.write(f"Source: {item.field} — {item.excerpt}")
    for note in finding.conflict_notes:
        st.info(note)
    st.caption("Return to Incident Details and clarify what was or was not shared, then resubmit the case.")


@st.dialog("Official support", width="medium", icon=":material/support_agent:")
def support_dialog(kind: str, state: IncidentState) -> None:
    if kind == "check":
        st.markdown("## Check the suspicious contact and link")
        st.write("Open ScamShield's Check for Scams feature and check each item separately.")
        if state.facts.suspect_identifiers:
            st.info("Phone or contact to check: " + ", ".join(state.facts.suspect_identifiers))
        if state.facts.suspicious_urls:
            st.info("Website link to check: " + ", ".join(state.facts.suspicious_urls))
        if not state.facts.suspect_identifiers and not state.facts.suspicious_urls:
            st.caption("No phone number or URL was supplied. You can still paste the suspicious message into ScamShield.")
        st.link_button("Open ScamShield checking guide", OFFICIAL_HANDOFFS["scamshield_check"], icon=":material/open_in_new:", width="content")
    elif kind == "report":
        st.markdown("## Report the scam in the ScamShield app")
        st.write("Use the app to report the suspicious call, message, or website so it can be reviewed for blocking and detection.")
        st.warning("A ScamShield report is not an official police report. If you were scammed or lost money, also lodge an SPF report.")
        st.link_button("Open ScamShield reporting guide", OFFICIAL_HANDOFFS["scamshield_report"], icon=":material/open_in_new:", width="content")
    else:
        st.markdown("## Police help and reporting")
        st.error("For immediate police assistance, call 999. If it is unsafe to speak, SMS 70999.")
        st.info("To provide non-emergency crime-related information, call the Police Hotline at 1800 255 0000.")
        st.link_button("Lodge a non-urgent police report", OFFICIAL_HANDOFFS["police_report"], icon=":material/open_in_new:", width="content")
        st.link_button("View official SPF contacts", OFFICIAL_HANDOFFS["police_contact"], icon=":material/open_in_new:", width="content")


@st.dialog("Recovery step", width="medium", icon=":material/task_alt:")
def action_dialog(state: IncidentState, action_id: str) -> None:
    state = st.session_state.get("incident", state)
    action = next(item for item in state.actions if item.id == action_id)
    st.markdown(f"## {action.title}")
    st.info(f"Why this step is included: {action_reason(state, action)}")
    st.caption("Never enter passwords, OTPs, PINs, recovery codes, or full card numbers into First30.")
    if action.status == "skipped":
        st.warning("This step is skipped and still prevents the plan from reaching 100%.")
        if st.button("Reopen this step", type="primary", width="content", key=f"reopen_{state.case_revision}_{action.id}"):
            st.session_state.incident = reopen_action(state, action.id)
            st.rerun()
        return

    result = result_for_action(state, action)
    completion_ready = True
    if action.status in {"prepared", "completed"} and result:
        completion_ready = render_artifact(state, action, result)
    elif action.id == state.current_action_id:
        prepared_state = state.model_copy(deep=True)
        if action.tool_name == "prepare_bank_freeze":
            banks = ["I don't know yet", "DBS / POSB", "OCBC", "UOB"]
            initial = prepared_state.selected_bank if prepared_state.selected_bank in banks else "I don't know yet"
            selected = st.selectbox("Affected bank", banks, index=banks.index(initial), key=f"bank_r{state.case_revision}_{action.id}")
            prepared_state.selected_bank = "" if selected == "I don't know yet" else selected
        if action.tool_name == "draft_contact_notification":
            prepared_state.notification_channel = st.selectbox("Message channel", ["WhatsApp", "SMS", "Telegram", "Email"], key=f"channel_r{state.case_revision}_{action.id}")
        if st.button("Prepare tailored guidance", type="primary", width="content", key=f"prepare_r{state.case_revision}_{action.id}"):
            st.session_state.incident = prepare_current_action(prepared_state)
            st.rerun(scope="fragment")
        return
    elif action.status == "pending":
        st.caption("This step is upcoming. Complete or skip the current-priority step first.")

    if action.status == "completed":
        st.success("You confirmed this step as completed.")
        return
    if action.status == "prepared" and action.id == state.current_action_id:
        complete_label = "I completed this external step" if action.requires_confirmation else "I reviewed and completed this step"
        if action.tool_name == "create_evidence_summary" and not completion_ready:
            st.caption("Check every evidence-preservation item to unlock completion.")
        complete, skip = st.columns(2)
        if complete.button(
            complete_label,
            type="primary",
            width="stretch",
            disabled=not completion_ready,
            key=f"complete_r{state.case_revision}_{action.id}",
        ):
            st.session_state.incident = advance_incident(state, completed_action_ids=[action.id])
            st.rerun()
        if skip.button("Skip for now", width="stretch", key=f"skip_r{state.case_revision}_{action.id}"):
            st.session_state.incident = advance_incident(state, skipped_action_ids=[action.id])
            st.rerun()


@st.dialog("Developer details")
def developer_dialog(state: IncidentState) -> None:
    config = get_analysis_configuration()
    st.markdown("**Analysis configuration**")
    st.write(f"Provider: {str(config['provider']).title()}")
    st.write(f"Model: {config['model']}")
    if config["provider"] == "bedrock":
        profile = str(config["aws_profile"])
        st.write(f"Authentication: IAM Identity Center profile ({profile})" if profile else "Authentication: IAM Identity Center profile not configured")
    st.write(f"Mode used: {state.assessment_source.replace('_', ' ')}")
    st.write(f"Screenshots supplied: {len(state.image_metadata)}")
    if state.image_metadata:
        st.write(f"Screenshot status: {'Analysed' if state.images_analyzed else 'Not analysed'}")
    st.write(f"Case revision: {state.case_revision}")
    st.write(f"Accepted model findings: {state.facts.accepted_model_findings}")
    st.write(f"Rejected unsupported findings: {state.facts.rejected_model_findings}")
    st.write(f"Conflicted findings: {state.facts.conflicted_findings}")
    st.write(f"Rules-confirmed findings: {state.facts.rules_only_findings}")
    if state.facts.model_diagnostic:
        st.warning(f"Diagnostic: {state.facts.model_diagnostic}")
    if state.analysis_warning:
        st.warning(state.analysis_warning)
    elif state.assessment_source == "curated_rules_plus_llm":
        st.success("The structured model assessment completed successfully.")
    else:
        st.info("This case used the local curated assessment.")


def incident_details_page() -> None:
    restore_intake_draft()
    render_header_badge()
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
                    st.image(image.data, width="stretch")
                    st.caption(f"{image.name} · {len(image.data) / 1024:.0f} KB")
                    if st.button("Remove", key=f"remove_image_{upload_nonce}_{index}", width="content"):
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
        st.info("An AWS IAM Identity Center profile is not configured. You can submit safely, but screenshots will be marked “Not analysed” and the written-details fallback will be used.")
    disabled = count < 30 or bool(upload_error) or bool(image_model_error) or (bool(normalised) and not image_consent)
    if st.button("Analyse incident and build my plan", type="primary", width="content", disabled=disabled, key="submit_incident"):
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
    render_header_badge()
    state: IncidentState | None = st.session_state.get("incident")
    if not state:
        st.markdown('<div class="f30-eyebrow">Response dashboard</div>', unsafe_allow_html=True)
        st.title("No response plan yet")
        st.write("Describe the incident first. Your risk assessment and recovery steps will appear here.")
        if st.button("Go to Incident Details", type="primary"):
            st.switch_page(INCIDENT_PAGE)
        return
    support_column, progress_column = st.columns([7, 5], gap="medium")
    with support_column:
        with st.container(border=True, height=205, key="support_board"):
            st.markdown('<div class="f30-board-title">Official support</div><div class="f30-board-copy">Check, report, or contact the appropriate public service.</div>', unsafe_allow_html=True)
            support_tiles = st.columns(3, gap="small")
            support_definitions = (
                ("check", "ScamShield Check", "Check the supplied phone number, message, or link", ":material/search:"),
                ("report", "ScamShield Report", "Report a suspicious call, message, or website", ":material/report:"),
                ("police", "Police Help", "Emergency contacts and official reporting", ":material/local_police:"),
            )
            for column, (kind, title, description, icon) in zip(support_tiles, support_definitions):
                with column:
                    if st.button(f"**{title}**\n\n{description}", icon=icon, key=f"support_tile_{kind}_{state.case_revision}", width="stretch"):
                        support_dialog(kind, state)
    with progress_column:
        with st.container(border=True, height=205, key="progress_board"):
            render_progress_hero(state)
            if state.analysis_warning:
                st.warning(state.analysis_warning)

    risk_column, plan_column = st.columns([5, 7], gap="medium")
    with risk_column:
        with st.container(border=True, height=410, key="risk_board"):
            st.markdown('<div class="f30-board-title">Risks identified</div><div class="f30-board-copy">Confirmed risks and findings that still need clarification.</div>', unsafe_allow_html=True)
            risk_columns = st.columns(2, gap="small")
            card_index = 0
            for risk in state.risks:
                label, icon = SEVERITY_LABELS[risk.severity]
                with risk_columns[card_index % 2]:
                    if st.button(
                        f"{label.upper()}\n\n**{risk.title}**\n\nView supporting facts",
                        icon=icon, key=f"risk_tile_{risk.severity.value}_{state.case_revision}_{risk.id}", width="stretch",
                    ):
                        risk_dialog(state, risk)
                card_index += 1
            for finding in (item for item in state.facts.exposure_findings if item.status == "possible"):
                with risk_columns[card_index % 2]:
                    if st.button(
                        f"NEEDS CONFIRMATION\n\n**{finding.category.replace('_', ' ').title()}**\n\nClarify this finding",
                        icon=":material/help:", key=f"risk_tile_possible_{state.case_revision}_{finding.category}", width="stretch",
                    ):
                        possible_finding_dialog(finding)
                card_index += 1
    with plan_column:
        with st.container(border=True, height=410, key="plan_board"):
            st.markdown('<div class="f30-board-title">Your First30 plan</div><div class="f30-board-copy">Open the current step, prepare its guidance, then confirm what you completed.</div>', unsafe_allow_html=True)
            step_columns = st.columns(2, gap="small")
            for index, action in enumerate(state.actions, start=1):
                current = action.id == state.current_action_id
                status = STATUS_LABELS.get(action.status, action.status.title())
                key_status = "current" if current else action.status
                with step_columns[(index - 1) % 2]:
                    if st.button(
                        f"STEP {index} · {status.upper()}\n\n**{action.title}**\n\n{action.description}",
                        icon=ACTION_ICONS.get(action.tool_name, ":material/task_alt:"),
                        key=f"step_tile_{key_status}_{state.case_revision}_{action.id}", width="stretch",
                    ):
                        action_dialog(state, action.id)
    st.divider()
    if st.button("Developer details", key=f"developer_{state.case_revision}"):
        developer_dialog(state)
    st.caption("Prototype only. First30 does not access accounts, submit reports, upload evidence to official services, or send messages.")


def help_page() -> None:
    """Explain the prototype workflow in plain language for people using the app."""
    render_header_badge()
    st.title("How First30 works")
    st.markdown(
        '<div class="f30-lead">First30 helps you organise the first recovery steps after a suspected scam. '
        'It prepares guidance and drafts for your review; you remain in control of every external action.</div>',
        unsafe_allow_html=True,
    )

    with st.container(border=True):
        section_intro("1. Tell us what happened", "Describe the incident and select the information that may have been exposed.")
        st.write("You can add context such as the suspicious contact, website, affected bank, and any money transferred. "
                 "Screenshots are optional—only upload images you are comfortable having analysed.")

    with st.container(border=True):
        section_intro("2. Review the response dashboard", "Open a risk tile to see why it was identified, then open the current recovery-step tile.")
        st.write("Each recovery step prepares tailored guidance, an editable draft, or a link to an official service. "
                 "Complete steps in order where possible, and use the checklists to keep track of what you have done.")

    with st.container(border=True):
        section_intro("3. Take external action yourself", "First30 does not contact organisations or change accounts on your behalf.")
        st.warning(
            "The app never accesses your bank, Singpass, email, passwords, OTPs, PINs, or card details. "
            "It does not submit reports, upload evidence to official services, or send messages."
        )
        st.write("Use the prepared drafts and official links to contact your bank, Singpass, police, or trusted contacts directly.")

    with st.container(border=True):
        section_intro("Optional AI analysis", "The app can use Amazon Bedrock only when an AWS IAM Identity Center profile is configured and signed in.")
        st.write("The AI can help classify the incident and prioritise approved recovery steps. If it is unavailable, "
                 "First30 uses its built-in guidance instead.")

    st.error("If money may be at risk, contact your bank through its official channel immediately. For urgent police assistance in Singapore, call 999.")
    st.caption("This is a prototype. Check the official service before relying on any guidance.")


st.set_page_config(page_title="First30", page_icon=":material/security:", layout="wide", initial_sidebar_state="collapsed")
st.logo(Path(__file__).parent / "src" / "ui" / "first30-logo.svg", size="large")
load_styles()
INCIDENT_PAGE = st.Page(incident_details_page, title="Incident Details", icon=":material/edit_note:", default=True)
DASHBOARD_PAGE = st.Page(response_dashboard_page, title="Response Dashboard", icon=":material/dashboard:")
HELP_PAGE = st.Page(help_page, title="How it works", icon=":material/help:")
navigation = st.navigation([INCIDENT_PAGE, DASHBOARD_PAGE, HELP_PAGE], position="top")
navigation.run()
