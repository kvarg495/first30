from __future__ import annotations

import streamlit as st

from src.graph import continue_incident, run_incident
from src.state import IncidentState, RecoveryAction, Severity, ToolResult


EXPOSURE_OPTIONS = {
    "Bank/card details": "card_details",
    "OTP": "otp",
    "Singpass details": "singpass_details",
    "Email/password": "email_password",
    "Personal information": "personal_information",
    "Unsure": "unsure",
}

DEMO_DESCRIPTION = (
    "I clicked a fake parcel delivery website and entered my DBS credit-card details, "
    "OTP and Gmail password."
)
DEMO_EXPOSURES = ["Bank/card details", "OTP", "Email/password"]

SEVERITY_STYLES = {
    Severity.critical: ("🔴", "Critical"),
    Severity.high: ("🟠", "High"),
    Severity.medium: ("🔵", "Medium"),
    Severity.low: ("⚪", "Low"),
}


def load_demo() -> None:
    st.session_state.incident_description = DEMO_DESCRIPTION
    st.session_state.incident_exposures = DEMO_EXPOSURES


def start_new_incident() -> None:
    st.session_state.pop("incident", None)
    st.session_state.incident_description = ""
    st.session_state.incident_exposures = []


def action_icon(action: RecoveryAction, current_action_id: str | None) -> str:
    if action.status == "completed":
        return "✅"
    if action.status == "skipped":
        return "⏭️"
    if action.status == "prepared":
        return "📋"
    if action.id == current_action_id:
        return "▶️"
    return "○"


def render_risks(state: IncidentState) -> None:
    st.subheader("Risk assessment")
    for risk in state.risks:
        icon, label = SEVERITY_STYLES[risk.severity]
        with st.container(border=True):
            st.markdown(f"{icon} **{label} — {risk.title}**")
            st.caption(risk.rationale)
            st.caption(f"Exposure identified: {risk.source_exposure.replace('_', ' ')}")
    facts = state.facts
    with st.container(border=True):
        st.markdown("**What First30 understood**")
        st.write(
            f"OTP context: **{facts.otp_context.replace('_', ' ')}** · "
            f"Money transferred: **{facts.money_transferred}**"
        )
        if facts.impersonated_organisation or facts.scam_channels:
            st.caption(
                f"Channel: {', '.join(facts.scam_channels) or 'not recorded'} · "
                f"Impersonated organisation: {facts.impersonated_organisation or 'not recorded'}"
            )


def render_plan(state: IncidentState) -> None:
    st.subheader("Your First30 plan")
    for number, action in enumerate(state.actions, start=1):
        is_current = action.id == state.current_action_id
        with st.container(border=is_current):
            badges = []
            if action.status == "prepared":
                badges.append("Guidance prepared")
            elif action.status == "skipped":
                badges.append("Skipped")
            elif action.requires_confirmation and action.status != "completed":
                badges.append("Human step required")
            if is_current:
                badges.append("Current priority")
            suffix = f" · {' · '.join(badges)}" if badges else ""
            st.markdown(f"{action_icon(action, state.current_action_id)} **{number}. {action.title}**{suffix}")
            st.caption(action.description)


def render_scamshield_support() -> None:
    with st.container(border=True):
        st.markdown("**ScamShield assistance**")
        st.caption("Use ScamShield for official scam guidance and assistance. This is separate from a police report or a bank/account-security step.")
        st.link_button("Open ScamShield guidance", "https://www.scamshield.gov.sg/i-have-been-scammed/", use_container_width=True)
        st.caption("If you are unsure whether something is a scam, the ScamShield Helpline is 1799.")


def result_for_action(state: IncidentState, action: RecoveryAction) -> ToolResult | None:
    return next((result for result in reversed(state.tool_results) if result.action == action.tool_name), None)


def render_prepared_artifact(result: ToolResult) -> None:
    metadata = result.metadata
    st.success("Guidance prepared locally. First30 has not contacted, signed in to, or submitted anything to an external service.")
    official_url = metadata.get("official_guidance_url") or metadata.get("official_contact_url") or metadata.get("official_report_url")
    if official_url:
        st.link_button("Open official service", official_url, use_container_width=True)
    if metadata.get("support_note"):
        st.info(metadata["support_note"])
    if metadata.get("contact_route"):
        st.info(f"**Official contact route:** {metadata['contact_route']}")
    if metadata.get("call_script"):
        st.markdown("**Suggested call script**")
        st.text_area("Call script", metadata["call_script"], height=110, disabled=True, label_visibility="collapsed")
    if metadata.get("security_checklist"):
        st.markdown("**Security checklist**")
        for item in metadata["security_checklist"].split("; "):
            st.write(f"- {item.strip().capitalize()}")
    if metadata.get("content"):
        st.markdown("**Draft to review**")
        st.text_area("Prepared draft", metadata["content"], height=260, disabled=True, label_visibility="collapsed")
        extension = "eml.txt" if metadata.get("format") == "email" else "md"
        st.download_button(
            "Download draft",
            data=metadata["content"],
            file_name=f"first30-{result.action}.{extension}",
            mime="text/plain",
            use_container_width=True,
        )


def stop_response(state: IncidentState) -> None:
    paused = state.model_copy(deep=True)
    paused.status = "stopped_by_user"
    paused.current_action_id = None
    paused.activity_log.append("Response paused by the user; no external action was performed by First30")
    st.session_state.incident = paused


def personalise_action_explanation(state: IncidentState, action: RecoveryAction) -> str:
    facts = state.facts
    if action.tool_name == "prepare_singpass_security":
        return "Your story indicates a Singpass-related verification flow. No card or bank credentials were identified, so this is prioritised ahead of reporting."
    if action.tool_name == "prepare_bank_freeze":
        return "This route is shown because you reported card/bank exposure, a financial OTP, or a completed transfer."
    if action.tool_name == "create_evidence_summary":
        return "First30 will turn your recorded timeline, identifiers, URLs, and available screenshots into a local evidence pack."
    if action.tool_name == "prepare_police_report":
        return "First30 will prepare the fields you need for the relevant SPF report type; it will not submit the report."
    if action.tool_name == "draft_contact_notification":
        return "Identity or account exposure can be used to impersonate you. This prepares an unsent warning in your chosen format."
    return action.description


def collect_preparation_details(state: IncidentState, action: RecoveryAction) -> IncidentState:
    """Collect only non-secret case details before a local tool creates its draft."""
    updated = state.model_copy(deep=True)
    if action.tool_name == "prepare_bank_freeze":
        choice = st.selectbox("Which bank is involved?", ["I don't know yet", "DBS / POSB"], key=f"bank-{action.id}")
        updated.selected_bank = "" if choice == "I don't know yet" else choice
    elif action.tool_name == "create_evidence_summary":
        st.markdown("**Evidence capture** — do not upload or enter credentials, OTPs, PINs, or full card numbers.")
        updated.evidence_fields = {
            "incident_date_and_time": st.text_input("Approximate incident date and time", value=state.evidence_fields.get("incident_date_and_time", ""), key=f"evidence-time-{action.id}"),
            "scammer_identifier": st.text_input("Scammer number, username, or account identifier", value=state.evidence_fields.get("scammer_identifier", ""), key=f"evidence-suspect-{action.id}"),
            "additional_evidence": st.text_area("Screenshots or items saved locally", value=state.evidence_fields.get("additional_evidence", ""), key=f"evidence-items-{action.id}", placeholder="For example: WhatsApp chat screenshot, call log, fake website screenshot"),
        }
        if state.facts.evidence_available:
            st.info(f"Already identified: {', '.join(state.facts.evidence_available).replace('_', ' ')}")
    elif action.tool_name == "prepare_police_report":
        report_type = st.selectbox(
            "Which report preparation best fits this case?",
            ["scam", "unauthorised_card_transaction", "other_cheating"],
            format_func=lambda value: {"scam": "Scam", "unauthorised_card_transaction": "Unauthorised card transaction", "other_cheating": "Other cheating case"}[value],
            key=f"report-type-{action.id}",
        )
        updated.report_type = report_type
        updated.report_fields = {
            "when_and_where": st.text_input("When did it happen, and where/how did it take place?", value=state.report_fields.get("when_and_where", ""), key=f"report-when-{action.id}"),
            "how_discovered": st.text_area("How did you discover it? Include transaction count/amount/time period if relevant.", value=state.report_fields.get("how_discovered", ""), key=f"report-discovery-{action.id}"),
            "items_and_suspects": st.text_area("Items involved, suspect details, and attachments available", value=state.report_fields.get("items_and_suspects", ""), key=f"report-items-{action.id}"),
        }
    return updated


def render_confirmation(state: IncidentState) -> None:
    if state.status not in {"awaiting_preparation", "awaiting_user_confirmation"} or not state.current_action_id:
        return

    action = next(item for item in state.actions if item.id == state.current_action_id)
    st.warning("Action needed now")
    st.markdown(f"### {action.title}")
    st.write(personalise_action_explanation(state, action))
    st.caption(
        "First30 will only prepare a safe hand-off. It will not access your bank, "
        "Singpass, passwords, OTPs, PINs, or full card details."
    )
    if state.status == "awaiting_preparation":
        prepared_state = collect_preparation_details(state, action)
        st.caption("Preparing guidance creates a local draft or official hand-off only. It does not perform the real-world action.")
        if st.button("Prepare guidance", type="primary", use_container_width=True):
            st.session_state.incident = continue_incident(
                prepared_state,
                approved_action_ids=[action.id],
                use_llm=st.session_state.get("use_llm", False),
            )
            st.rerun()
        return

    result = result_for_action(state, action)
    if result:
        render_prepared_artifact(result)

    primary_label = "I’ve completed this step" if action.requires_confirmation else "Mark reviewed and continue"
    complete, skip = st.columns(2)
    if complete.button(primary_label, type="primary", use_container_width=True):
        st.session_state.incident = continue_incident(
            state,
            completed_action_ids=[action.id],
            use_llm=st.session_state.get("use_llm", False),
        )
        st.rerun()
    if skip.button("Skip for now", use_container_width=True):
        st.session_state.incident = continue_incident(
            state,
            skipped_action_ids=[action.id],
            use_llm=st.session_state.get("use_llm", False),
        )
        st.rerun()
    if st.button("Stop response", use_container_width=True):
        stop_response(state)
        st.rerun()


def render_activity(state: IncidentState) -> None:
    with st.expander("Response timeline", expanded=True):
        for event in state.activity_log[-6:]:
            st.write(f"✓ {event}")


def render_state(state: IncidentState) -> None:
    completed = sum(action.status in {"completed", "skipped"} for action in state.actions)
    critical = sum(risk.severity == Severity.critical for risk in state.risks)
    status_label = (
        "Action required"
        if state.status in {"awaiting_preparation", "awaiting_user_confirmation"}
        else state.status.replace("_", " ").title()
    )

    st.subheader("Your First30 response")
    left, middle, right = st.columns(3)
    left.metric("Status", status_label)
    middle.metric("Critical risks", critical)
    right.metric("Actions resolved", f"{completed} / {len(state.actions)}")

    render_risks(state)
    render_plan(state)
    render_scamshield_support()
    render_confirmation(state)

    if state.status == "completed":
        st.success("The current response plan is complete.")
        st.info("Continue monitoring your official accounts and follow up through the relevant official channels.")
        st.button("Start a new incident", on_click=start_new_incident, use_container_width=True)
    elif state.status in {"stopped_safely", "stopped_by_user"}:
        st.info("First30 paused the response safely. Review the remaining actions through official channels.")

    render_activity(state)


st.set_page_config(page_title="First30", page_icon="🛡️", layout="centered")
st.title("First30")
st.caption("Every minute matters after a scam.")
st.warning("Never enter passwords, OTPs, card PINs, or full banking credentials here.")

st.button("Load demo scenario", on_click=load_demo, help="Use the polished parcel-delivery scam scenario for the demo.")

description = st.text_area(
    "What happened?",
    key="incident_description",
    placeholder="Describe the scam and the kinds of information you may have exposed.",
    height=140,
)
labels = st.multiselect(
    "What information might have been exposed?",
    list(EXPOSURE_OPTIONS),
    key="incident_exposures",
)
use_llm = st.toggle(
    "Use optional LLM reasoning",
    key="use_llm",
    value=False,
    help="Off by default so the local, curated workflow responds immediately. Turn on only when your configured model credentials are available.",
)

if st.button("Start First30 response", type="primary", disabled=not description.strip(), use_container_width=True):
    st.session_state.incident = run_incident(
        description=description.strip(),
        selected_exposures=[EXPOSURE_OPTIONS[label] for label in labels],
        use_llm=use_llm,
    )

if "incident" in st.session_state:
    st.divider()
    render_state(st.session_state.incident)

st.divider()
st.caption("Prototype only. For urgent financial loss, contact your bank through its official channel immediately.")
