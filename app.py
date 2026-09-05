from __future__ import annotations

import streamlit as st

from src.graph import advance_incident, prepare_current_action, run_incident
from src.state import IncidentState, RecoveryAction, Severity, ToolResult


EXPOSURE_OPTIONS = {
    "Bank/card details": "card_details", "OTP": "otp", "Singpass details": "singpass_details",
    "Email/password": "email_password", "Personal information": "personal_information", "Unsure": "unsure",
}
DEMO_DESCRIPTION = "I clicked a fake parcel delivery website and entered my DBS credit-card details, OTP and Gmail password."
DEMO_EXPOSURES = ["Bank/card details", "OTP", "Email/password"]
SEVERITY_STYLES = {Severity.critical: ("🔴", "Critical"), Severity.high: ("🟠", "High"), Severity.medium: ("🔵", "Medium"), Severity.low: ("⚪", "Low")}


def load_demo() -> None:
    st.session_state.incident_description = DEMO_DESCRIPTION
    st.session_state.incident_exposures = DEMO_EXPOSURES


def start_new_incident() -> None:
    st.session_state.pop("incident", None)
    st.session_state.incident_description = ""
    st.session_state.incident_exposures = []


def action_icon(action: RecoveryAction, current_action_id: str | None) -> str:
    return {"completed": "✅", "skipped": "⏭️", "prepared": "📋"}.get(action.status, "▶️" if action.id == current_action_id else "○")


def action_reason(state: IncidentState, action: RecoveryAction) -> str:
    facts = state.facts
    if action.tool_name == "prepare_singpass_security":
        return "You reported a Singpass-related verification flow. No card or bank exposure was identified, so securing Singpass comes before reporting."
    if action.tool_name == "prepare_bank_freeze":
        return "You reported card/bank exposure, a financial OTP, or a completed transfer. Containment is prioritised to limit further loss."
    if action.tool_name == "prepare_email_security":
        return "Email access can be used to reset other accounts or hide alerts, so it is handled before documentation."
    if action.tool_name == "create_evidence_summary":
        return "Preserving originals now makes it easier to report accurately later and avoids losing key details."
    if action.tool_name == "prepare_police_report":
        return "Containment guidance is prepared first. This step organises the information the official SPF form will ask for."
    return "Identity or account exposure can be used to impersonate you. This prepares an unsent warning for people you trust."


def render_scamshield_card() -> None:
    with st.container(border=True):
        st.markdown("**ScamShield guidance**")
        st.caption("Official scam guidance and assistance. This complements—rather than replaces—your bank, Singpass, and SPF steps.")
        st.link_button("Open ScamShield guidance", "https://www.scamshield.gov.sg/i-have-been-scammed/", use_container_width=True)
        st.caption("If you are unsure whether something is a scam, call ScamShield at 1799.")


def render_risks(state: IncidentState) -> None:
    st.subheader("Risk assessment")
    for risk in state.risks:
        icon, label = SEVERITY_STYLES[risk.severity]
        with st.container(border=True):
            st.markdown(f"{icon} **{label} — {risk.title}**")
            st.caption(risk.rationale)


def render_plan(state: IncidentState) -> None:
    st.subheader("Your First30 plan")
    for number, action in enumerate(state.actions, start=1):
        current = action.id == state.current_action_id
        with st.container(border=current):
            suffix = " · Current priority" if current else ""
            if action.status == "prepared": suffix = " · Guidance prepared"
            if action.status == "skipped": suffix = " · Skipped"
            st.markdown(f"{action_icon(action, state.current_action_id)} **{number}. {action.title}**{suffix}")
            if current:
                st.caption(action_reason(state, action))


def result_for_action(state: IncidentState, action: RecoveryAction) -> ToolResult | None:
    return next((item for item in reversed(state.tool_results) if item.action == action.tool_name), None)


def copyable_text(label: str, value: str, key: str, height: int = 120) -> None:
    st.text_area(label, value=value, key=key, height=height, help="Select and copy this text if you want to use it in an official service or message.")


def render_report_fields(metadata: dict[str, str], action: RecoveryAction) -> None:
    st.markdown(f"**Suggested entries for an SPF {metadata['report_type']} report**")
    st.caption("Review and edit these suggestions before entering them in the official form. Missing facts are labelled rather than invented.")
    labels = {
        "field_when_where": "When and where it happened",
        "field_what_happened": "What happened",
        "field_discovery": "How it was discovered",
        "field_money_transactions": "Money or transactions involved",
        "field_items_involved": "Items/information involved",
        "field_suspect_details": "Suspect details",
        "field_attachments": "Attachments to prepare",
    }
    for field, label in labels.items():
        copyable_text(label, metadata.get(field, "Not recorded"), f"{action.id}-{field}", 96 if field == "field_what_happened" else 68)


def render_artifact(state: IncidentState, action: RecoveryAction, result: ToolResult) -> None:
    metadata = result.metadata
    st.success("Prepared locally. First30 has not contacted, signed in to, uploaded evidence to, or submitted anything to an external service.")
    url = metadata.get("official_guidance_url") or metadata.get("official_contact_url") or metadata.get("official_report_url")
    if url:
        st.link_button("Open official service", url, use_container_width=True)
    if metadata.get("support_note"):
        st.info(metadata["support_note"])
    if metadata.get("contact_route"):
        st.info(f"Official contact route: {metadata['contact_route']}")
    if metadata.get("call_script"):
        st.markdown("**What to say**")
        copyable_text("Support script", metadata["call_script"], f"{action.id}-script")
    if action.tool_name == "create_evidence_summary":
        st.markdown("**Preserve evidence now**")
        for index, step in enumerate(metadata["preservation_steps"].splitlines()):
            st.checkbox(step, key=f"{action.id}-evidence-{index}")
        st.caption(f"Already identified from your story: {metadata['evidence_available']}.")
    if action.tool_name == "prepare_police_report":
        render_report_fields(metadata, action)
    if metadata.get("content"):
        title = "Message preview" if action.tool_name == "draft_contact_notification" else "Prepared text"
        copyable_text(title, metadata["content"], f"{action.id}-content", 170)


def render_current_action(state: IncidentState) -> None:
    if state.status not in {"awaiting_preparation", "awaiting_user_confirmation"} or not state.current_action_id:
        return
    action = next(item for item in state.actions if item.id == state.current_action_id)
    st.divider()
    st.markdown(f"### {action.title}")
    st.info(f"Why this is next: {action_reason(state, action)}")
    st.caption("Never enter passwords, OTPs, PINs, recovery codes, or full card details into First30.")
    if state.status == "awaiting_preparation":
        prepared_state = state.model_copy(deep=True)
        if action.tool_name == "prepare_bank_freeze":
            selected = st.selectbox("Which bank is involved?", ["I don't know yet", "DBS / POSB"], key=f"bank-{action.id}")
            prepared_state.selected_bank = "" if selected == "I don't know yet" else selected
        if action.tool_name == "draft_contact_notification":
            prepared_state.notification_channel = st.selectbox("Prepare this warning for", ["WhatsApp", "SMS", "Telegram", "Email"], key=f"channel-{action.id}")
        if st.button("Prepare guidance", type="primary", use_container_width=True):
            st.session_state.incident = prepare_current_action(prepared_state)
            st.rerun()
        return
    result = result_for_action(state, action)
    if result:
        render_artifact(state, action, result)
    label = "I’ve completed this step" if action.requires_confirmation else "Mark reviewed and continue"
    complete, skip = st.columns(2)
    if complete.button(label, type="primary", use_container_width=True):
        st.session_state.incident = advance_incident(state, completed_action_ids=[action.id])
        st.rerun()
    if skip.button("Skip for now", use_container_width=True):
        st.session_state.incident = advance_incident(state, skipped_action_ids=[action.id])
        st.rerun()


def render_state(state: IncidentState) -> None:
    completed = sum(action.status in {"completed", "skipped"} for action in state.actions)
    critical = sum(risk.severity == Severity.critical for risk in state.risks)
    st.subheader("Your First30 response")
    first, second, third = st.columns(3)
    first.metric("Status", "Action required" if state.current_action_id else state.status.replace("_", " ").title())
    second.metric("Critical risks", critical)
    third.metric("Actions resolved", f"{completed} / {len(state.actions)}")
    if state.assessment_source == "curated_rules_fallback":
        st.caption("AI analysis is temporarily unavailable. First30 is using its local safety rules.")
    render_scamshield_card()
    render_risks(state)
    render_plan(state)
    render_current_action(state)
    if state.status == "completed":
        st.success("The current response plan is complete.")
        st.button("Start a new incident", on_click=start_new_incident, use_container_width=True)


st.set_page_config(page_title="First30", page_icon="🛡️", layout="centered")
st.title("First30")
st.caption("Every minute matters after a scam.")
st.warning("Never enter passwords, OTPs, card PINs, or full banking credentials here.")
st.button("Load demo scenario", on_click=load_demo)
description = st.text_area("What happened?", key="incident_description", placeholder="Describe the scam and the kinds of information you may have exposed.", height=140)
labels = st.multiselect("What information might have been exposed?", list(EXPOSURE_OPTIONS), key="incident_exposures")
use_llm = st.toggle("Use optional LLM reasoning", key="use_llm", value=False, help="Use configured Bedrock/Groq reasoning. The local safety workflow remains available if it fails.")
if st.button("Start First30 response", type="primary", disabled=not description.strip(), use_container_width=True):
    st.session_state.incident = run_incident(description.strip(), [EXPOSURE_OPTIONS[label] for label in labels], use_llm=use_llm)
if "incident" in st.session_state:
    st.divider()
    render_state(st.session_state.incident)
st.divider()
st.caption("Prototype only. For urgent financial loss, contact your bank through its official channel immediately.")
