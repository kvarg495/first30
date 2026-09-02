from __future__ import annotations

import streamlit as st

from src.graph import run_incident
from src.state import IncidentState, RecoveryAction, Severity


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


def render_plan(state: IncidentState) -> None:
    st.subheader("Your First30 plan")
    for number, action in enumerate(state.actions, start=1):
        is_current = action.id == state.current_action_id
        with st.container(border=is_current):
            badges = []
            if action.requires_confirmation and action.status != "completed":
                badges.append("Approval required")
            if is_current:
                badges.append("Current priority")
            suffix = f" · {' · '.join(badges)}" if badges else ""
            st.markdown(f"{action_icon(action, state.current_action_id)} **{number}. {action.title}**{suffix}")
            st.caption(action.description)


def render_confirmation(state: IncidentState) -> None:
    if state.status != "awaiting_confirmation" or not state.current_action_id:
        return

    action = next(item for item in state.actions if item.id == state.current_action_id)
    st.warning("Action needed now")
    st.markdown(f"### {action.title}")
    st.write(action.description)
    st.caption(
        "First30 will only prepare a safe hand-off. It will not access your bank, "
        "Singpass, passwords, OTPs, PINs, or full card details."
    )
    if st.button("Approve and continue", type="primary", use_container_width=True):
        approvals = list(dict.fromkeys([*state.approved_action_ids, action.id]))
        st.session_state.incident = run_incident(
            description=state.description,
            selected_exposures=state.selected_exposures,
            approved_action_ids=approvals,
            completed_action_ids=state.completed_action_ids,
        )
        st.rerun()


def render_activity(state: IncidentState) -> None:
    with st.expander("Why First30 chose this", expanded=True):
        for event in state.activity_log:
            st.write(f"✓ {event}")


def render_state(state: IncidentState) -> None:
    completed = sum(action.status == "completed" for action in state.actions)
    critical = sum(risk.severity == Severity.critical for risk in state.risks)
    status_label = "Action required" if state.status == "awaiting_confirmation" else state.status.replace("_", " ").title()

    st.subheader("Your First30 response")
    left, middle, right = st.columns(3)
    left.metric("Status", status_label)
    middle.metric("Critical risks", critical)
    right.metric("Actions completed", f"{completed} / {len(state.actions)}")

    render_risks(state)
    render_plan(state)
    render_confirmation(state)

    if state.status == "completed":
        st.success("The current response plan is complete.")
        st.info("Continue monitoring your official accounts and follow up through the relevant official channels.")
        st.button("Start a new incident", on_click=start_new_incident, use_container_width=True)
    elif state.status == "stopped_safely":
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

if st.button("Start First30 response", type="primary", disabled=not description.strip(), use_container_width=True):
    st.session_state.incident = run_incident(
        description=description.strip(),
        selected_exposures=[EXPOSURE_OPTIONS[label] for label in labels],
    )

if "incident" in st.session_state:
    st.divider()
    render_state(st.session_state.incident)

st.divider()
st.caption("Prototype only. For urgent financial loss, contact your bank through its official channel immediately.")
