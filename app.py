from __future__ import annotations

import streamlit as st

from src.graph import run_incident
from src.state import IncidentState


EXPOSURE_OPTIONS = {
    "Bank/card details": "card_details",
    "OTP": "otp",
    "Singpass details": "singpass_details",
    "Email/password": "email_password",
    "Personal information": "personal_information",
    "Unsure": "unsure",
}


def render_state(state: IncidentState) -> None:
    st.subheader("Your First30 response")

    if state.risks:
        for risk in state.risks:
            st.markdown(f"**{risk.severity.value.upper()} — {risk.title}**")
            st.caption(risk.rationale)

    st.subheader("Prioritised plan")
    for action in state.actions:
        icon = "✅" if action.status == "completed" else "▶️" if action.id == state.current_action_id else "○"
        st.markdown(f"{icon} **{action.title}**")
        st.caption(action.description)

    if state.status == "awaiting_confirmation" and state.current_action_id:
        action = next(item for item in state.actions if item.id == state.current_action_id)
        st.warning(f"Approval required: {action.title}")
        if st.button("Approve this prepared action", type="primary"):
            approvals = list(dict.fromkeys([*state.approved_action_ids, action.id]))
            st.session_state.incident = run_incident(
                description=state.description,
                selected_exposures=state.selected_exposures,
                approved_action_ids=approvals,
                completed_action_ids=state.completed_action_ids,
            )
            st.rerun()

    if state.status == "completed":
        st.success("The current response plan is complete. Continue monitoring official accounts and channels.")

    with st.expander("Agent activity", expanded=True):
        for event in state.activity_log:
            st.write(f"✓ {event}")


st.set_page_config(page_title="First30", page_icon="🛡️", layout="centered")
st.title("First30")
st.caption("Take control in the critical moments after a scam.")
st.info("Never enter passwords, OTPs, card PINs, or full banking credentials here.")

description = st.text_area(
    "What happened?",
    placeholder="Describe the scam and the kinds of information you may have exposed.",
    height=140,
)
labels = st.multiselect("What information might have been exposed?", list(EXPOSURE_OPTIONS))

if st.button("Start First30", type="primary", disabled=not description.strip()):
    st.session_state.incident = run_incident(
        description=description.strip(),
        selected_exposures=[EXPOSURE_OPTIONS[label] for label in labels],
    )

if "incident" in st.session_state:
    render_state(st.session_state.incident)

st.divider()
st.caption("Prototype only. For urgent financial loss, contact your bank through its official channel immediately.")

