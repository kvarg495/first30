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
    if metadata.get("call_script"):
        st.markdown("**Suggested call script**")
        st.code(metadata["call_script"], language=None)
    if metadata.get("security_checklist"):
        st.markdown("**Security checklist**")
        st.write(metadata["security_checklist"])
    if metadata.get("content"):
        st.markdown("**Draft to review**")
        st.code(metadata["content"], language="markdown")
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


def render_confirmation(state: IncidentState) -> None:
    if state.status not in {"awaiting_preparation", "awaiting_user_confirmation"} or not state.current_action_id:
        return

    action = next(item for item in state.actions if item.id == state.current_action_id)
    st.warning("Action needed now")
    st.markdown(f"### {action.title}")
    st.write(action.description)
    st.caption(
        "First30 will only prepare a safe hand-off. It will not access your bank, "
        "Singpass, passwords, OTPs, PINs, or full card details."
    )
    if state.status == "awaiting_preparation":
        st.caption("Preparing guidance creates a local draft or official hand-off only. It does not perform the real-world action.")
        if st.button("Prepare guidance", type="primary", use_container_width=True):
            st.session_state.incident = continue_incident(
                state,
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
    with st.expander("Why First30 chose this", expanded=True):
        for event in state.activity_log:
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
