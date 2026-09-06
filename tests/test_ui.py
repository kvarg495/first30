from pathlib import Path

from streamlit.testing.v1 import AppTest


NARRATIVE = "A caller impersonated the police and asked for my Singpass OTP, but I sent no money."


def app(monkeypatch) -> AppTest:
    monkeypatch.setenv("LLM_PROVIDER", "groq")
    monkeypatch.setenv("GROQ_API_KEY", "")
    return AppTest.from_file(Path(__file__).parents[1] / "app.py", default_timeout=20).run()


def test_intake_validates_narrative(monkeypatch) -> None:
    at = app(monkeypatch)
    assert not at.exception
    assert at.text_area[0].label == "Incident description"
    assert at.button(key="submit_incident").disabled is True
    at.text_area[0].set_value(NARRATIVE).run()
    assert at.button(key="submit_incident").disabled is False


def test_submission_redirects_to_fresh_dashboard(monkeypatch) -> None:
    at = app(monkeypatch)
    at.text_area[0].set_value(NARRATIVE).run()
    at.button(key="submit_incident").click().run()
    assert not at.exception
    assert at.session_state["incident"].case_revision == 1
    assert at.session_state["incident"].completed_action_ids == []
    labels = [button.label for button in at.button]
    assert any("ScamShield Check" in label for label in labels)
    assert any("ScamShield Report" in label for label in labels)
    assert any("Police Help" in label for label in labels)
    assert any("Secure Singpass access" in label for label in labels)
    assert not any("Secure your bank or card" in label for label in labels)


def test_dashboard_exposes_risk_and_step_tile_controls(monkeypatch) -> None:
    at = app(monkeypatch)
    at.text_area[0].set_value(NARRATIVE).run()
    at.button(key="submit_incident").click().run()
    assert not at.exception
    assert any("View supporting facts" in button.label for button in at.button)
    assert any("STEP 1" in button.label for button in at.button)


def test_evidence_checklist_unlocks_completion() -> None:
    at = AppTest.from_string(
        """
import streamlit as st
from src.ui.checklists import render_checklist

ready = render_checklist(
    ["Save screenshots", "Save call logs", "Keep originals"],
    "evidence_check_r1_action-create_evidence_summary",
)
st.button("Complete", key="complete", disabled=not ready)
"""
    ).run()

    checklist = list(at.checkbox)
    complete_key = "complete"
    assert len(checklist) == 3
    assert at.button(key=complete_key).disabled is True

    for item in checklist:
        at.checkbox(key=item.key).check().run()

    assert at.button(key=complete_key).disabled is False
    assert not at.exception
