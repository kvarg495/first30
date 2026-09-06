from __future__ import annotations

import streamlit as st


def render_checklist(items: list[str], key_prefix: str, *, disabled: bool = False) -> bool:
    """Render a stable per-case checklist and report whether every item is checked."""
    checked: list[bool] = []
    for index, item in enumerate(items):
        key = f"{key_prefix}_{index}"
        if disabled:
            st.session_state[key] = True
        checked.append(
            st.checkbox(
                item,
                key=key,
                disabled=disabled,
                wrap=True,
                persist_state="session",
            )
        )
    return all(checked)
