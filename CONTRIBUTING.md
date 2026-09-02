# Contributing

Agree on the incident input, tool response, and final graph response schemas before extending the prototype. Keep ownership separated by architectural layer to reduce merge conflicts.

## Suggested branches and ownership

| Branch | Scope | Primary files |
|---|---|---|
| `agent-workflow` | Agent reasoning and LangGraph | `src/state.py`, `src/graph.py`, `src/agents/`, `src/utils/llm.py` |
| `tools` | Recovery tools and Singapore guidance | `src/tools/`, `src/data/` |
| `frontend` | Streamlit experience and demo flow | `app.py`, optional `src/ui/` |

Integrate frequently in this order when dependencies require it: tools, agent workflow, frontend, then main.

## Shared interfaces

Incident input:

```python
{
    "description": "...",
    "selected_exposures": ["card_details", "otp"],
}
```

Tool response:

```python
{
    "success": True,
    "action": "prepare_bank_freeze",
    "message": "Card freeze workflow prepared",
    "requires_confirmation": True,
}
```

Graph output is the validated `IncidentState` model in `src/state.py`.

## Pull requests

- Keep changes inside your owned layer where possible.
- Add or update a scenario test for behavioural changes.
- Never commit `.env` files or real credentials.
- Do not replace mock actions with real consequential integrations without a security review.

