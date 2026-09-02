# First30

**Every minute matters.** First30 is a Singapore-focused scam incident-response agent for people who have already been scammed or exposed sensitive information.

This repository is a proof-of-concept starter for the SimplifyNext Agentic AI Hackathon. It demonstrates the core loop:

`intake -> assess -> plan -> choose action -> use tool -> review state -> replan`

It intentionally uses mocked recovery tools. It never asks for banking passwords, Singpass passwords, OTPs, or card PINs, and consequential actions require explicit user approval or a hand-off to an official service.

## Architecture

```text
Streamlit UI
    |
Pydantic IncidentState
    |
LangGraph orchestrator
    |-- assess risk (curated rules + optional structured LLM)
    |-- plan and prioritise approved tools
    |-- choose next action
    |-- execute mocked tool
    `-- store observation and replan
         |
         |-- bank action mock
         |-- account action mock
         |-- evidence tool mock
         `-- reporting tool mock
```

## Project structure

```text
first30/
|-- app.py
|-- requirements.txt
|-- .env.example
|-- README.md
|-- CONTRIBUTING.md
|-- src/
|   |-- state.py
|   |-- graph.py
|   |-- agents/
|   |   |-- assessor.py
|   |   |-- planner.py
|   |   `-- reviewer.py
|   |-- tools/
|   |   |-- bank_tools.py
|   |   |-- reporting_tools.py
|   |   |-- account_tools.py
|   |   |-- evidence_tools.py
|   |   |-- notification_tools.py
|   |   `-- registry.py
|   |-- data/
|   |   `-- singapore_guidance.py
|   `-- utils/
|       `-- llm.py
`-- tests/
    |-- test_agent_workflow.py
    |-- test_scenarios.py
    `-- test_tools.py
```

## Quick start

1. Create and activate a virtual environment: `python3.13 -m venv .venv && source .venv/bin/activate`.
2. Install dependencies with `python -m pip install -r requirements.txt`.
3. Copy `.env.example` to `.env`. Add a Groq key to enable optional LLM classification and planning.
4. Run `streamlit run app.py`.
5. Run tests with `python -m pytest -q`.

The application works deterministically without sending incident details to an LLM. When Groq or Bedrock credentials are explicitly configured, the assessor uses structured output to classify the narrative and the planner orders only the tools allowed by the curated response guide. Invalid output or model failure falls back to deterministic rules.

## Agent loop

The graph follows this controlled cycle:

```text
assess -> plan -> select -> execute -> observe/review
             ^                         |
             `---------- replan -------'
```

`IncidentState` is the shared source of truth. It retains risks, approvals, completed action IDs, structured tool results, the activity log, and the current plan version. After each tool result the reviewer either finishes, stops safely, or routes back through the planner. `continue_incident(...)` can resume the same state after an approval or newly discovered information without losing completed work.

The LLM is deliberately bounded: it can classify into known exposure categories and order an incident-specific allow-list, but curated code owns severity, official guidance, available tools, confirmation requirements, and the rule that containment precedes documentation.

## Demo scenario

Try:

> I clicked a fake parcel delivery website and entered my DBS credit-card details, OTP and Gmail password.

The graph should identify critical financial exposure, require approval before preparing a bank/card action, preserve evidence, prepare a report, and keep reassessing until no actions remain.

## Safety boundaries

- Do not collect authentication secrets, OTPs, card PINs, or full payment credentials.
- Do not claim that First30 can recover funds.
- Keep bank, Singpass, ScamShield, and police interactions mocked for the POC.
- Require explicit confirmation before consequential actions.
- Link users to official services for real account or reporting actions.
- Treat the curated guidance as prototype data that must be verified before production use.

## Planned stack

- Frontend: Streamlit
- Backend: Python
- Orchestration: LangGraph
- State and schemas: Pydantic
- Development LLM: Groq
- Optional hackathon LLM: AWS Bedrock / Claude Haiku
- Tools: mocked Python functions
- Knowledge: curated Singapore scam-response guidance
- Secrets: local `.env`, excluded from Git
