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
    |-- assess risk
    |-- plan and prioritise
    |-- choose next action
    |-- execute mocked tool
    `-- review state and replan
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
|   |   `-- registry.py
|   |-- data/
|   |   `-- singapore_guidance.py
|   `-- utils/
|       `-- llm.py
`-- tests/
    `-- test_scenarios.py
```

## Quick start

1. Create and activate a virtual environment.
2. Install dependencies with `pip install -r requirements.txt`.
3. Copy `.env.example` to `.env` and add a Groq key if you want to extend the rule-based starter with LLM reasoning.
4. Run `streamlit run app.py`.
5. Run tests with `pytest`.

The starter works deterministically without sending incident details to an LLM. `src/utils/llm.py` provides optional Groq and Bedrock model wiring for the team to use as it develops the assessor, planner, or reviewer.

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

