# First30

**Every minute matters.** First30 is a Singapore-focused scam incident-response agent for people who have already been scammed or exposed sensitive information.

This repository is a proof-of-concept starter for the SimplifyNext Agentic AI Hackathon. It demonstrates the core loop:

`intake -> assess -> plan -> choose action -> use tool -> review state -> replan`

It intentionally uses mocked recovery tools. It never asks for banking passwords, Singpass passwords, OTPs, or card PINs. Each action has two explicit stages: First30 prepares a local draft or official hand-off, then the user confirms whether they completed the real-world step themselves.

The response is context-sensitive: an OTP is classified by its likely use (bank transaction, Singpass, account recovery, or unknown) before a containment action is selected. A Singpass-related OTP does not create a bank-card action unless the incident also indicates a transfer or bank/card exposure.

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
3. Copy `.env.example` to `.env`. Add the three temporary AWS credentials from the hackathon access portal, or a Groq key, to enable optional LLM classification and planning.
4. Run `python -m streamlit run app.py`.
5. Run tests with `python -m pytest -q`.

The application works deterministically without sending incident details to an LLM. When Groq or Bedrock credentials are explicitly configured, the assessor uses structured output to classify the narrative and the planner orders only the tools allowed by the curated response guide. Invalid output or model failure falls back to deterministic rules.

## Agent loop

The graph follows this controlled cycle:

```text
assess -> plan -> select -> execute -> observe/review
             ^                         |
             `---------- replan -------'
```

`IncidentState` is the shared source of truth. It retains redacted incident facts, risks, prepared and completed action IDs, structured tool results, the activity log, and the current plan version. A tool result means guidance has been prepared; it never means that a bank, Singpass, email, or police action was performed. `continue_incident(...)` resumes the same state when the user confirms, skips, or adds new information, without losing prior work.

## Case preparation

The UI keeps ScamShield guidance visible, gives one concise reason for the current priority, and advances through an existing case without repeatedly reassessing it. Evidence preparation is preservation guidance only: First30 does not collect or upload screenshots. Police-report preparation shows copyable SPF-style field suggestions drawn from the original incident facts. Trusted-contact drafts are channel-appropriate and editable. The prototype links to official services but does not sign in, upload evidence, submit reports, or send messages.

The LLM is deliberately bounded: it can classify into known exposure categories and order an incident-specific allow-list, but curated code owns severity, official guidance, available tools, confirmation requirements, and the rule that containment precedes documentation.

## Demo scenario

Try:

> I clicked a fake parcel delivery website and entered my DBS credit-card details, OTP and Gmail password.

The graph should identify critical financial exposure, let the user prepare a bank/card hand-off, show the official link and call script, wait for the user to confirm the external step, then move through evidence and report drafts.

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
- Hackathon LLM: AWS Bedrock / Amazon Nova Micro
- Optional fallback LLM: Groq / GPT-OSS 120B
- Tools: mocked Python functions
- Knowledge: curated Singapore scam-response guidance
- Secrets: local `.env`, excluded from Git
