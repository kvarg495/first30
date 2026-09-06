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
3. [Configure an AWS IAM Identity Center profile](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html) with `aws configure sso --profile first30-bedrock`. Choose an account and permission set with access to the configured Amazon Bedrock model.
4. Sign in and cache the session with `aws sso login --profile first30-bedrock`.
5. Copy `.env.example` to `.env`. Set `AWS_PROFILE` to the profile name from step 3. Do not add `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, or `AWS_SESSION_TOKEN`; environment credentials take precedence over the Identity Center provider.
6. Run `python -m streamlit run app.py`.
7. Run tests with `python -m pytest -q`.

The application works deterministically without sending incident details to an LLM. When the Bedrock Identity Center profile is signed in, Amazon Nova Lite can assess the structured intake and consented screenshots in one bounded multimodal request. The AWS SDK retrieves and refreshes the role credentials from the cached Identity Center session; rerun `aws sso login --profile first30-bedrock` when the portal session itself expires. Explicit user-entered facts take precedence over model or image inference. Invalid output or model failure falls back to deterministic rules and marks screenshots as not analysed.

## Agent loop

The graph follows this controlled cycle:

```text
assess -> plan -> select -> execute -> observe/review
             ^                         |
             `---------- replan -------'
```

`IncidentState` is the shared source of truth. It retains redacted incident facts, risks, prepared and completed action IDs, structured tool results, the activity log, and the current plan version. A tool result means guidance has been prepared; it never means that a bank, Singpass, email, or police action was performed. `continue_incident(...)` resumes the same state when the user confirms, skips, or adds new information, without losing prior work.

## Case preparation

The two-page UI keeps an editable Incident Details intake separate from a tile-based Response Dashboard. ScamShield guidance remains visible, each risk and recovery step opens in a dialog, and human-confirmed completion drives the segmented progress display. Evidence preparation is preservation guidance only. Police-report preparation shows copyable SPF-style field suggestions, and trusted-contact drafts are channel-appropriate and editable. The prototype links to official services but does not sign in, upload evidence to official services, submit reports, or send messages.

Uploaded screenshots are validated and re-encoded in memory with Pillow, which strips metadata and limits image size. Bytes remain only in Streamlit session memory and are transmitted to Bedrock only after explicit acknowledgement; they are never stored in `IncidentState`, on disk, in logs, or in Git.

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
- Hackathon LLM: AWS Bedrock / Amazon Nova Lite (text and image input)
- Optional fallback LLM: Groq / GPT-OSS 120B
- Tools: mocked Python functions
- Knowledge: curated Singapore scam-response guidance
- AWS authentication: IAM Identity Center profile, with the local `.env` containing only the non-secret profile name and model configuration
