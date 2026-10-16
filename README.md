# First30

First30 is a Singapore-focused scam-response prototype. It helps someone who has already shared sensitive information or lost money work out which accounts may be at risk and what to do next.

We built it for the SimplifyNext Agentic AI Hackathon 2026. It prepares guidance, drafts and links to official services. It does not contact banks, freeze accounts, submit police reports or recover money.

## My contribution

I'm [Aryan Sharma](https://github.com/Aryann-Sharma), one of the team members. I worked on the Streamlit interface: risk displays, action-progress indicators, confirmation controls, a demo scenario and in-app help. I connected the interface to the shared incident state and response workflow.

The [interface commit](https://github.com/kvarg495/first30/commit/f51610b9aa527fffe3d7cb65b70b76ac8372bf70) and [help-page commit](https://github.com/kvarg495/first30/commit/f9c0f8483932a4918bd93e62c95332011c99c3ad) show this work. LangGraph orchestration, recovery tools and model integration were part of the wider team project.

## What the app does

- Collects an incident description and the types of information exposed.
- Shows the identified risks and a prioritised response plan.
- Prepares account-security guidance, evidence checklists, reporting suggestions and trusted-contact drafts.
- Tracks which steps the user has prepared, completed or skipped.
- Reassesses the plan when the user adds information.
- Optionally reads consented screenshots through Amazon Bedrock.

The app separates preparing guidance from confirming that a real-world step is complete. For example, preparing bank-security instructions does not mean that a bank card has been blocked.

## How it works

```text
Streamlit intake
    -> Pydantic incident state
    -> assessment
    -> plan and next action
    -> mocked tool / local draft
    -> user confirmation or new information
```

LangGraph manages the workflow. Curated rules control severity, allowed tools and action ordering. The optional model helps assess the incident; invalid output or a model failure falls back to local rules.

The stack is Python, Streamlit, Pydantic and LangGraph, with Amazon Bedrock / Nova Lite for optional text and image input. A Groq model adapter is also available. Tool functions prepare local guidance and drafts.

## Run locally

Use Python 3.13. From the repository root:

```text
python -m venv .venv
```

Activate the environment:

```powershell
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
```

```bash
# macOS or Linux
source .venv/bin/activate
```

Install dependencies and start the app:

```text
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

Leave `AWS_PROFILE` and LLM credentials unconfigured to use the deterministic local workflow. This mode does not analyse screenshot contents with a model.

### Optional Bedrock setup

1. Configure an AWS IAM Identity Center profile with access to the configured Bedrock model: `aws configure sso --profile first30-bedrock`.
2. Sign in with `aws sso login --profile first30-bedrock`.
3. Copy `.env.example` to `.env` and set `AWS_PROFILE` to the profile name. Keep the Bedrock provider and model settings, then restart the app.

Do not put access keys or session tokens in `.env`; environment credentials can override the profile. If the portal session expires, run the login command again.

Explicit user-entered facts take precedence over model or image inference. Screenshots are validated and re-encoded in memory before any consented model request. Their bytes are not saved in the incident state or on disk.

## Try a scenario

Describe an incident where you entered bank-card details and an OTP on a fake bank website, but have not noticed a transfer. Select the matching exposure categories.

The plan should prioritise securing the bank/card, then show evidence-preservation guidance and reporting/support steps. A Singpass-only exposure should not produce a bank-card action unless bank details or a transfer are also involved.

Use made-up details for the demo. Do not enter passwords, actual OTPs, card PINs or full payment credentials.

## Tests

```text
python -m pytest -q
```

The tests cover workflow state, incident scenarios, tool results, image validation, model configuration, official links and the Streamlit UI. The repository currently has no GitHub Actions workflow; these are local tests.

## Limits

This is a hackathon prototype with mocked recovery actions, not a live incident-response service. The curated guidance needs review before production use. Screenshot analysis can fail or miss information, so the user must check the incident details and take real actions through official channels.

Source layout: `app.py` and `src/ui/` contain the interface, `src/graph.py` the workflow, `src/agents/` the assessment/planning code, and `src/tools/` the mocked tools. See [CONTRIBUTING](https://github.com/kvarg495/first30/blob/main/CONTRIBUTING.md) for the team's interfaces and development notes.
