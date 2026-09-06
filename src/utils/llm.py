from __future__ import annotations

import os
from typing import Any

from dotenv import load_dotenv


def get_chat_model():
    """Return the configured optional LLM without loading credentials at import time."""
    load_dotenv()
    provider = os.getenv("LLM_PROVIDER", "groq").casefold()

    if provider == "groq":
        from langchain_groq import ChatGroq

        return ChatGroq(
            model=os.getenv("GROQ_MODEL", "openai/gpt-oss-120b"),
            temperature=0,
        )

    if provider == "bedrock":
        from langchain_aws import ChatBedrockConverse

        return ChatBedrockConverse(
            model=os.getenv("BEDROCK_MODEL_ID", "amazon.nova-lite-v1:0"),
            region_name=os.getenv("AWS_REGION", "us-east-1"),
            temperature=0,
        )

    raise ValueError(f"Unsupported LLM_PROVIDER: {provider}")


def get_analysis_configuration() -> dict[str, str | bool]:
    """Return non-secret provider diagnostics suitable for the developer dialog."""
    load_dotenv()
    provider = os.getenv("LLM_PROVIDER", "groq").casefold()
    model = (
        os.getenv("BEDROCK_MODEL_ID", "amazon.nova-lite-v1:0")
        if provider == "bedrock"
        else os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
    )
    image_capable = provider == "bedrock" and any(
        family in model.casefold() for family in ("nova-lite", "nova-pro", "nova-premier")
    )
    credentials_available = bool(
        os.getenv("AWS_PROFILE")
        or os.getenv("AWS_ACCESS_KEY_ID")
        or os.getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
    ) if provider == "bedrock" else bool(os.getenv("GROQ_API_KEY"))
    return {
        "provider": provider,
        "model": model,
        "image_capable": image_capable,
        "credentials_available": credentials_available,
    }


def get_optional_chat_model() -> Any | None:
    """Return an LLM only when the user has explicitly configured one.

    The deterministic workflow remains available for local development and tests.
    Incident details are never sent to a model merely because the model packages
    are installed.
    """
    load_dotenv()
    provider = os.getenv("LLM_PROVIDER", "groq").casefold()

    if provider == "groq" and not os.getenv("GROQ_API_KEY"):
        return None

    if provider == "bedrock" and not (
        os.getenv("AWS_PROFILE")
        or os.getenv("AWS_ACCESS_KEY_ID")
        or os.getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
    ):
        return None

    return get_chat_model()
