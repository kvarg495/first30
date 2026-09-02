from __future__ import annotations

import os

from dotenv import load_dotenv


def get_chat_model():
    """Return the configured optional LLM without loading credentials at import time."""
    load_dotenv()
    provider = os.getenv("LLM_PROVIDER", "groq").casefold()

    if provider == "groq":
        from langchain_groq import ChatGroq

        return ChatGroq(
            model=os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"),
            temperature=0,
        )

    if provider == "bedrock":
        from langchain_aws import ChatBedrock

        return ChatBedrock(
            model_id=os.getenv("BEDROCK_MODEL_ID", "anthropic.claude-3-haiku-20240307-v1:0"),
            region_name=os.getenv("AWS_REGION", "ap-southeast-1"),
            model_kwargs={"temperature": 0},
        )

    raise ValueError(f"Unsupported LLM_PROVIDER: {provider}")

