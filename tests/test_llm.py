from src.utils.llm import get_analysis_configuration


def test_bedrock_configuration_requires_identity_center_profile(monkeypatch) -> None:
    monkeypatch.setenv("LLM_PROVIDER", "bedrock")
    monkeypatch.setenv("AWS_PROFILE", "first30-bedrock")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "ignored-static-key")

    config = get_analysis_configuration()

    assert config["credentials_available"] is True
    assert config["aws_profile"] == "first30-bedrock"


def test_static_aws_keys_do_not_count_as_bedrock_configuration(monkeypatch) -> None:
    monkeypatch.setenv("LLM_PROVIDER", "bedrock")
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "legacy-static-key")

    config = get_analysis_configuration()

    assert config["credentials_available"] is False
    assert config["aws_profile"] == ""
