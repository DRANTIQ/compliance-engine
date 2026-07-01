from __future__ import annotations

from platform_backend.platform.integrations.auth_errors import (
    collection_errors_indicate_auth_failure,
    is_azure_auth_error_text,
    is_azure_auth_failure,
    verify_failure_is_auth,
)


def test_is_azure_auth_error_text_detects_invalid_secret() -> None:
    assert is_azure_auth_error_text("AADSTS7000215: Invalid client secret is provided.")
    assert is_azure_auth_error_text("AuthenticationFailed: invalid_client")


def test_is_azure_auth_failure_honors_flag() -> None:
    assert is_azure_auth_failure({"auth_failure": True, "message": "anything"})
    assert not is_azure_auth_failure({"message": "Subscription Not Registered"})


def test_collection_errors_all_auth() -> None:
    errors = [
        {"plugin": "azure.storage", "error": "AuthenticationFailed: invalid_client"},
        {"plugin": "azure.network", "type": "ClientAuthenticationError", "error": "bad secret"},
    ]
    assert collection_errors_indicate_auth_failure(errors)


def test_collection_errors_mixed_not_all_auth() -> None:
    errors = [
        {"plugin": "azure.defender", "error": "Please register to Microsoft.Security"},
        {"plugin": "azure.storage", "error": "AuthenticationFailed: invalid_client"},
    ]
    assert not collection_errors_indicate_auth_failure(errors)


def test_verify_failure_is_auth_status_code() -> None:
    assert verify_failure_is_auth(message="forbidden", status_code=401)
    assert not verify_failure_is_auth(message="not found", status_code=404)
