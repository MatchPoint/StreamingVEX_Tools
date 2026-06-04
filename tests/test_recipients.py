"""Tests for encryption recipient API client."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from streamingvex_tools.pusher.recipients import fetch_encryption_recipients


def test_fetch_encryption_recipients_success() -> None:
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = [
        {"fingerprint": "ABCD", "pgp_public_key_armored": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"},
    ]
    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.__exit__.return_value = False
    mock_client.get.return_value = mock_resp

    with patch("streamingvex_tools.pusher.recipients.httpx.Client", return_value=mock_client):
        rows = fetch_encryption_recipients(
            base_url="http://127.0.0.1:8000",
            api_key="svx_test",
            scope="prod",
        )

    assert len(rows) == 1
    mock_client.get.assert_called_once()
    call_kwargs = mock_client.get.call_args
    assert call_kwargs[0][0].endswith("/v1/supplier/me/encryption-recipients")
    assert call_kwargs[1]["headers"]["X-Supplier-API-Key"] == "svx_test"
    assert call_kwargs[1]["params"] == {"scope": "prod"}


def test_fetch_encryption_recipients_empty_raises() -> None:
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = []
    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.__exit__.return_value = False
    mock_client.get.return_value = mock_resp

    with patch("streamingvex_tools.pusher.recipients.httpx.Client", return_value=mock_client):
        with pytest.raises(RuntimeError, match="no approved encryption recipients"):
            fetch_encryption_recipients(base_url="http://127.0.0.1:8000", api_key="svx_test")


def test_fetch_encryption_recipients_http_error() -> None:
    mock_resp = MagicMock()
    mock_resp.status_code = 403
    mock_resp.text = "forbidden"
    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.__exit__.return_value = False
    mock_client.get.return_value = mock_resp

    with patch("streamingvex_tools.pusher.recipients.httpx.Client", return_value=mock_client):
        with pytest.raises(RuntimeError, match="encryption-recipients failed"):
            fetch_encryption_recipients(base_url="http://127.0.0.1:8000", api_key="svx_bad")
