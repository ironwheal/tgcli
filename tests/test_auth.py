from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from telethon.errors import PasswordHashInvalidError, SessionPasswordNeededError
from telethon.tl.types.auth import LoginTokenMigrateTo, LoginTokenSuccess

from tgcli.auth import get_status, login, login_qr, logout, migrate_session


class TestLogin:
    @patch("tgcli.auth.save_session")
    @patch("tgcli.auth.StringSession")
    @patch("tgcli.auth.create_client")
    async def test_login_saves_session(self, mock_create, mock_ss, mock_save):
        client = AsyncMock()
        mock_create.return_value = client
        mock_ss.save.return_value = "saved_session"

        await login()

        client.start.assert_awaited_once()
        mock_save.assert_called_once_with("saved_session")
        client.disconnect.assert_awaited_once()


def _qr_client(*wait_effects):
    qr = MagicMock()
    qr.url = "tg://login?token=abc"
    qr.expires = datetime.now(UTC) + timedelta(seconds=30)
    qr.wait = AsyncMock(side_effect=list(wait_effects))
    qr.recreate = AsyncMock()
    client = AsyncMock()
    client.is_user_authorized = AsyncMock(return_value=False)
    client.qr_login = AsyncMock(return_value=qr)
    return client, qr


@patch("tgcli.auth.save_session")
@patch("tgcli.auth.StringSession")
@patch("tgcli.auth.create_client")
class TestLoginQr:
    async def test_scan_saves_session(self, mock_create, mock_ss, mock_save):
        client, qr = _qr_client(None)
        mock_create.return_value = client
        mock_ss.save.return_value = "saved_session"
        urls = []

        await login_qr(urls.append, lambda hint: "unused")

        assert urls == ["tg://login?token=abc"]
        assert 29 <= qr.wait.await_args.kwargs["timeout"] <= 30
        mock_save.assert_called_once_with("saved_session")
        client.disconnect.assert_awaited_once()

    async def test_expired_token_still_waits_a_second(
        self, mock_create, mock_ss, mock_save
    ):
        client, qr = _qr_client(None)
        qr.expires = datetime.now(UTC) - timedelta(seconds=5)
        mock_create.return_value = client

        await login_qr(lambda url: None, lambda hint: "unused")

        assert qr.wait.await_args.kwargs["timeout"] == 1.0

    async def test_already_authorized_skips_qr(self, mock_create, mock_ss, mock_save):
        client, qr = _qr_client()
        client.is_user_authorized.return_value = True
        mock_create.return_value = client

        await login_qr(lambda url: None, lambda hint: "unused")

        client.qr_login.assert_not_awaited()
        mock_save.assert_called_once()

    async def test_scan_during_refresh_completes(self, mock_create, mock_ss, mock_save):
        client, qr = _qr_client(TimeoutError())
        qr.recreate.side_effect = lambda: setattr(
            qr, "_resp", LoginTokenSuccess(authorization=None)
        )
        mock_create.return_value = client

        await login_qr(lambda url: None, lambda hint: "unused")

        mock_save.assert_called_once()

    async def test_scan_during_refresh_with_dc_migration_fails(
        self, mock_create, mock_ss, mock_save
    ):
        client, qr = _qr_client(TimeoutError())
        qr.recreate.side_effect = lambda: setattr(
            qr, "_resp", LoginTokenMigrateTo(dc_id=2, token=b"t")
        )
        mock_create.return_value = client

        with pytest.raises(RuntimeError, match="scanned while it refreshed"):
            await login_qr(lambda url: None, lambda hint: "unused")

        mock_save.assert_not_called()

    async def test_2fa_during_refresh(self, mock_create, mock_ss, mock_save):
        client, qr = _qr_client(TimeoutError())
        qr.recreate.side_effect = SessionPasswordNeededError(request=None)
        mock_create.return_value = client

        await login_qr(lambda url: None, lambda hint: "secret")

        client.sign_in.assert_awaited_once_with(password="secret")  # noqa: S106
        mock_save.assert_called_once()

    async def test_expired_token_rotates(self, mock_create, mock_ss, mock_save):
        client, qr = _qr_client(TimeoutError(), None)
        mock_create.return_value = client
        urls = []

        await login_qr(urls.append, lambda hint: "unused")

        qr.recreate.assert_awaited_once()
        assert len(urls) == 2
        mock_save.assert_called_once()

    async def test_2fa_asks_for_password(self, mock_create, mock_ss, mock_save):
        client, qr = _qr_client(SessionPasswordNeededError(request=None))
        client.return_value = SimpleNamespace(hint="dog's name")
        mock_create.return_value = client
        hints = []

        await login_qr(lambda url: None, lambda hint: hints.append(hint) or "secret")

        assert hints == ["dog's name"]
        client.sign_in.assert_awaited_once_with(password="secret")  # noqa: S106
        mock_save.assert_called_once()

    async def test_wrong_password_retries(self, mock_create, mock_ss, mock_save):
        client, qr = _qr_client(SessionPasswordNeededError(request=None))
        client.sign_in.side_effect = [PasswordHashInvalidError(request=None), None]
        mock_create.return_value = client

        await login_qr(lambda url: None, lambda hint: "secret")

        assert client.sign_in.await_count == 2
        mock_save.assert_called_once()

    async def test_wrong_password_three_times_fails(
        self, mock_create, mock_ss, mock_save
    ):
        client, qr = _qr_client(SessionPasswordNeededError(request=None))
        client.sign_in.side_effect = PasswordHashInvalidError(request=None)
        mock_create.return_value = client

        with pytest.raises(PasswordHashInvalidError):
            await login_qr(lambda url: None, lambda hint: "secret")

        assert client.sign_in.await_count == 3
        mock_save.assert_not_called()

    async def test_deadline_raises(self, mock_create, mock_ss, mock_save):
        client, qr = _qr_client(TimeoutError())
        mock_create.return_value = client

        with pytest.raises(TimeoutError, match="within 0s"):
            await login_qr(lambda url: None, lambda hint: "unused", timeout=0)

        mock_save.assert_not_called()
        client.disconnect.assert_awaited_once()


class TestLogout:
    @patch("tgcli.auth.delete_session")
    @patch("tgcli.auth.create_client")
    async def test_logout_authorized(self, mock_create, mock_delete):
        client = AsyncMock()
        client.is_user_authorized = AsyncMock(return_value=True)
        mock_create.return_value = client

        await logout()

        client.log_out.assert_awaited_once()
        mock_delete.assert_called_once()

    @patch("tgcli.auth.delete_session")
    @patch("tgcli.auth.create_client")
    async def test_logout_not_authorized(self, mock_create, mock_delete):
        client = AsyncMock()
        client.is_user_authorized = AsyncMock(return_value=False)
        mock_create.return_value = client

        await logout()

        client.log_out.assert_not_awaited()
        mock_delete.assert_called_once()

    @patch("tgcli.auth.delete_session")
    @patch("tgcli.auth.create_client")
    async def test_logout_deletes_session_when_client_fails(
        self, mock_create, mock_delete
    ):
        """Local session should be deleted even if remote logout fails."""
        mock_create.side_effect = RuntimeError("no config")

        await logout()

        mock_delete.assert_called_once()


class TestMigrateSession:
    @patch("tgcli.auth.session_path")
    @patch("tgcli.auth.save_session")
    @patch("tgcli.auth.load_session")
    def test_migrates_keychain_session(self, mock_load, mock_save, mock_path):
        mock_load.return_value = "legacy_session"
        mock_path.return_value = "/tmp/session"

        result = migrate_session()

        mock_load.assert_called_once_with(store="keychain")
        mock_save.assert_called_once_with("legacy_session", store="file")
        assert result == {
            "migrated": True,
            "deleted_keychain": False,
            "path": "/tmp/session",
        }

    @patch("tgcli.auth.delete_session")
    @patch("tgcli.auth.session_path")
    @patch("tgcli.auth.save_session")
    @patch("tgcli.auth.load_session")
    def test_migrates_and_deletes_keychain(
        self, mock_load, mock_save, mock_path, mock_delete
    ):
        mock_load.return_value = "legacy_session"
        mock_path.return_value = "/tmp/session"

        result = migrate_session(delete_keychain=True)

        mock_save.assert_called_once_with("legacy_session", store="file")
        mock_delete.assert_called_once_with(store="keychain")
        assert result["deleted_keychain"] is True

    @patch("tgcli.auth.session_path")
    @patch("tgcli.auth.save_session")
    @patch("tgcli.auth.load_session")
    def test_missing_keychain_session(self, mock_load, mock_save, mock_path):
        mock_load.return_value = None
        mock_path.return_value = "/tmp/session"

        result = migrate_session()

        mock_save.assert_not_called()
        assert result == {
            "migrated": False,
            "deleted_keychain": False,
            "path": "/tmp/session",
        }


class TestGetStatus:
    @patch("tgcli.auth.create_client")
    @patch("tgcli.auth.load_session_store", return_value="file")
    @patch("tgcli.auth.load_session", return_value=None)
    async def test_no_session(self, mock_load, mock_store, mock_create):
        result = await get_status()

        assert result == {
            "authenticated": False,
            "phone": None,
            "session_exists": False,
            "session_store": "file",
        }
        mock_load.assert_called_once_with(store="file")
        mock_create.assert_not_called()

    @patch("tgcli.auth.create_client")
    @patch("tgcli.auth.load_session_store", return_value="file")
    @patch("tgcli.auth.load_session", return_value="some_session")
    async def test_authenticated_with_phone(self, mock_load, mock_store, mock_create):
        client = AsyncMock()
        client.is_user_authorized = AsyncMock(return_value=True)
        client.get_me = AsyncMock(return_value=SimpleNamespace(phone="12345678901"))
        mock_create.return_value = client

        result = await get_status()

        assert result["authenticated"] is True
        assert result["session_exists"] is True
        assert result["session_store"] == "file"
        assert result["phone"] == "123******01"

    @patch("tgcli.auth.create_client")
    @patch("tgcli.auth.load_session_store", return_value="keychain")
    @patch("tgcli.auth.load_session", return_value="some_session")
    async def test_session_exists_but_not_authorized(
        self, mock_load, mock_store, mock_create
    ):
        client = AsyncMock()
        client.is_user_authorized = AsyncMock(return_value=False)
        mock_create.return_value = client

        result = await get_status()

        assert result["authenticated"] is False
        assert result["session_exists"] is True
        assert result["session_store"] == "keychain"
        mock_load.assert_called_once_with(store="keychain")
