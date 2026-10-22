from __future__ import annotations

import time
from collections.abc import Callable
from datetime import UTC, datetime

from telethon.errors import PasswordHashInvalidError, SessionPasswordNeededError
from telethon.sessions import StringSession
from telethon.tl.functions.account import GetPasswordRequest
from telethon.tl.types.auth import LoginTokenMigrateTo, LoginTokenSuccess

from tgcli.client import create_client
from tgcli.config import load_session_store
from tgcli.session import delete_session, load_session, save_session, session_path


async def login() -> None:
    """Interactive login: phone + code/2FA. Saves the local session."""
    client = create_client()
    try:
        await client.start(phone=lambda: input("Phone number: "))
        session_str = StringSession.save(client.session)
        save_session(session_str)
    finally:
        await client.disconnect()


async def login_qr(
    on_url: Callable[[str], None],
    password: Callable[[str | None], str],
    timeout: float = 300.0,
) -> None:
    """QR login approved from an already authorized device. Saves the local session.

    on_url is called with each tg://login URL, again whenever the token rotates.
    password is called with the account's password hint, if it has one.
    """
    client = create_client()
    try:
        await client.connect()
        if not await client.is_user_authorized():
            await _wait_for_qr_scan(client, on_url, password, timeout)
        save_session(StringSession.save(client.session))
    finally:
        await client.disconnect()


async def _wait_for_qr_scan(client, on_url, password, timeout: float) -> None:
    qr = await client.qr_login()
    deadline = time.monotonic() + timeout
    try:
        while True:
            on_url(qr.url)
            ttl = (qr.expires - datetime.now(UTC)).total_seconds()
            remaining = deadline - time.monotonic()
            try:
                # recreate() returns the same token until it expires: wait out the TTL.
                await qr.wait(timeout=max(1.0, min(ttl, remaining)))
                return
            except TimeoutError:
                if time.monotonic() >= deadline:
                    raise TimeoutError(
                        f"No device scanned the QR code within {timeout:.0f}s."
                    ) from None
            await qr.recreate()
            # A scan that lands after wait() gave up is answered by recreate() instead.
            # QRLogin exposes that answer only as _resp.
            if isinstance(qr._resp, LoginTokenSuccess):
                return
            if isinstance(qr._resp, LoginTokenMigrateTo):
                raise RuntimeError(
                    "The code was scanned while it refreshed. Run `tg auth qr` again."
                )
    except SessionPasswordNeededError:
        hint = (await client(GetPasswordRequest())).hint
        for attempts_left in reversed(range(3)):
            try:
                await client.sign_in(password=password(hint))
                return
            except PasswordHashInvalidError:
                if not attempts_left:
                    raise


async def logout() -> None:
    """Log out and remove the local session.

    Always deletes the local session, even if the remote logout fails.
    """
    try:
        client = create_client()
        try:
            await client.connect()
            if await client.is_user_authorized():
                await client.log_out()
        finally:
            await client.disconnect()
    except Exception:  # noqa: S110
        pass
    delete_session()


def migrate_session(*, delete_keychain: bool = False) -> dict[str, object]:
    """Copy the legacy keychain session to the file backend."""
    legacy_session = load_session(store="keychain")
    if not legacy_session:
        return {
            "migrated": False,
            "deleted_keychain": False,
            "path": session_path(),
        }

    save_session(legacy_session, store="file")
    deleted_keychain = False
    if delete_keychain:
        delete_session(store="keychain")
        deleted_keychain = True

    return {
        "migrated": True,
        "deleted_keychain": deleted_keychain,
        "path": session_path(),
    }


async def get_status() -> dict:
    """Return auth status info.

    Returns dict with keys: authenticated, phone, session_exists.
    """
    session_store = load_session_store()
    session_exists = load_session(store=session_store) is not None

    if not session_exists:
        return {
            "authenticated": False,
            "phone": None,
            "session_exists": False,
            "session_store": session_store,
        }

    client = create_client()
    try:
        await client.connect()
        authorized = await client.is_user_authorized()
        phone = None
        if authorized:
            me = await client.get_me()
            if me and me.phone:
                # Mask phone: show first 3 and last 2 digits
                p = me.phone
                if len(p) > 5:
                    phone = p[:3] + "*" * (len(p) - 5) + p[-2:]
                else:
                    phone = p
    finally:
        await client.disconnect()

    return {
        "authenticated": authorized,
        "phone": phone,
        "session_exists": session_exists,
        "session_store": session_store,
    }
