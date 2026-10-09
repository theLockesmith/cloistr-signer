"""Tests for scripts/throwaway-account.py (run: python3 -m pytest scripts/)."""
import importlib.util
import os
import stat
import subprocess

import pytest

_spec = importlib.util.spec_from_file_location(
    "throwaway_account", os.path.join(os.path.dirname(__file__), "throwaway-account.py"))
ta = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ta)


def test_delete_refuses_non_throwaway_account(tmp_path, monkeypatch):
    cred = tmp_path / "creds"
    cred.write_text("arbiter-tester\nsecret\n")
    monkeypatch.setattr(ta, "call", lambda *a, **k: pytest.fail("API called for a real account"))
    with pytest.raises(SystemExit):
        ta.delete(str(cred))
    assert cred.exists(), "must not shred the creds of an account it refused"


def test_delete_refuses_malformed_name(tmp_path, monkeypatch):
    cred = tmp_path / "creds"
    cred.write_text("throwaway-x' or '1'='1\nsecret\n")
    monkeypatch.setattr(ta, "call", lambda *a, **k: pytest.fail("API called"))
    with pytest.raises(SystemExit):
        ta.delete(str(cred))


def test_delete_uses_self_delete_api_and_shreds_creds(tmp_path, monkeypatch):
    cred = tmp_path / "creds"
    cred.write_text("throwaway-0123abcd\npw-123\n")
    calls = []

    def fake_call(method, path, body=None, token=None):
        calls.append((method, path, body, token))
        if path == "/api/v1/users/login":
            return 200, {"token": "tok"}
        return 200, {"deleted": True}

    monkeypatch.setattr(ta, "call", fake_call)
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: os.remove(a[0][-1]))
    ta.delete(str(cred))

    assert calls[0][:2] == ("POST", "/api/v1/users/login")
    assert calls[1] == ("DELETE", "/api/v1/users/me",
                        {"password": "pw-123", "confirm": "throwaway-0123abcd"}, "tok")
    assert not cred.exists(), "creds file must be shredded after deletion"


def test_delete_keeps_creds_when_api_refuses(tmp_path, monkeypatch):
    cred = tmp_path / "creds"
    cred.write_text("throwaway-0123abcd\npw-123\n")

    def fake_call(method, path, body=None, token=None):
        if path == "/api/v1/users/login":
            return 200, {"token": "tok"}
        return 500, {"error": "account deletion did not complete"}

    monkeypatch.setattr(ta, "call", fake_call)
    with pytest.raises(SystemExit):
        ta.delete(str(cred))
    assert cred.exists(), "keep the creds so the deletion can be retried"


def test_create_writes_private_creds_and_prints_only_username(tmp_path, monkeypatch, capsys):
    sent = {}

    def fake_call(method, path, body=None, token=None):
        sent.update(body)
        return 201, {}

    monkeypatch.setattr(ta, "call", fake_call)
    cred = tmp_path / "creds"
    ta.create(str(cred))

    user, pw = cred.read_text().splitlines()
    assert user.startswith("throwaway-") and user == sent["username"] and pw == sent["password"]
    assert stat.S_IMODE(cred.stat().st_mode) == 0o600
    out = capsys.readouterr().out
    assert out.strip() == user and pw not in out


def test_write_private_is_owner_only(tmp_path):
    p = tmp_path / "tok"
    ta.write_private(str(p), "t")
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
