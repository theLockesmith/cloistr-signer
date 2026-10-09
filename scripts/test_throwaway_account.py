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
    called = []
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: called.append(a))
    with pytest.raises(SystemExit):
        ta.delete(str(cred))
    assert called == [], "must not touch the cluster for a real account"
    assert cred.exists(), "must not shred the creds of an account it refused"


def test_delete_refuses_injection_in_name(tmp_path, monkeypatch):
    cred = tmp_path / "creds"
    cred.write_text("throwaway-x' or '1'='1\nsecret\n")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("cluster touched"))
    with pytest.raises(SystemExit):
        ta.delete(str(cred))


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
