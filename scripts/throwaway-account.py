#!/usr/bin/env python3
"""Create, log in, and delete a throwaway cloistr-signer account for live checks.

Use this instead of a shared test account: a shared account can be logged in
(and its key held) by another session mid-check, which silently changes what
a live test measures.

    scripts/throwaway-account.py create  CREDFILE           # register; creds -> CREDFILE (0600)
    scripts/throwaway-account.py login   CREDFILE TOKFILE   # session token -> TOKFILE (0600)
    scripts/throwaway-account.py delete  CREDFILE           # delete account + keys, shred CREDFILE

Nothing secret is ever printed: only the generated username. Usernames always
start with "throwaway-", and delete refuses any other name.

Registration creates and unlocks a signing key on the replica that served it;
login unlocks it on the replica that serves the login. With two replicas these
can differ, so a live test that needs exactly ONE replica holding the key must
account for both (check the pod logs for "created initial signing key" and
"loaded passphrase-wrapped keys").

delete runs one guarded DELETE against the signer database from a short-lived
postgres pod in the cloistr namespace (kubectl access required). The account's
Vault userpass entry, provisioned at registration, is not removed (that needs
Vault admin rights).

SIGNER_BASE overrides the API base URL (default https://signer.cloistr.xyz).
"""
import base64
import json
import os
import re
import secrets
import subprocess
import sys
import urllib.error
import urllib.request

BASE = os.environ.get("SIGNER_BASE", "https://signer.cloistr.xyz")
PREFIX = "throwaway-"
NAME_RE = re.compile(r"^throwaway-[0-9a-f]{8}$")


def call(method, path, body=None, token=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=40) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:
            return e.code, {}


def write_private(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.write(fd, text.encode())
    os.close(fd)


def read_creds(path):
    with open(path) as f:
        user, pw = [line.rstrip("\n") for line in f.readlines()[:2]]
    return user, pw


def create(cred):
    user = PREFIX + secrets.token_hex(4)
    pw = secrets.token_urlsafe(24)
    st, resp = call("POST", "/api/v1/users/register", {"username": user, "password": pw})
    if st not in (200, 201):
        sys.exit(f"register failed: HTTP {st} {resp.get('error', '')}")
    write_private(cred, f"{user}\n{pw}\n")
    print(user)


def login(cred, tok):
    user, pw = read_creds(cred)
    st, resp = call("POST", "/api/v1/users/login", {"username": user, "password": pw})
    if st != 200 or not resp.get("token"):
        sys.exit(f"login failed: HTTP {st} {resp.get('error', '')}")
    write_private(tok, resp["token"])
    print(f"logged in {user}")


def database_url():
    raw = subprocess.run(
        ["kubectl", "-n", "cloistr", "get", "secret", "signer-secret", "-o", "jsonpath={.data.database-url}"],
        capture_output=True, text=True, check=True).stdout
    return base64.b64decode(raw).decode()


def delete(cred):
    user, _ = read_creds(cred)
    # Only names this script generates; nothing else can reach the SQL below.
    if not NAME_RE.match(user):
        sys.exit(f"refusing to delete {user!r}: not a {PREFIX}* account made by this script")
    sql = f"""\\set ON_ERROR_STOP on
begin;
delete from signer_permissions where key_id in (
  select k.pubkey from signer_keys k join signer_web_accounts a on k.owner_id = a.id
   where a.username = '{user}' and a.username like '{PREFIX}%');
delete from signer_web_accounts where username = '{user}' and username like '{PREFIX}%';
select 'remaining=' || count(*) from signer_web_accounts where username = '{user}';
commit;
"""
    out = subprocess.run(
        ["kubectl", "-n", "cloistr", "run", "throwaway-del-" + secrets.token_hex(3), "--rm", "-i",
         "--restart=Never", "--quiet", "--image=postgres:16-alpine", "--env=DBURL=" + database_url(),
         "--command", "--", "sh", "-c", 'psql "$DBURL" -X -t -A -f -'],
        input=sql, capture_output=True, text=True)
    if out.returncode != 0 or "remaining=0" not in out.stdout:
        sys.exit(f"delete failed: {out.stderr.strip()[:200]}")
    subprocess.run(["shred", "-u", cred], check=False)
    print(f"deleted {user}")


if __name__ == "__main__":
    args = sys.argv[1:]
    if args[:1] == ["create"] and len(args) == 2:
        create(args[1])
    elif args[:1] == ["login"] and len(args) == 3:
        login(args[1], args[2])
    elif args[:1] == ["delete"] and len(args) == 2:
        delete(args[1])
    else:
        sys.exit(__doc__)
