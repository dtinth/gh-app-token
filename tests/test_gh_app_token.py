"""Tests for gh_app_token. Run with: python -m unittest discover -s tests"""

import contextlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import gh_app_token as g  # noqa: E402

OPENSSL = shutil.which("openssl")
TMP_ROOT = None
KEY_FILE = None


def setUpModule():
    global TMP_ROOT, KEY_FILE
    if not OPENSSL:
        raise unittest.SkipTest("openssl not available")
    TMP_ROOT = Path(tempfile.mkdtemp(prefix="gh-app-token-test-"))
    KEY_FILE = TMP_ROOT / "key.pem"
    subprocess.run([OPENSSL, "genrsa", "-out", str(KEY_FILE), "2048"], check=True, capture_output=True)
    KEY_FILE.chmod(0o600)


def tearDownModule():
    shutil.rmtree(TMP_ROOT, ignore_errors=True)


def iso(offset_seconds):
    moment = datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


class FakeGitHub(BaseHTTPRequestHandler):
    """Just enough of the GitHub API; server.state records what happened."""

    def log_message(self, *args):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self):
        state = self.server.state
        if state.get("reject_jwt"):
            self._send(401, {"message": "A JSON web token could not be decoded"})
            return False
        auth = self.headers.get("Authorization", "")
        if not (auth.startswith("Bearer ") and auth.count(".") == 2):
            self._send(401, {"message": "Bad credentials"})
            return False
        return True

    def do_GET(self):
        state = self.server.state
        state["requests"].append(("GET", self.path))
        if not self._authorized():
            return
        if self.path == "/app":
            return self._send(200, {"slug": "test-app"})
        if self.path == "/repos/acme/widgets/installation":
            return self._send(200, {"id": 42})
        if self.path == "/orgs/solo/installation":
            return self._send(404, {"message": "Not Found"})
        if self.path == "/users/solo/installation":
            return self._send(200, {"id": 43})
        if self.path == "/app/installations/42":
            return self._send(200, {"account": {"login": "acme"}, "suspended_at": None})
        self._send(404, {"message": "Not Found"})

    def do_POST(self):
        state = self.server.state
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        state["requests"].append(("POST", self.path))
        if not self._authorized():
            return
        match = re.fullmatch(r"/app/installations/(\d+)/access_tokens", self.path)
        if not match or match.group(1) == "999":
            return self._send(404, {"message": "Not Found"})
        if state.get("fail_5xx", 0) > 0:
            state["fail_5xx"] -= 1
            return self._send(502, {"message": "Bad Gateway"})
        time.sleep(state.get("delay", 0))
        state["mints"] += 1
        state["bodies"].append(body)
        self._send(
            201,
            {
                "token": f"ghs_token{state['mints']}",
                "expires_at": iso(state.get("lifetime", 3600)),
                "permissions": {"contents": "read"},
            },
        )


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(dir=TMP_ROOT))
        self.runtime = self.dir / "run"
        self.runtime.mkdir(mode=0o700)
        env = {
            "PATH": os.environ["PATH"],
            "HOME": str(self.dir / "home"),
            "XDG_RUNTIME_DIR": str(self.runtime),
            "XDG_CONFIG_HOME": str(self.dir / "config"),
        }
        patcher = mock.patch.dict(os.environ, env, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), FakeGitHub)
        self.server.state = {"mints": 0, "requests": [], "bodies": []}
        self.state = self.server.state
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def settings(self, **overrides):
        values = dict(app_id="123", api_url=self.url, private_key_path=KEY_FILE, installation_id=42)
        values.update(overrides)
        return g.Settings(**values)

    def run_main(self, argv, stdin=""):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("sys.stdin", io.StringIO(stdin)), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = g.main(argv)
        return code, out.getvalue(), err.getvalue()

    def flags(self, *extra):
        return ["--app-id", "123", "--installation-id", "42", "--private-key-path", str(KEY_FILE), "--api-url", self.url, *extra]


class JwtTests(Base):
    def test_signature_verifies_and_claims(self):
        key = g.load_private_key(self.settings())
        jwt = g.make_jwt("123", key, now=1_000_000)
        header, payload, signature = jwt.split(".")
        pad = lambda s: s + "=" * (-len(s) % 4)  # noqa: E731
        import base64

        claims = json.loads(base64.urlsafe_b64decode(pad(payload)))
        self.assertEqual(claims, {"iat": 1_000_000 - 60, "exp": 1_000_000 + 540, "iss": 123})
        self.assertEqual(json.loads(base64.urlsafe_b64decode(pad(header))), {"alg": "RS256", "typ": "JWT"})

        pub, sig, data = self.dir / "pub.pem", self.dir / "sig", self.dir / "data"
        subprocess.run([OPENSSL, "rsa", "-in", str(KEY_FILE), "-pubout", "-out", str(pub)], check=True, capture_output=True)
        sig.write_bytes(base64.urlsafe_b64decode(pad(signature)))
        data.write_bytes(f"{header}.{payload}".encode())
        verify = subprocess.run([OPENSSL, "dgst", "-sha256", "-verify", str(pub), "-signature", str(sig), str(data)], capture_output=True)
        self.assertEqual(verify.returncode, 0, verify.stderr)

    def test_client_id_stays_a_string(self):
        jwt = g.make_jwt("Iv1.abc", g.load_private_key(self.settings()), now=5000)
        import base64

        payload = jwt.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        self.assertEqual(claims["iss"], "Iv1.abc")

    def test_world_readable_key_is_refused(self):
        loose = self.dir / "loose.pem"
        shutil.copy(KEY_FILE, loose)
        loose.chmod(0o644)
        with self.assertRaisesRegex(g.ConfigError, "chmod 600"):
            g.load_private_key(self.settings(private_key_path=loose))

    def test_missing_and_non_pem_keys(self):
        with self.assertRaisesRegex(g.ConfigError, "not found"):
            g.load_private_key(self.settings(private_key_path=self.dir / "nope.pem"))
        with self.assertRaisesRegex(g.ConfigError, "PEM"):
            g.load_private_key(self.settings(private_key_path=None, private_key="garbage"))

    def test_key_from_env_text_with_escaped_newlines(self):
        escaped = KEY_FILE.read_text().strip().replace("\n", "\\n")
        key = g.load_private_key(self.settings(private_key_path=None, private_key=escaped))
        self.assertEqual(key.decode(), KEY_FILE.read_text().strip())
        g.make_jwt("1", key)  # signs without complaint


class ConfigTests(Base):
    def write_config(self, text):
        path = self.dir / "config.toml"
        path.write_text(text)
        return path

    def build(self, argv, env=None):
        args = g.build_parser().parse_args(argv)
        return g.build_settings(args, {**os.environ, **(env or {})})

    def test_precedence_flags_env_profile_file(self):
        cfg = self.write_config(
            'app_id = "1"\nprivate_key_path = "key.pem"\ninstallation_id = 10\n'
            'default_profile = "p"\n[profiles.p]\napp_id = "2"\n'
        )
        s = self.build(["--config", str(cfg)])
        self.assertEqual((s.app_id, s.installation_id, s.profile), ("2", 10, "p"))
        self.assertEqual(s.private_key_path, cfg.parent / "key.pem")  # relative to the file
        s = self.build(["--config", str(cfg)], {"GH_APP_ID": "3"})
        self.assertEqual(s.app_id, "3")
        s = self.build(["--config", str(cfg), "--app-id", "4"], {"GH_APP_ID": "3"})
        self.assertEqual(s.app_id, "4")

    def test_installation_selector_groups_replace_each_other(self):
        cfg = self.write_config('app_id = "1"\nprivate_key_path = "k"\ninstallation_id = 10\n')
        s = self.build(["--config", str(cfg), "--owner", "acme", "--repo", "widgets"])
        self.assertIsNone(s.installation_id)
        self.assertEqual((s.owner, s.repo), ("acme", "widgets"))
        cfg = self.write_config('app_id = "1"\nprivate_key_path = "k"\nowner = "acme"\n')
        s = self.build(["--config", str(cfg), "--installation-id", "7"])
        self.assertEqual((s.installation_id, s.owner), (7, None))

    def test_key_sources_replace_each_other(self):
        cfg = self.write_config('app_id = "1"\ninstallation_id = 1\nprivate_key_path = "k"\n')
        s = self.build(["--config", str(cfg)], {"GH_APP_PRIVATE_KEY": "-----BEGIN PRIVATE KEY-----\nx"})
        self.assertIsNone(s.private_key_path)
        self.assertTrue(s.private_key)

    def test_unknown_key_and_profile_are_errors(self):
        cfg = self.write_config('app_id = "1"\nappid = "typo"\n')
        with self.assertRaisesRegex(g.ConfigError, "unknown key"):
            self.build(["--config", str(cfg)])
        cfg = self.write_config('app_id = "1"\n')
        with self.assertRaisesRegex(g.ConfigError, "not defined"):
            self.build(["--config", str(cfg), "--profile", "nope"])

    def test_missing_explicit_config_is_an_error_but_default_is_not(self):
        with self.assertRaisesRegex(g.ConfigError, "not found"):
            self.build(["--config", str(self.dir / "absent.toml")])
        with self.assertRaisesRegex(g.ConfigError, "app_id is not set"):
            self.build([])

    def test_validation(self):
        base = ["--app-id", "1", "--private-key-path", "k"]
        with self.assertRaisesRegex(g.ConfigError, "installation_id, or owner"):
            self.build(base)
        with self.assertRaisesRegex(g.ConfigError, "https"):
            self.build([*base, "--installation-id", "1", "--api-url", "http://example.com"])
        with self.assertRaisesRegex(g.ConfigError, "integer"):
            self.build([*base, "--installation-id", "abc"])
        with self.assertRaisesRegex(g.ConfigError, "refresh_margin"):
            self.build([*base, "--installation-id", "1", "--refresh-margin", "99999"])
        with self.assertRaisesRegex(g.ConfigError, "name=level"):
            self.build([*base, "--installation-id", "1", "--permission", "oops"])

    def test_scoping_options(self):
        s = self.build(
            ["--app-id", "1", "--private-key-path", "k", "--installation-id", "1",
             "--repositories", "a, b", "--permission", "contents=read", "--permission", "issues=write"]
        )
        self.assertEqual(s.repositories, ("a", "b"))
        self.assertEqual(s.permissions, {"contents": "read", "issues": "write"})

    def test_host_helpers(self):
        self.assertEqual(g.web_host("https://api.github.com"), "github.com")
        self.assertEqual(g.web_host("https://ghe.corp.example/api/v3"), "ghe.corp.example")
        self.assertEqual(g.web_host("http://127.0.0.1:8080"), "127.0.0.1:8080")
        self.assertEqual(g.token_env("https://api.github.com")[0][0], "GH_TOKEN")
        self.assertEqual(g.token_env("https://api.octo.ghe.com")[0][0], "GH_TOKEN")
        names, extra = g.token_env("https://ghe.corp.example/api/v3")
        self.assertEqual((names[0], extra), ("GH_ENTERPRISE_TOKEN", {"GH_HOST": "ghe.corp.example"}))


class CacheTests(Base):
    def test_read_cache_cases(self):
        path = self.dir / "c.json"
        now = time.time()
        self.assertIsNone(g.read_cache(path, 300, now))  # missing
        path.write_text("{not json")
        self.assertIsNone(g.read_cache(path, 300, now))  # corrupt
        path.write_text(json.dumps({"token": "t", "expires_at": iso(3600)}))
        self.assertEqual(g.read_cache(path, 300, now)["token"], "t")  # fresh
        path.write_text(json.dumps({"token": "t", "expires_at": iso(200)}))
        self.assertIsNone(g.read_cache(path, 300, now))  # inside the margin
        path.write_text(json.dumps({"token": "", "expires_at": iso(3600)}))
        self.assertIsNone(g.read_cache(path, 300, now))

    def test_write_cache_is_private_and_atomic(self):
        path = self.dir / "c.json"
        g.write_cache(path, {"token": "t", "expires_at": iso(60)})
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual([p.name for p in self.dir.glob("*.tmp")], [])

    def test_cache_dir_is_private(self):
        mode = stat.S_IMODE(g.cache_dir().stat().st_mode)
        self.assertEqual(mode, 0o700)

    def test_cache_key_depends_on_scope(self):
        a = g.cache_key(self.settings())
        self.assertEqual(a, g.cache_key(self.settings()))
        self.assertNotEqual(a, g.cache_key(self.settings(repositories=("x",))))
        self.assertNotEqual(a, g.cache_key(self.settings(permissions={"issues": "read"})))
        self.assertNotEqual(a, g.cache_key(self.settings(installation_id=43)))
        self.assertEqual(
            g.cache_key(self.settings(repositories=("a", "b"))),
            g.cache_key(self.settings(repositories=("b", "a"))),
        )


class MintTests(Base):
    def test_second_call_hits_the_cache(self):
        s = self.settings()
        first, second = g.get_token(s), g.get_token(s)
        self.assertEqual(first["token"], second["token"])
        self.assertEqual(self.state["mints"], 1)

    def test_force_remints(self):
        s = self.settings()
        g.get_token(s)
        self.assertEqual(g.get_token(s, force=True)["token"], "ghs_token2")

    def test_near_expiry_remints(self):
        self.state["lifetime"] = 100  # inside the 300s margin immediately
        s = self.settings()
        g.get_token(s)
        g.get_token(s)
        self.assertEqual(self.state["mints"], 2)

    def test_concurrent_callers_mint_once(self):
        self.state["delay"] = 0.3
        s = self.settings()
        tokens, errors = [], []

        def worker():
            try:
                tokens.append(g.get_token(s)["token"])
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(self.state["mints"], 1)
        self.assertEqual(set(tokens), {"ghs_token1"})

    def test_scoping_is_sent(self):
        g.get_token(self.settings(repositories=("a",), permissions={"contents": "read"}))
        self.assertEqual(self.state["bodies"][0], {"repositories": ["a"], "permissions": {"contents": "read"}})

    def test_installation_lookup_by_repo_and_owner(self):
        g.mint(self.settings(installation_id=None, owner="acme", repo="widgets"))
        self.assertIn(("POST", "/app/installations/42/access_tokens"), self.state["requests"])
        # org lookup 404s, falls back to the user endpoint
        g.mint(self.settings(installation_id=None, owner="solo"))
        self.assertIn(("GET", "/orgs/solo/installation"), self.state["requests"])
        self.assertIn(("POST", "/app/installations/43/access_tokens"), self.state["requests"])

    def test_not_installed(self):
        with self.assertRaisesRegex(g.MintError, "not installed"):
            g.mint(self.settings(installation_id=None, owner="nobody", repo="nothing"))

    def test_error_mapping(self):
        with self.assertRaisesRegex(g.MintError, "installation|not found"):
            g.mint(self.settings(installation_id=999))
        self.state["reject_jwt"] = True
        with self.assertRaisesRegex(g.MintError, "private key belongs to this app"):
            g.mint(self.settings())

    def test_retries_on_5xx(self):
        self.state["fail_5xx"] = 1
        with mock.patch("time.sleep"):
            self.assertEqual(g.mint(self.settings())["token"], "ghs_token1")

    def test_unreachable_server(self):
        self.server.shutdown()
        self.server.server_close()
        with mock.patch("time.sleep"), self.assertRaisesRegex(g.MintError, "cannot reach"):
            g.mint(self.settings())


class CommandTests(Base):
    def test_token_prints_only_the_token(self):
        code, out, _ = self.run_main(self.flags())
        self.assertEqual((code, out), (0, "ghs_token1\n"))
        code, out, _ = self.run_main(self.flags("token", "--json"))
        self.assertEqual(json.loads(out)["token"], "ghs_token1")  # cached
        self.assertEqual(self.state["mints"], 1)

    def test_exit_codes(self):
        code, _, err = self.run_main(["--app-id", "1"])
        self.assertEqual(code, 2)
        self.assertIn("private key", err)
        self.state["reject_jwt"] = True
        code, _, err = self.run_main(self.flags())
        self.assertEqual(code, 1)

    def test_git_credential_get(self):
        code, out, _ = self.run_main(
            self.flags("git-credential", "get"),
            stdin=f"protocol=http\nhost=127.0.0.1:{self.server.server_address[1]}\n\n",
        )
        lines = dict(line.split("=", 1) for line in out.splitlines())
        self.assertEqual(code, 0)
        self.assertEqual((lines["username"], lines["password"]), ("x-access-token", "ghs_token1"))
        self.assertGreater(int(lines["password_expiry_utc"]), time.time())

    def test_git_credential_ignores_other_hosts_and_store(self):
        code, out, _ = self.run_main(self.flags("git-credential", "get"), stdin="protocol=https\nhost=gitlab.com\n\n")
        self.assertEqual((code, out, self.state["mints"]), (0, "", 0))
        host = f"127.0.0.1:{self.server.server_address[1]}"
        code, out, _ = self.run_main(self.flags("git-credential", "store"), stdin=f"protocol=http\nhost={host}\npassword=x\n\n")
        self.assertEqual((code, out, self.state["mints"]), (0, "", 0))

    def test_git_credential_erase_forces_a_fresh_token(self):
        host = f"protocol=http\nhost=127.0.0.1:{self.server.server_address[1]}\n\n"
        self.run_main(self.flags("git-credential", "get"), stdin=host)
        self.run_main(self.flags("git-credential", "erase"), stdin=host)
        _, out, _ = self.run_main(self.flags("git-credential", "get"), stdin=host)
        self.assertIn("password=ghs_token2", out)

    def test_exec_sets_token_and_runs_command(self):
        captured = {}

        def fake_execve(path, argv, env):
            captured.update(path=path, argv=argv, env=env)
            raise SystemExit(0)

        with mock.patch("os.execve", fake_execve), self.assertRaises(SystemExit):
            self.run_main(self.flags("exec", "--", "sh", "-c", "true"))
        # a non-github.com host is treated like GHES: enterprise variable plus GH_HOST
        self.assertEqual(captured["env"]["GH_ENTERPRISE_TOKEN"], "ghs_token1")
        self.assertEqual(captured["env"]["GH_HOST"], "127.0.0.1")
        self.assertNotIn("GH_TOKEN", captured["env"])
        self.assertEqual(captured["argv"], ["sh", "-c", "true"])
        self.assertTrue(captured["path"].endswith("/sh"))

    def test_exec_passes_dashed_arguments_through(self):
        captured = {}

        def fake_execve(path, argv, env):
            captured["argv"] = argv
            raise SystemExit(0)

        with mock.patch("os.execve", fake_execve), self.assertRaises(SystemExit):
            self.run_main(self.flags("exec", "--", "sh", "--version"))
        self.assertEqual(captured["argv"], ["sh", "--version"])

    def test_exec_keep_existing_skips_minting(self):
        captured = {}

        def fake_execve(path, argv, env):
            captured["env"] = env
            raise SystemExit(0)

        with mock.patch.dict(os.environ, {"GH_ENTERPRISE_TOKEN": "mine"}), mock.patch("os.execve", fake_execve), self.assertRaises(SystemExit):
            self.run_main(self.flags("exec", "--keep-existing", "--", "sh"))
        self.assertEqual(captured["env"]["GH_ENTERPRISE_TOKEN"], "mine")
        self.assertEqual(self.state["mints"], 0)

    def test_exec_command_not_found(self):
        code, _, err = self.run_main(self.flags("exec", "--", "definitely-not-a-command"))
        self.assertEqual(code, 127)

    def test_exec_without_command(self):
        code, _, err = self.run_main(self.flags("exec"))
        self.assertEqual(code, 2)

    def test_which_excluding_skips_directories(self):
        first, second = self.dir / "a", self.dir / "b"
        for d in (first, second):
            d.mkdir()
            tool = d / "mytool"
            tool.write_text("#!/bin/sh\n")
            tool.chmod(0o755)
        with mock.patch.dict(os.environ, {"PATH": f"{first}:{second}"}):
            self.assertEqual(g.which_excluding("mytool", []), str(first / "mytool"))
            self.assertEqual(g.which_excluding("mytool", [str(first)]), str(second / "mytool"))

    def test_install_shim(self):
        target_dir = self.dir / "bin"
        # installing the shim does not need working credentials
        code, out, _ = self.run_main(["install-shim", "--dir", str(target_dir)])
        shim = target_dir / "gh"
        self.assertEqual(code, 0)
        text = shim.read_text()
        self.assertIn("exec gh-app-token exec --keep-existing --exclude-dir", text)
        self.assertTrue(os.access(shim, os.X_OK))
        self.run_main(["--profile", "main", "install-shim", "--dir", str(target_dir)])
        self.assertIn("gh-app-token --profile main exec", shim.read_text())
        # re-installing over our own shim is fine; over somebody else's file is not
        self.assertEqual(self.run_main(["install-shim", "--dir", str(target_dir)])[0], 0)
        shim.write_text("#!/bin/sh\necho mine\n")
        self.assertEqual(self.run_main(["install-shim", "--dir", str(target_dir)])[0], 2)
        self.assertEqual(self.run_main(["install-shim", "--dir", str(target_dir), "--force"])[0], 0)

    def test_doctor_reports_ok_and_failure(self):
        code, out, _ = self.run_main(self.flags("doctor"))
        self.assertEqual(code, 0, out)
        self.assertIn("app 'test-app'", out)
        self.assertIn("account acme", out)
        self.assertNotIn("ghs_token", out)  # never prints the token
        self.state["reject_jwt"] = True
        code, out, _ = self.run_main(self.flags("doctor"))
        self.assertEqual(code, 1)
        self.assertIn("[FAIL]", out)


if __name__ == "__main__":
    unittest.main()
