#!/usr/bin/env python3
"""Mint and cache GitHub App installation tokens for gh and git.

Standard library only. The app JWT is signed with the system ``openssl``.
Tokens are cached (until shortly before they expire) under
``$XDG_RUNTIME_DIR``, so nothing needs to run in the background and a
broken setup fails loudly at the point of use.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import dataclasses
import fcntl
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

__version__ = "0.1.0"

DEFAULT_API_URL = "https://api.github.com"
DEFAULT_REFRESH_MARGIN = 300
MAX_REFRESH_MARGIN = 3000  # installation tokens live for 3600s
HTTP_TIMEOUT = 10
HTTP_ATTEMPTS = 3
LOCK_TIMEOUT = 30.0
USER_AGENT = f"gh-app-token/{__version__}"
SHIM_MARKER = "managed by gh-app-token"

CONFIG_KEYS = frozenset(
    {
        "app_id",
        "installation_id",
        "owner",
        "repo",
        "private_key_path",
        "api_url",
        "repositories",
        "permissions",
        "refresh_margin",
    }
)
ENV_VARS = {
    "GH_APP_ID": "app_id",
    "GH_APP_INSTALLATION_ID": "installation_id",
    "GH_APP_OWNER": "owner",
    "GH_APP_REPO": "repo",
    "GH_APP_PRIVATE_KEY_PATH": "private_key_path",
    "GH_APP_PRIVATE_KEY": "private_key",
    "GH_APP_API_URL": "api_url",
    "GH_APP_REPOSITORIES": "repositories",
    "GH_APP_PERMISSIONS": "permissions",
    "GH_APP_REFRESH_MARGIN": "refresh_margin",
}


class ConfigError(Exception):
    """Bad or missing configuration (exit status 2)."""


class MintError(Exception):
    """Could not obtain a token from GitHub (exit status 1)."""

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


def eprint(*parts: object) -> None:
    print(*parts, file=sys.stderr)


# --------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------


@dataclasses.dataclass
class Settings:
    app_id: str
    api_url: str = DEFAULT_API_URL
    private_key_path: Path | None = None
    private_key: str | None = None
    installation_id: int | None = None
    owner: str | None = None
    repo: str | None = None
    repositories: tuple[str, ...] = ()
    permissions: dict[str, str] = dataclasses.field(default_factory=dict)
    refresh_margin: int = DEFAULT_REFRESH_MARGIN
    config_path: Path | None = None
    profile: str | None = None


def config_path(explicit: str | None, env: dict) -> Path:
    if explicit:
        return Path(explicit).expanduser()
    base = env.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "gh-app-token" / "config.toml"


def load_file_layer(
    path: Path, profile: str | None, required: bool
) -> tuple[dict, str | None]:
    """Read one config file; top-level keys are defaults, a profile overrides."""
    if not path.is_file():
        if required:
            raise ConfigError(f"config file not found: {path}")
        return {}, None
    try:
        data = tomllib.loads(path.read_text())
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"{path}: {exc}") from None

    profiles = data.pop("profiles", {})
    default_profile = data.pop("default_profile", None)
    if not isinstance(profiles, dict):
        raise ConfigError(f"{path}: 'profiles' must be a table")
    name = profile or default_profile
    layer = dict(data)
    if name:
        if name not in profiles:
            raise ConfigError(f"profile {name!r} is not defined in {path}")
        if not isinstance(profiles[name], dict):
            raise ConfigError(f"{path}: profile {name!r} must be a table")
        layer.update(profiles[name])

    unknown = sorted(set(layer) - CONFIG_KEYS)
    if unknown:
        raise ConfigError(
            f"{path}: unknown key(s): {', '.join(unknown)} "
            f"(valid: {', '.join(sorted(CONFIG_KEYS))})"
        )
    if "private_key_path" in layer:
        key_path = Path(str(layer["private_key_path"])).expanduser()
        if not key_path.is_absolute():
            key_path = path.parent / key_path
        layer["private_key_path"] = str(key_path)
    return layer, name


def env_layer(env: dict) -> dict:
    return {key: env[var] for var, key in ENV_VARS.items() if env.get(var)}


def flag_layer(args: argparse.Namespace) -> dict:
    layer = {}
    for key in (
        "app_id",
        "installation_id",
        "owner",
        "repo",
        "private_key_path",
        "api_url",
        "repositories",
        "refresh_margin",
    ):
        value = getattr(args, key, None)
        if value is not None:
            layer[key] = value
    if getattr(args, "permission", None):
        layer["permissions"] = ",".join(args.permission)
    return layer


def merge_layers(layers: list[dict]) -> dict:
    """Merge lowest-precedence first. Related keys replace each other as a group.

    A higher layer naming a private key replaces any lower key source, and one
    naming an installation_id (or owner/repo) replaces the lower selector, so a
    flag can never be silently combined with a conflicting file setting.
    """
    out: dict = {}
    for layer in layers:
        if "private_key_path" in layer or "private_key" in layer:
            out.pop("private_key_path", None)
            out.pop("private_key", None)
        if "installation_id" in layer:
            out.pop("owner", None)
            out.pop("repo", None)
        if "owner" in layer or "repo" in layer:
            out.pop("installation_id", None)
        out.update(layer)
    return out


def _as_int(value: object, name: str) -> int:
    try:
        return int(str(value))
    except ValueError:
        raise ConfigError(f"{name} must be an integer, got {value!r}") from None


def _as_list(value: object, name: str) -> list[str]:
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, (list, tuple)) and all(isinstance(i, str) for i in value):
        return list(value)
    raise ConfigError(f"{name} must be a list of strings")


def _as_permissions(value: object, name: str) -> dict[str, str]:
    if isinstance(value, str):
        out = {}
        for item in _as_list(value, name):
            key, sep, level = item.partition("=")
            if not (sep and key.strip() and level.strip()):
                raise ConfigError(f"{name}: expected name=level, got {item!r}")
            out[key.strip()] = level.strip()
        return out
    if isinstance(value, dict) and all(
        isinstance(k, str) and isinstance(v, str) for k, v in value.items()
    ):
        return dict(value)
    raise ConfigError(f"{name} must be a table of name = \"level\"")


def build_settings(args: argparse.Namespace, env: dict | None = None) -> Settings:
    """Resolve settings. Precedence: flags > environment > profile > file defaults."""
    env = os.environ if env is None else env
    explicit = getattr(args, "config", None) or env.get("GH_APP_CONFIG")
    path = config_path(explicit, env)
    profile = getattr(args, "profile", None) or env.get("GH_APP_PROFILE")
    file_layer, used_profile = load_file_layer(path, profile, bool(explicit))
    layer = merge_layers([file_layer, env_layer(env), flag_layer(args)])

    app_id = layer.get("app_id")
    if not app_id:
        raise ConfigError("app_id is not set (config file, GH_APP_ID or --app-id)")

    key_path = layer.get("private_key_path")
    key_text = layer.get("private_key")
    if not (key_path or key_text):
        raise ConfigError(
            "no private key (private_key_path in config, GH_APP_PRIVATE_KEY_PATH, "
            "GH_APP_PRIVATE_KEY or --private-key-path)"
        )

    installation_id = layer.get("installation_id")
    owner, repo = layer.get("owner"), layer.get("repo")
    if installation_id is not None:
        installation_id = _as_int(installation_id, "installation_id")
        owner = repo = None
    elif not owner:
        raise ConfigError(
            "set installation_id, or owner (and optionally repo) to look it up"
        )
    elif repo and "/" in repo:
        raise ConfigError("repo must be a bare name, not owner/repo")

    api_url = str(layer.get("api_url") or DEFAULT_API_URL).rstrip("/")
    parsed = urllib.parse.urlparse(api_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ConfigError(f"api_url is not a valid URL: {api_url!r}")
    if parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise ConfigError("api_url must use https")

    margin = _as_int(layer.get("refresh_margin", DEFAULT_REFRESH_MARGIN), "refresh_margin")
    if not 0 <= margin <= MAX_REFRESH_MARGIN:
        raise ConfigError(f"refresh_margin must be between 0 and {MAX_REFRESH_MARGIN}")

    return Settings(
        app_id=str(app_id),
        api_url=api_url,
        private_key_path=Path(str(key_path)).expanduser() if key_path else None,
        private_key=str(key_text) if key_text else None,
        installation_id=installation_id,
        owner=owner,
        repo=repo,
        repositories=tuple(_as_list(layer.get("repositories", []), "repositories")),
        permissions=_as_permissions(layer.get("permissions", {}), "permissions"),
        refresh_margin=margin,
        config_path=path if path.is_file() else None,
        profile=used_profile,
    )


def web_host(api_url: str) -> str:
    """Host (and non-default port) that git uses for this API endpoint."""
    parsed = urllib.parse.urlparse(api_url)
    host = parsed.hostname or ""
    if host.startswith("api."):
        host = host[len("api.") :]
    return f"{host}:{parsed.port}" if parsed.port else host


def token_env(api_url: str) -> tuple[tuple[str, ...], dict[str, str]]:
    """Variables gh reads for this host, and extra variables to set with it."""
    host = web_host(api_url).split(":")[0]
    if host == "github.com" or host.endswith(".ghe.com"):
        return ("GH_TOKEN", "GITHUB_TOKEN"), {}
    return ("GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN"), {"GH_HOST": host}


# --------------------------------------------------------------------------
# JWT
# --------------------------------------------------------------------------


def load_private_key(settings: Settings) -> bytes:
    if settings.private_key:
        pem = settings.private_key
        if "\n" not in pem.strip() and "\\n" in pem:  # newline-escaped (CI secrets)
            pem = pem.replace("\\n", "\n")
    else:
        path = settings.private_key_path
        assert path is not None
        try:
            mode = path.stat().st_mode
            if mode & 0o077:
                raise ConfigError(
                    f"{path} is accessible by other users (mode {mode & 0o777:03o}); "
                    f"run: chmod 600 {shlex.quote(str(path))}"
                )
            pem = path.read_text()
        except FileNotFoundError:
            raise ConfigError(f"private key not found: {path}") from None
        except (OSError, UnicodeDecodeError) as exc:
            raise ConfigError(f"cannot read private key {path}: {exc}") from None
    if "PRIVATE KEY-----" not in pem:
        raise ConfigError("private key is not PEM encoded")
    return pem.encode()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def rs256_sign(key_pem: bytes, data: bytes) -> bytes:
    openssl = shutil.which("openssl")
    if not openssl:
        raise ConfigError("openssl was not found on PATH")
    with tempfile.NamedTemporaryFile() as handle:  # the data is not secret; the key is
        handle.write(data)
        handle.flush()
        try:
            result = subprocess.run(
                [openssl, "dgst", "-sha256", "-sign", "/dev/stdin", handle.name],
                input=key_pem,
                capture_output=True,
                timeout=15,
            )
        except subprocess.TimeoutExpired:
            raise ConfigError("openssl timed out while signing") from None
    if result.returncode != 0:
        detail = result.stderr.decode(errors="replace").strip()
        raise ConfigError(f"openssl could not sign with this key (is it an RSA key?): {detail}")
    return result.stdout


def make_jwt(app_id: str, key_pem: bytes, now: float | None = None) -> str:
    issued = int(time.time() if now is None else now)
    compact = {"separators": (",", ":")}
    header = b64url(json.dumps({"alg": "RS256", "typ": "JWT"}, **compact).encode())
    claims = {
        "iat": issued - 60,  # tolerate clock drift
        "exp": issued + 540,  # GitHub allows at most 10 minutes
        "iss": int(app_id) if app_id.isdigit() else app_id,
    }
    payload = b64url(json.dumps(claims, **compact).encode())
    signature = rs256_sign(key_pem, f"{header}.{payload}".encode())
    return f"{header}.{payload}.{b64url(signature)}"


# --------------------------------------------------------------------------
# GitHub API
# --------------------------------------------------------------------------


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: urllib would forward the Authorization header."""

    def redirect_request(self, *args, **kwargs):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def _explain(status: int, message: str, path: str) -> str:
    if status == 401:
        return (
            f"GitHub rejected the app JWT (401: {message}). Check app_id, that the "
            "private key belongs to this app and was not deleted, and that the "
            "system clock is accurate."
        )
    if status == 403:
        return f"forbidden (403: {message}); the app may be suspended or rate limited"
    if status == 404:
        return f"not found (404) for {path}: {message}"
    return f"GitHub API error {status} for {path}: {message}"


def api_request(
    settings: Settings, method: str, path: str, *, bearer: str, body: dict | None = None
) -> dict:
    url = settings.api_url + path
    headers = {
        "Authorization": f"Bearer {bearer}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": USER_AGENT,
    }
    data = None
    if method == "POST":
        data = json.dumps(body or {}).encode()
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, method=method, headers=headers)

    delay = 0.5
    for attempt in range(1, HTTP_ATTEMPTS + 1):
        last = attempt == HTTP_ATTEMPTS
        try:
            with _opener.open(request, timeout=HTTP_TIMEOUT) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            if exc.code >= 500 and not last:
                time.sleep(delay)
                delay *= 2
                continue
            try:
                message = json.load(exc).get("message", exc.reason)
            except (ValueError, AttributeError, OSError):
                message = exc.reason
            raise MintError(_explain(exc.code, str(message), path), exc.code) from None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            if not last:
                time.sleep(delay)
                delay *= 2
                continue
            raise MintError(f"cannot reach {url}: {getattr(exc, 'reason', exc)}") from None
    raise AssertionError("unreachable")


def resolve_installation_id(settings: Settings, jwt: str) -> int:
    if settings.installation_id is not None:
        return settings.installation_id
    owner = urllib.parse.quote(settings.owner or "", safe="")
    if settings.repo:
        repo = urllib.parse.quote(settings.repo, safe="")
        candidates = [f"/repos/{owner}/{repo}/installation"]
    else:
        candidates = [f"/orgs/{owner}/installation", f"/users/{owner}/installation"]
    for index, path in enumerate(candidates):
        try:
            return int(api_request(settings, "GET", path, bearer=jwt)["id"])
        except MintError as exc:
            if exc.status == 404 and index < len(candidates) - 1:
                continue
            if exc.status == 404:
                raise MintError(
                    f"the app is not installed on {settings.owner}"
                    + (f"/{settings.repo}" if settings.repo else "")
                    + " (404)",
                    404,
                ) from None
            raise
    raise AssertionError("unreachable")


def mint(settings: Settings) -> dict:
    jwt = make_jwt(settings.app_id, load_private_key(settings))
    installation_id = resolve_installation_id(settings, jwt)
    body: dict = {}
    if settings.repositories:
        body["repositories"] = list(settings.repositories)
    if settings.permissions:
        body["permissions"] = settings.permissions
    response = api_request(
        settings,
        "POST",
        f"/app/installations/{installation_id}/access_tokens",
        bearer=jwt,
        body=body,
    )
    if not response.get("token") or not response.get("expires_at"):
        raise MintError("unexpected response from GitHub (no token / expires_at)")
    return {
        key: response[key]
        for key in ("token", "expires_at", "permissions", "repository_selection")
        if key in response
    }


# --------------------------------------------------------------------------
# cache
# --------------------------------------------------------------------------


def cache_dir() -> Path:
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if runtime and os.access(runtime, os.W_OK):
        root = Path(runtime)
    else:
        root = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    directory = root / "gh-app-token"
    try:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = directory.stat()
        if info.st_uid != os.getuid():
            raise ConfigError(f"cache directory {directory} is owned by another user")
        if info.st_mode & 0o077:
            directory.chmod(0o700)
    except OSError as exc:
        raise ConfigError(f"cannot use cache directory {directory}: {exc}") from None
    return directory


def cache_key(settings: Settings) -> str:
    identity = {
        "api": settings.api_url,
        "app": settings.app_id,
        "installation": settings.installation_id,
        "owner": settings.owner,
        "repo": settings.repo,
        "repositories": sorted(settings.repositories),
        "permissions": settings.permissions,
    }
    digest = hashlib.sha256(json.dumps(identity, sort_keys=True).encode())
    return digest.hexdigest()[:20]


def parse_timestamp(value: str) -> float:
    return datetime.fromisoformat(value).timestamp()


def read_cache(path: Path, margin: int, now: float) -> dict | None:
    """Return the cached token if it is valid for longer than ``margin`` seconds."""
    try:
        data = json.loads(path.read_text())
        if not isinstance(data["token"], str) or not data["token"]:
            return None
        expires = parse_timestamp(data["expires_at"])
    except (OSError, ValueError, KeyError, TypeError):
        return None  # missing or corrupt: just mint again
    return data if expires - now > margin else None


def write_cache(path: Path, data: dict) -> None:
    temp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as handle:
            json.dump(data, handle)
        os.replace(temp, path)  # readers see the old or the new file, never half
    finally:
        with contextlib.suppress(FileNotFoundError):
            temp.unlink()


@contextlib.contextmanager
def locked(path: Path, timeout: float = LOCK_TIMEOUT):
    """Exclusive advisory lock; the kernel drops it if the holder dies."""
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() > deadline:
                    raise MintError(
                        "timed out waiting for another gh-app-token process"
                    ) from None
                time.sleep(0.05)
        yield
    finally:
        os.close(fd)


def get_token(settings: Settings, force: bool = False, now: float | None = None) -> dict:
    clock = time.time if now is None else (lambda: now)
    directory = cache_dir()
    key = cache_key(settings)
    cache_file = directory / f"{key}.json"
    if not force:
        hit = read_cache(cache_file, settings.refresh_margin, clock())
        if hit:
            return hit
    with locked(directory / f"{key}.lock"):
        if not force:  # another process may have refreshed while we waited
            hit = read_cache(cache_file, settings.refresh_margin, clock())
            if hit:
                return hit
        fresh = mint(settings)
        write_cache(cache_file, fresh)
        return fresh


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------


def cmd_token(args: argparse.Namespace) -> int:
    result = get_token(build_settings(args), force=getattr(args, "force", False))
    if getattr(args, "json", False):
        print(json.dumps({"token": result["token"], "expires_at": result["expires_at"]}))
    else:
        print(result["token"])
    return 0


def which_excluding(command: str, exclude: list[str]) -> str | None:
    if os.sep in command:
        return command
    skip = {os.path.realpath(os.path.expanduser(d)) for d in exclude}
    kept = [
        d
        for d in os.environ.get("PATH", "").split(os.pathsep)
        if d and os.path.realpath(d) not in skip
    ]
    return shutil.which(command, path=os.pathsep.join(kept))


def cmd_exec(args: argparse.Namespace) -> int:
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise ConfigError("exec: no command given (usage: gh-app-token exec -- COMMAND ...)")
    settings = build_settings(args)
    names, extra = token_env(settings.api_url)
    env = dict(os.environ)
    if not (args.keep_existing and any(env.get(name) for name in names)):
        env[names[0]] = get_token(settings)["token"]
        env.update(extra)
    executable = which_excluding(command[0], args.exclude_dir or [])
    if not executable:
        eprint(f"gh-app-token: {command[0]}: command not found")
        return 127
    try:
        os.execve(executable, command, env)
    except OSError as exc:
        eprint(f"gh-app-token: cannot run {command[0]}: {exc}")
        return 126
    return 0  # unreachable


def read_credential_attrs(stream) -> dict[str, str]:
    attrs = {}
    for line in stream:
        line = line.rstrip("\n")
        if not line:
            break
        key, _, value = line.partition("=")
        attrs[key] = value
    return attrs


def cmd_git_credential(args: argparse.Namespace) -> int:
    attrs = read_credential_attrs(sys.stdin)
    settings = build_settings(args)
    scheme = urllib.parse.urlparse(settings.api_url).scheme
    if attrs.get("protocol") != scheme or attrs.get("host") != web_host(settings.api_url):
        return 0  # not ours: stay silent so other helpers can answer
    if args.action == "get":
        result = get_token(settings)
        print("username=x-access-token")
        print(f"password={result['token']}")
        print(f"password_expiry_utc={int(parse_timestamp(result['expires_at']))}")
    elif args.action == "erase":
        # git rejected the credential (revoked early?): drop it so the next get re-mints
        cache_file = cache_dir() / f"{cache_key(settings)}.json"
        with contextlib.suppress(FileNotFoundError):
            cache_file.unlink()
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    healthy = True

    def report(good: bool, label: str, detail: str = "") -> bool:
        nonlocal healthy
        healthy = healthy and good
        print(f"[{'ok' if good else 'FAIL'}] {label}" + (f": {detail}" if detail else ""))
        return good

    print(f"gh-app-token {__version__}")
    try:
        settings = build_settings(args)
    except ConfigError as exc:
        report(False, "config", str(exc))
        return 1
    source = str(settings.config_path) if settings.config_path else "no config file (env/flags only)"
    report(True, "config", source + (f" [profile {settings.profile}]" if settings.profile else ""))
    report(True, "app_id", settings.app_id)
    report(True, "api_url", settings.api_url)

    try:
        key = load_private_key(settings)
        origin = "from environment" if settings.private_key else f"{settings.private_key_path} (mode 600 or stricter)"
        report(True, "private key", origin)
        jwt = make_jwt(settings.app_id, key)
        report(True, "JWT signed", shutil.which("openssl") or "")
    except ConfigError as exc:
        report(False, "private key / signing", str(exc))
        return 1

    try:
        app = api_request(settings, "GET", "/app", bearer=jwt)
        report(True, "GitHub accepted the JWT", f"app {app.get('slug', '?')!r}")
        installation_id = resolve_installation_id(settings, jwt)
        info = api_request(settings, "GET", f"/app/installations/{installation_id}", bearer=jwt)
        account = (info.get("account") or {}).get("login", "?")
        suspended = bool(info.get("suspended_at"))
        report(not suspended, f"installation {installation_id}", f"account {account}" + (" (SUSPENDED)" if suspended else ""))
        fresh = get_token(settings, force=True)
        minutes = int((parse_timestamp(fresh["expires_at"]) - time.time()) // 60)
        granted = ", ".join(f"{k}:{v}" for k, v in sorted((fresh.get("permissions") or {}).items()))
        report(True, "token minted", f"valid ~{minutes} min; {granted or 'no permissions listed'}")
    except (MintError, ConfigError) as exc:
        report(False, "GitHub API", str(exc))
    return 0 if healthy else 1


def cmd_install_shim(args: argparse.Namespace) -> int:
    directory = Path(args.dir or "~/.local/bin").expanduser()
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / "gh"
    if (target.exists() or target.is_symlink()) and not args.force:
        try:
            managed = SHIM_MARKER in target.read_text(errors="replace")
        except OSError:
            managed = False
        if not managed:
            raise ConfigError(f"{target} exists and was not created by gh-app-token (use --force)")
    flags = []
    if getattr(args, "config", None):
        flags += ["--config", args.config]
    if getattr(args, "profile", None):
        flags += ["--profile", args.profile]
    command = " ".join(
        shlex.quote(part)
        for part in ["gh-app-token", *flags, "exec", "--keep-existing", "--exclude-dir", str(directory), "--", "gh"]
    )
    target.unlink(missing_ok=True)
    target.write_text(f"#!/bin/sh\n# {SHIM_MARKER}\nexec {command} \"$@\"\n")
    target.chmod(0o755)
    print(f"installed {target}")
    resolved = shutil.which("gh")
    if resolved and Path(resolved).resolve() != target.resolve():
        eprint(f"warning: `gh` currently resolves to {resolved}; put {directory} earlier in PATH")
    return 0


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def _common_flags() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False, argument_default=argparse.SUPPRESS)
    group = parser.add_argument_group("configuration (overrides environment and config file)")
    group.add_argument("--config", metavar="FILE", help="config file (default: $XDG_CONFIG_HOME/gh-app-token/config.toml)")
    group.add_argument("--profile", help="profile in the config file")
    group.add_argument("--app-id", help="GitHub App ID or client ID")
    group.add_argument("--installation-id", help="installation ID")
    group.add_argument("--owner", help="look up the installation for this user/org")
    group.add_argument("--repo", help="with --owner: look up the installation for this repository")
    group.add_argument("--private-key-path", metavar="FILE", help="PEM private key (must be mode 600)")
    group.add_argument("--api-url", help=f"API base URL (default {DEFAULT_API_URL})")
    group.add_argument("--repositories", help="comma-separated repository names to scope the token to")
    group.add_argument("--permission", action="append", metavar="NAME=LEVEL", help="restrict a permission (repeatable)")
    group.add_argument("--refresh-margin", metavar="SECONDS", help=f"re-mint when less than this remains (default {DEFAULT_REFRESH_MARGIN})")
    return parser


def build_parser() -> argparse.ArgumentParser:
    common = _common_flags()
    token_flags = argparse.ArgumentParser(add_help=False, argument_default=argparse.SUPPRESS)
    token_flags.add_argument("--json", action="store_true", help="print token and expiry as JSON")
    token_flags.add_argument("--force", action="store_true", help="ignore the cache and mint a new token")

    parser = argparse.ArgumentParser(
        prog="gh-app-token",
        description="Mint and cache GitHub App installation tokens. With no command, prints a token.",
        parents=[common, token_flags],
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="cmd", metavar="COMMAND")

    sub.add_parser("token", parents=[common, token_flags], help="print a valid token (default)")

    p_exec = sub.add_parser("exec", parents=[common], help="run a command with the token in its environment")
    p_exec.add_argument("--keep-existing", action="store_true", help="do nothing special if a token variable is already set")
    p_exec.add_argument("--exclude-dir", action="append", metavar="DIR", help="ignore this PATH entry when finding the command")
    p_exec.add_argument("command", nargs=argparse.REMAINDER, help="-- COMMAND [ARGS...]")

    p_git = sub.add_parser("git-credential", parents=[common], help="git credential helper (get/erase/store)")
    p_git.add_argument("action", choices=["get", "store", "erase"])

    sub.add_parser("doctor", parents=[common], help="check configuration, key, and GitHub access")

    p_shim = sub.add_parser("install-shim", parents=[common], help="install a `gh` wrapper script")
    p_shim.add_argument("--dir", help="directory for the shim (default ~/.local/bin)")
    p_shim.add_argument("--force", action="store_true", help="overwrite an existing gh that is not a shim")
    return parser


COMMANDS = {
    "token": cmd_token,
    "exec": cmd_exec,
    "git-credential": cmd_git_credential,
    "doctor": cmd_doctor,
    "install-shim": cmd_install_shim,
}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return COMMANDS[args.cmd or "token"](args)
    except ConfigError as exc:
        eprint(f"gh-app-token: {exc}")
        return 2
    except MintError as exc:
        eprint(f"gh-app-token: {exc}")
        return 1
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    sys.exit(main())
