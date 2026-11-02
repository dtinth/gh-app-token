# gh-app-token

Use a **GitHub App installation** as the identity for `gh` and `git`, without
running a refresh daemon.

Installation tokens expire after an hour. `gh-app-token` mints one on demand
from your app's private key, caches it until shortly before it expires, and
hands it to `gh` and `git` at the moment they need it. There is nothing in the
background to monitor: if something is misconfigured, the command you ran fails
immediately with a clear message.

- Python 3.11+, standard library only. Needs the `openssl` binary to sign the JWT.
- Linux and macOS (uses `flock`).
- GitHub.com, GitHub Enterprise Server, and GHE.com.

## Install

```sh
pipx install .            # or: pip install --user .
# or just drop the single file on your PATH:
install -m 755 gh_app_token.py ~/.local/bin/gh-app-token
```

## Configure

Create `~/.config/gh-app-token/config.toml` (see `config.example.toml`):

```toml
default_profile = "main"

[profiles.main]
app_id = "123456"
installation_id = 12345678
private_key_path = "my-app.private-key.pem"   # relative to this file
```

Keep the key somewhere only you can read, and make it `chmod 600`. The tool
refuses a key that other users can read.

Instead of `installation_id` you can set `owner` (and optionally `repo`) and the
installation is looked up for you.

**Precedence:** command-line flags, then `GH_APP_*` environment variables, then
the selected profile, then top-level keys in the file. Unknown keys in the file
are an error, so typos don't pass silently.

| Setting            | Flag                  | Environment                                  |
| ------------------ | --------------------- | -------------------------------------------- |
| config file        | `--config`            | `GH_APP_CONFIG`                              |
| profile            | `--profile`           | `GH_APP_PROFILE`                             |
| `app_id`           | `--app-id`            | `GH_APP_ID`                                  |
| `installation_id`  | `--installation-id`   | `GH_APP_INSTALLATION_ID`                     |
| `owner`, `repo`    | `--owner`, `--repo`   | `GH_APP_OWNER`, `GH_APP_REPO`                |
| `private_key_path` | `--private-key-path`  | `GH_APP_PRIVATE_KEY_PATH`                    |
| key contents (CI)  |                       | `GH_APP_PRIVATE_KEY` (PEM; `\n` escapes OK)  |
| `api_url`          | `--api-url`           | `GH_APP_API_URL`                             |
| `repositories`     | `--repositories a,b`  | `GH_APP_REPOSITORIES`                        |
| `permissions`      | `--permission k=v`    | `GH_APP_PERMISSIONS` (`contents=read,...`)   |
| `refresh_margin`   | `--refresh-margin`    | `GH_APP_REFRESH_MARGIN`                      |

Run `gh-app-token doctor` to check the whole chain: config, key permissions,
signing, GitHub accepting the JWT, the installation, and minting a token.

## Use

```sh
gh-app-token                       # print a valid token (minted only if needed)
gh-app-token --json                # token + expires_at
GH_TOKEN=$(gh-app-token) gh pr list
gh-app-token exec -- gh pr list    # run one command with the token set
```

### Make plain `gh` just work

```sh
gh-app-token install-shim          # writes ~/.local/bin/gh
```

The shim runs the real `gh` (found on `PATH`, skipping its own directory) with a
fresh token on every invocation, so long-running scripts never see a stale one.
If `GH_TOKEN` is already set, the shim leaves it alone. Make sure `~/.local/bin`
comes before the real `gh` in `PATH`.

If the token can't be minted, the shim **fails** rather than falling back to
`gh`'s stored login, so you never act as the wrong identity by accident.

### When plain `gh` still isn't authenticated

Run `type -a gh`. The first line must be `~/.local/bin/gh`. If it is anything
else, something is ahead of the shim in `PATH`, and that `gh` has no credentials.

**A version manager that rewrites `PATH` on every prompt is the usual cause.**
`mise activate` prepends each tool's install directory, so a `gh` that mise
manages comes first and the shim comes last. Setting `PATH` in your shell rc
file does not help, because the hook runs again after it. Tell mise to keep the
shim directory in front. A file in mise's global `conf.d` is enough, and it
needs no change to any project:

```toml
# ~/.config/mise/conf.d/gh-app-token.toml
[env]
_.path = ["{{env.HOME}}/.local/bin"]
```

Checked with mise 2026.10.25: after `mise activate bash`, `~/.local/bin` is first,
and the shim still finds the real `gh` because it skips only its own directory.
This puts all of `~/.local/bin` ahead of mise's tools, not only the shim. Other
version managers were not tried.

**The interpreter can be a shim too.** The script starts with
`#!/usr/bin/env python3`. If `python3` resolves through a version manager, that
manager's errors reach you instead of ours. One seen case: an untrusted
`.mise.toml` made every shimmed command, `gh-app-token` included, exit with
`mise ERROR ... are not trusted`. It looks like an authentication failure and is
not one. Trust the config (`mise trust`), or run the script with a fixed
interpreter: `/usr/bin/python3 ~/.local/bin/gh-app-token doctor`.

To tell a `PATH` problem from a credentials problem, run the real `gh` once
without the shim: `gh-app-token exec -- /full/path/to/gh api user`.

### Make `git` work over HTTPS

```sh
git config --global credential.https://github.com.helper ''
git config --global --add credential.https://github.com.helper \
  '!gh-app-token git-credential'
```

Git asks for credentials per operation, so tokens are always current. If git
reports a credential as rejected, the cached token is dropped and the next
request mints a new one. For GHES use `credential.https://ghe.example.com.helper`.

## How it works

1. Sign a 10-minute JWT with the app's private key (`openssl dgst -sha256 -sign`).
2. `POST /app/installations/{id}/access_tokens`.
3. Store the response in `$XDG_RUNTIME_DIR/gh-app-token/` (mode 0600, tmpfs on
   most Linux systems; falls back to `$XDG_CACHE_HOME`), keyed by app,
   installation, and requested scope.
4. Reuse it until fewer than `refresh_margin` (default 300) seconds remain.

Concurrent callers coordinate with `flock`, so a burst of `gh` invocations
mints one token. The kernel releases the lock if a holder dies. The cache file
is replaced atomically, so readers never see a partial write.

The key (and its permissions) is only touched when a token must be minted, so
a configuration problem surfaces at the next refresh, at most about an hour
later. `gh-app-token doctor` and `gh-app-token --force` always mint, so they
catch it immediately.

Requests have a 10 s timeout, retry on 5xx and network errors, and never follow
redirects (so credentials can't be forwarded to another host).

## Exit codes

`0` success, `1` could not get a token (network, GitHub rejected the request),
`2` configuration error, `126`/`127` from `exec` when the command can't be run
or found.

## Security notes

- The private key is the only long-lived secret; tokens are derived from it.
  Rotate by adding a second key in the app settings, switching, then deleting
  the old one.
- The key is read only when a token must be minted, and is never written to a
  temporary file: it is piped to `openssl` over stdin.
- Prefer scoping tokens to what the task needs (`repositories`, `permissions`).
- A process that can read your key can mint tokens. If the caller (an agent, a
  CI job) shouldn't hold the key, run minting as a different user and expose
  only the token.

## Development

```sh
python -m unittest discover -s tests -v
```

The tests run against a fake GitHub API on localhost and generate a throwaway
key with `openssl`. They need no network and no credentials.

## License

MIT
