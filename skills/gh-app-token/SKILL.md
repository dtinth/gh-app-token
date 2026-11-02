---
name: gh-app-token
description: Diagnose and fix `gh` or `git` that is unauthenticated, acts as the wrong identity, or fails with an odd tool-manager error on a machine that uses gh-app-token (GitHub App installation tokens). Use when `gh` says you are not logged in, `gh auth status` shows nothing, a push or API call runs as the wrong user, or every `gh` call prints a mise or asdf error.
---

# gh-app-token

This machine does not use `gh auth login`. `gh` and `git` get a short-lived GitHub App
installation token from `gh-app-token`, which signs a JWT with the App's private key and
caches the token. `gh auth status` has nothing to report here, and that is normal. Never
run `gh auth login` to "fix" it: it would store a second identity.

## Triage, in this order

1. **Which `gh` runs?** `type -a gh`. The first line must be `~/.local/bin/gh`, the shim
   (its second line says `managed by gh-app-token`). If another path is first, go to
   "A tool manager is ahead of the shim".
2. **Does the chain work?** `gh-app-token doctor`. It checks config, key permissions,
   signing, GitHub accepting the JWT, the installation, and minting. Read the first
   failing line. Do not guess.
3. **Is the error even ours?** If every command prints a version-manager error such as
   `mise ERROR ... .mise.toml ... are not trusted`, auth is not the problem. The shim
   and the script both start through that manager. Fix the manager (`mise trust`, which
   is the user's decision, so ask), or run past it:
   `/usr/bin/python3 ~/.local/bin/gh-app-token exec --keep-existing -- <full path to gh> <args>`.
4. **Real credentials problem.** Exit code `2` is configuration, `1` is network or GitHub
   refusing. `doctor` names which.

## A tool manager is ahead of the shim

`mise activate` prepends each managed tool's directory to `PATH` on every prompt, so a
mise-managed `gh` runs before the shim and has no credentials. Editing `PATH` in an rc
file does not stick, because the hook runs after it. Ask the user, then add a global file:

```toml
# ~/.config/mise/conf.d/gh-app-token.toml
[env]
_.path = ["{{env.HOME}}/.local/bin"]
```

Verify with `bash -c 'eval "$(mise activate bash)"; _mise_hook; type -a gh'`. This was
checked with mise 2026.10.25 only. Do not claim it for asdf, nix or another manager
without testing it.

## Rules

- Do not print a token. `gh-app-token --json` prints one; use `exec --` or `gh api` instead.
- Do not set `GH_TOKEN` in a shell rc file. Tokens last an hour and a stale one fails
  confusingly. The shim mints a fresh one per call.
- Do not edit `~/.config/gh-app-token/config.toml` or touch the key file to fix a `PATH`
  or manager problem. Check `type -a gh` first.
- Changing the user's mise config, shell rc files, or trust state is the user's call: say
  what you would change and why, then wait.
