# CodeGuard

An independent macOS launcher that checks the connection environment, lets you choose a project, and opens the installed official Claude Code CLI in Apple Terminal.

[繁體中文](README.zh-Hant.md)

## Use

1. Open CodeGuard and review the checks and blocking reasons.
2. Choose a project folder.
3. Once checks pass, open Claude Code in Terminal. The terminal entry point checks again before executing the CLI.
4. Claude Chrome receives the official sign-in link. Once its checks pass, continue to Claude Code sign-in. Conversations and tool approvals stay in the original CLI.

Hosting exits are blocked by default. A complete reputation snapshot with only the `hosting` flag may be acknowledged by the user. Consent starts unchecked, stays in app memory, and is bound to the observed IP, geography, provider, scores, flags, and assessment time. A changed exit or refreshed snapshot invalidates it.

## Checks

- **Official CLI:** native installation symlink, safe file ownership and permissions, strict code signature, `com.anthropic.claude-code`, and Anthropic Team identity.
- **Protected entry:** ownership, permissions, and SHA-256 templates for the existing local launcher, process wrapper, and sandbox profile.
- **Exit:** matching current public IP/country from Cloudflare and ipwho.is; a dated 185-country Claude.ai supported-region snapshot, including excluded Ukrainian subdivisions.
- **IP reputation:** complete ProxyCheck risk flags, risk/confidence scores, provider, and consistent geography. Any flag or risk above 25 blocks by default.
- **Time zone and language:** `TZ`, `LANG`, and `LC_ALL` launch settings derived from the verified exit. The Mac's system settings are unchanged. These are process settings, not evidence of residency or account eligibility.
- **Network probes:** direct IPv4/IPv6/UDP denial and reachability of the designated proxy under the verified profile. Evidence covers this controlled launch path.
- **WebRTC and browser fingerprinting:** not applicable to the pure CLI. An external authentication browser needs separate protection.

Unknown, incomplete, duplicate, or failed mandatory checks block launch. GUI results expire after 60 seconds. The Terminal entry point reruns checks and revalidates the CLI and protection files immediately before execution.

## Permissions and privacy

CodeGuard requests no Accessibility, Screen Recording, microphone, camera, Automation, or Full Disk Access permissions. It uses a native folder picker and Launch Services to open Terminal without Apple Events.

This does not restrict the CLI to the selected folder: the CLI still runs as the current user and can read/write files and execute commands according to its own approval settings. Keep those approval prompts enabled.

- No custom Claude sign-in, credential/token handling, CLI transcript collection, or input/output interception.
- Cloudflare, ipwho.is, and ProxyCheck see the proxy's public exit IP during checks.
- Reputation responses are cached privately for at most 30 minutes with mode `0600`; the current exit is still re-observed on each check.
- Each handoff creates one private `0700` temporary `.command`. Paths are shell-quoted, and the command deletes itself when run.

## Official usage boundaries

CodeGuard runs the user's installed, unmodified Claude Code. It does not bundle the official binary, build an SDK chat interface, proxy subscription usage, or implement OAuth. All authentication methods remain available through the original CLI, and users sign in through Anthropic's own flow.

Anthropic imposes Commercial Terms, unmodified-binary, individual-authentication, and direct-billing conditions on products running Claude Code. Third parties may not collect or intermediate Claude.ai credentials. This project has no Anthropic endorsement and makes no compliance certification or account-safety guarantee. Use and distribution must satisfy the applicable terms.

Sources: [official product integration and authentication rules](https://code.claude.com/docs/en/legal-and-compliance), [official proxy and process-wrapper configuration](https://code.claude.com/docs/en/network-config).

## Local prerequisites

- Apple silicon Mac, macOS 13+, Command Line Tools with Swift and Python 3.
- Official native CLI: `~/.local/bin/claude` → `~/.local/share/claude/versions/…`.
- Existing `~/bin/claude`, `~/.local/share/claude-network-guard/claude-process-wrapper.zsh`, and `claude-proxy-only.sb`, matching `Resources/CLIProtection.json`.
- Existing HTTP proxy at `127.0.0.1:17897`, with a fixed upstream and no direct fallback.
- Claude Chrome with `--login-url` support, and `BROWSER` pointing to the local `claude-code-browser.py` entry point. A user LaunchAgent runs its broker outside the CLI sandbox; the sandbox permits only that private Unix socket. Missing or stale broker versions block launch.

This version uses the existing local protection configuration; it does not provision other machines automatically. Missing prerequisites are reported as blockers.

## Build and verify

```sh
./scripts/build.sh
./script/build_and_run.sh --verify
python3 -B -m unittest discover -s tests -v
./scripts/test-ui.sh
```

`build.sh` creates an ad-hoc signed `dist/CodeGuard.app`. `build_and_run.sh` updates `/Applications/CodeGuard.app`, keeps one rollback copy, and powers the Codex Run action.

## Protection limits

A system Network Extension firewall is not deployed. Direct binary launches, other terminals/browsers, and processes launched by other services are outside this entry point's verified scope. Proxy and sandbox probes do not establish coverage of every failure mode; network and account services may still refuse access.

A system firewall would additionally require `NEFilterDataProvider`, authenticated policy readback, authorized signing/notarization, and real-machine testing of disconnection, crashes, updates, sleep, and direct launches.

## License

[MIT](LICENSE). The environment page's base styling derives from the MIT-licensed [Claude Chrome](https://github.com/miku233333/claude-chrome) resources. CodeGuard uses its own name and icon.
