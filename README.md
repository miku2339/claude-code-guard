# Claude Desktop Guard

> **ALPHA — diagnostic launch-gate prototype**

Claude Desktop Guard is an independent macOS prototype that checks a narrowly defined local environment before offering to launch the official Claude Desktop application. It is currently **locked by design**: the custom system firewall has not been implemented or deployed, and macOS TCC authorization cannot yet be verified. The current build therefore does not enable the launch button.

This project is not a completed kill switch, firewall, VPN, residency verifier, account eligibility checker, or account enforcement avoidance tool. It is not affiliated with or endorsed by Anthropic.

[繁體中文](README.zh-Hant.md)

## Current checks

- Verifies the staged and installed app against the currently pinned official identity: bundle ID `com.anthropic.claudefordesktop`, Team ID `Q6L2SF6YDW`, version `2.9939.4`, strict code-signature validation, and Gatekeeper assessment.
- Requires the configured HTTP loopback proxy at `127.0.0.1:17897` and checks that its public exit is in Japan, reports the `Asia/Tokyo` time zone, and matches the selected English app preferences.
- Cross-checks the public exit with Cloudflare Trace and ipwho.is.
- Applies a project-defined conservative ProxyCheck policy: any `hosting`, `proxy`, `vpn`, `tor`, `compromised`, `scraper`, or `anonymous` flag, or a risk score above 25, blocks the gate. This is a local policy and is not an official Anthropic allowlist or approval decision.
- Runs IPv4, IPv6, UDP, and loopback-proxy probes inside the configured `sandbox-exec` profile. These probes validate only the guarded CLI probe process; they do not prove that Claude Desktop has been tested or contained.
- Inventories permission declarations from the official app's `Info.plist` and code-signing entitlements. A declaration is not a macOS permission grant. Current TCC grant status remains unknown.
- Treats every failed or unknown mandatory result as launch-blocking. Check results expire after 60 seconds.

## Current security boundary

The launcher directly starts the verified Claude executable under a local `sandbox-exec` profile. This covers only a process started through this guarded path. Direct launches of the official app, Finder, Dock, Launch Services, URL schemes, login items, and the official updater are not controlled by this prototype.

A custom Network Extension firewall is planned but has not been implemented, signed, approved, installed, or tested. A supported macOS deployment requires a paid Apple Developer team, suitable Developer ID signing and provisioning, Network Extension and System Extension entitlements, notarization, and user approval of the System Extension and Network Filter. This project does not require or recommend disabling System Integrity Protection.

## Build

Requirements:

- macOS 13 or later on Apple silicon
- Command Line Tools containing `/usr/bin/swiftc`
- AppKit
- `/usr/bin/python3`

Build the local app:

```sh
./scripts/build.sh
```

The script compiles an arm64 AppKit app and places the ad-hoc-signed result at `dist/Claude 啟動檢查.app`. The ad-hoc signature is only for this local launch-gate app; it cannot provide the restricted entitlements required by a Network Extension firewall.

Run the tests:

```sh
python3 -B -m unittest discover -s tests -v
```

## Local configuration

The current prototype expects:

- Official staging app: `$HOME/Library/Application Support/Claude Desktop Guard/Staging/Claude.app`
- Official installed app: `/Applications/Claude.app`
- Sandbox profile: `$HOME/.local/share/claude-network-guard/claude-proxy-only.sb`
- HTTP proxy: `127.0.0.1:17897`

These home-relative paths describe local configuration. They do not contain private user data in this repository.

## Privacy

Network checks disclose the proxy's observed public exit IP to three external providers: Cloudflare, ipwho.is, and ProxyCheck. Those services may process requests under their own policies.

The guard does not collect or transmit Claude accounts, API keys, authentication tokens, or chat contents. This source repository contains neither the official Claude application nor its download cache.

## Limitations

- There is no implemented OS-level rule that forces every Claude Desktop launch or helper process through `127.0.0.1:17897`.
- The sandbox probes are diagnostic evidence for their own guarded probe process, not proof of Desktop-wide enforcement.
- TCC permission grants are not currently read back, so they remain unknown and block launch.
- The app identity and version are pinned and must be reviewed when the official app changes.
- External geolocation and reputation services can be unavailable, inconsistent, or wrong; unknown results block the gate.
- A Japanese exit IP does not establish residence, account eligibility, contractual compliance, or permission to use any service. Normal operation still depends on the official application's requirements and the user's own eligibility.

## License

[MIT](LICENSE)
