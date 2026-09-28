# claude-code-guard

> **ALPHA — diagnostic launch-gate prototype**

claude-code-guard is an independent macOS prototype that checks a narrowly defined local environment before offering to launch the official Claude Desktop application. It is currently **locked by design**: the custom system firewall has not been implemented or deployed, and macOS TCC authorization cannot yet be verified. The current build therefore does not enable the launch button.

This project is independent from Anthropic. This alpha provides environment diagnostics; system-level network enforcement is not implemented.

[繁體中文](README.zh-Hant.md)

## Current checks

- Verifies the staged and installed app against the currently pinned official identity: bundle ID `com.anthropic.claudefordesktop`, Team ID `Q6L2SF6YDW`, version `2.9939.4`, strict code-signature validation, and Gatekeeper assessment.
- Requires the configured HTTP loopback proxy at `127.0.0.1:17897`. Cloudflare Trace and ipwho.is must report the same current public IP and country, within the 185-country Claude.ai snapshot dated 2026-09-29. Excluded Ukrainian subdivisions remain blocked; missing subdivision information is unknown.
- Checks the exit time zone and UTC offset, local system time zone, and ordered app language preferences against the country locale used by [Claude Chrome](https://github.com/miku233333/claude-chrome). Japan expects `Asia/Tokyo` and `ja-JP,ja`. The bundled `EnvironmentPolicy.json` contains the region snapshot and macOS Foundation locale mapping. App preference readback does not prove the official app's runtime values.
- Applies the same conservative ProxyCheck policy as Claude Chrome: seven boolean risk flags plus complete risk/confidence, provider, and matching geography are required. Any positive flag or risk above 25 blocks by default. A user may acknowledge a complete snapshot where only `hosting` is true; other flags, missing data, or conflicting geography cannot be acknowledged. The unchecked-by-default option is held only in app memory and tied to the exact IP, geography, provider, scores, flags, and assessment time. This is a local policy, not an Anthropic approval decision.
- Caches valid reputation responses privately for up to 30 minutes for the same exit and geography. A refreshed or changed snapshot clears earlier consent. Every check still re-observes the current exit through both services.
- Runs IPv4, IPv6, UDP, and loopback-proxy probes inside the configured `sandbox-exec` profile. These probes validate only the guarded CLI probe process; they do not prove that Claude Desktop has been tested or contained.
- Inventories permission declarations from the official app's `Info.plist` and code-signing entitlements. A declaration is not a macOS permission grant. Current TCC grant status remains unknown.
- Uses the Claude Chrome environment card layout, with blocking reasons in the summary and expandable desktop protection and permissions. WebRTC, Canvas, WebGL, and other browser measurements are explicitly unmeasured in the official desktop app; results from Chrome are not reused as desktop evidence.
- Treats every failed or unknown mandatory result as launch-blocking. Check results expire after 60 seconds.

## Current security boundary

The currently disabled launch path is designed to start the verified Claude executable under a local `sandbox-exec` profile. That boundary would cover only a process started through the guarded path. Direct launches of the official app, Finder, Dock, Launch Services, URL schemes, login items, and the official updater are not controlled by this prototype.

A custom Network Extension firewall is planned but has not been implemented, signed, approved, installed, or tested. A supported macOS deployment requires a paid Apple Developer team, suitable Developer ID signing and provisioning, Network Extension and System Extension entitlements, notarization, and user approval of the System Extension and Network Filter. This project does not require or recommend disabling System Integrity Protection.

## System firewall completion path

1. Implement an `NEFilterDataProvider` system extension that identifies verified Claude executables and helpers and permits only the designated local proxy. The proxy must have a fixed upstream and no direct fallback. A content filter permits or drops traffic; the launcher must still configure proxy use.
2. Add authenticated runtime status, loaded-policy readback, executable identity checks, and real blocking probes. Present network enforcement and camera/microphone permission review separately.
3. Produce a Developer ID signed, provisioned, notarized artifact through a team authorized for this project, then install and approve it on a Mac with SIP enabled. A paid team can enable the ordinary content-filter entitlement; a free Personal Team lacks the required capabilities.
4. Validate new and existing connections during proxy loss, provider faults, sleep/wake, restart, updates, and direct launches. Shell children, delegated DNS, and Cowork VM traffic require separate attribution testing before claiming complete coverage.

References: [Apple Content Filter](https://developer.apple.com/documentation/networkextension/nefilterdataprovider), [Developer ID Network Extension](https://developer.apple.com/forums/thread/737894), [Network Extension signing eligibility](https://developer.apple.com/forums/thread/814047).

## Build

Requirements:

- macOS 13 or later on Apple silicon
- Command Line Tools containing `/usr/bin/swiftc`
- AppKit and WebKit
- `/usr/bin/python3`

Build the local app:

```sh
./scripts/build.sh
```

The script compiles an arm64 AppKit/WKWebView app and places the ad-hoc-signed result at `dist/claude-code-guard.app`. The ad-hoc signature is only for this local launch-gate app; it cannot provide the restricted entitlements required by a Network Extension firewall.

Run the tests:

```sh
python3 -B -m unittest discover -s tests -v
./scripts/test-ui.sh
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

The guard does not collect or transmit Claude accounts, API keys, authentication tokens, or chat contents. The local reputation cache contains the exit IP and provider response with file mode `0600`. This source repository contains neither that cache nor the official Claude application or its download cache.

## Limitations

- There is no implemented OS-level rule that forces every Claude Desktop launch or helper process through `127.0.0.1:17897`.
- The sandbox probes are diagnostic evidence for their own guarded probe process, not proof of Desktop-wide enforcement.
- TCC permission grants are not currently read back, so they remain unknown and block launch.
- The app identity and version are pinned and must be reviewed when the official app changes.
- External geolocation and reputation services can be unavailable, inconsistent, or wrong; unknown results block the gate.
- A Japanese exit IP does not establish residence, account eligibility, contractual compliance, or permission to use any service. Normal operation still depends on the official application's requirements and the user's own eligibility.

## License

[MIT](LICENSE)
