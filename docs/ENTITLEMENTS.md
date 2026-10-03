# Entitlements

SMP is distributed outside the Mac App Store with Developer ID signing, the Hardened Runtime and
notarization. It is intentionally **not sandboxed**: it needs direct access to `~/.ssh`, the
`ssh-agent` socket and `/usr/bin` OpenSSH tools.

## Current entitlements

| Entitlement | Since | Why |
| --- | --- | --- |
| `com.apple.security.automation.apple-events` | Milestone 4 | **Connect** opens a session in Terminal.app or iTerm2 by sending them a `do script` / `write text` Apple Event containing `ssh <alias>`. macOS asks the user for permission per target app on first use, showing `NSAppleEventsUsageDescription`. Ghostty, WezTerm and Warp are launched with arguments or a URL and need no Apple Events. |

No Hardened Runtime exceptions are requested (no JIT, no unsigned executable memory, no disabled
library validation, no DYLD variables).

## Planned entitlements

Each will be added with the milestone that needs it, and documented here with the reason.

| Entitlement | Milestone | Why |
| --- | --- | --- |
| `keychain-access-groups` | 5 | Share Secure Enclave key references between the app and the agent helper. Requires a Developer ID provisioning profile. |
