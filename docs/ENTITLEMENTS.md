# Entitlements

SMP is distributed outside the Mac App Store, ad-hoc signed with the Hardened Runtime (no paid
Apple Developer account, so no notarization). It therefore uses no entitlement that needs a
provisioning profile. It is intentionally **not sandboxed**: it needs direct access to `~/.ssh`, the
`ssh-agent` socket and `/usr/bin` OpenSSH tools.

## Current entitlements

| Entitlement | Since | Why |
| --- | --- | --- |
| `com.apple.security.automation.apple-events` | Milestone 4 | **Connect** opens a session in Terminal.app or iTerm2 by sending them a `do script` / `write text` Apple Event containing `ssh <alias>`. macOS asks the user for permission per target app on first use, showing `NSAppleEventsUsageDescription`. Ghostty, WezTerm and Warp are launched with arguments or a URL and need no Apple Events. |

`keychain-access-groups` (milestone 5) was removed in milestone 8: it needs a provisioning profile,
which ad-hoc signed builds cannot carry. SMP Agent now owns the Secure Enclave keys alone (see
ARCHITECTURE.md).

No Hardened Runtime exceptions are requested (no JIT, no unsigned executable memory, no disabled
library validation, no DYLD variables).

## SMP Agent (login-item helper)

`App/AgentHelper/SMPAgent.entitlements` requests no entitlements. It keeps Secure Enclave key
references in the login keychain, which needs none. The helper runs with the Hardened Runtime, is not sandboxed (it must reach the system
`ssh-agent` socket) and requests no exceptions.
