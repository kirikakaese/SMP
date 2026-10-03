# Entitlements

SMP is distributed outside the Mac App Store with Developer ID signing, the Hardened Runtime and
notarization. It is intentionally **not sandboxed**: it needs direct access to `~/.ssh`, the
`ssh-agent` socket and `/usr/bin` OpenSSH tools.

## Current entitlements

| Entitlement | Since | Why |
| --- | --- | --- |
| `keychain-access-groups` = `$(AppIdentifierPrefix)com.kirikakaese.smp.shared` | Milestone 5 | Both SMP and SMP Agent read the Keychain items that hold Secure Enclave key references, so a key created in the app can sign in the agent. Requires a Developer ID provisioning profile. Builds without a development team cannot use Secure Enclave keys. |
| `com.apple.security.automation.apple-events` | Milestone 4 | **Connect** opens a session in Terminal.app or iTerm2 by sending them a `do script` / `write text` Apple Event containing `ssh <alias>`. macOS asks the user for permission per target app on first use, showing `NSAppleEventsUsageDescription`. Ghostty, WezTerm and Warp are launched with arguments or a URL and need no Apple Events. |

No Hardened Runtime exceptions are requested (no JIT, no unsigned executable memory, no disabled
library validation, no DYLD variables).

## SMP Agent (login-item helper)

`App/AgentHelper/SMPAgent.entitlements` requests only `keychain-access-groups` (the same shared
group). The helper runs with the Hardened Runtime, is not sandboxed (it must reach the system
`ssh-agent` socket) and requests no exceptions.
