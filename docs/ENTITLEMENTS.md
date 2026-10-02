# Entitlements

SMP is distributed outside the Mac App Store with Developer ID signing, the Hardened Runtime and
notarization. It is intentionally **not sandboxed**: it needs direct access to `~/.ssh`, the
`ssh-agent` socket and `/usr/bin` OpenSSH tools.

## Current entitlements

None. `App/SMP.entitlements` is empty, and no Hardened Runtime exceptions are requested
(no JIT, no unsigned executable memory, no disabled library validation, no DYLD variables).

## Planned entitlements

Each will be added with the milestone that needs it, and documented here with the reason.

| Entitlement | Milestone | Why |
| --- | --- | --- |
| `com.apple.security.automation.apple-events` | 4 | Open SSH sessions in Terminal.app, iTerm2 and similar apps via AppleScript. Comes with an `NSAppleEventsUsageDescription` string. |
| `keychain-access-groups` | 5 | Share Secure Enclave key references between the app and the agent helper. Requires a Developer ID provisioning profile. |
