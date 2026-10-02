# Architecture

SSH Management Platform (SMP) is a SwiftUI app (macOS 14+, Swift 6 with strict concurrency)
built as MVVM on top of a protocol-based services layer.

## Layout

```
SMP/
├─ project.yml              XcodeGen spec for the app target (SMP.xcodeproj is generated)
├─ App/                     Thin app target: @main, AppDelegate, Info.plist, entitlements
├─ AgentHelper/             (milestone 5) login-item helper running the built-in agent
└─ Packages/SMPKit/         All logic, as one Swift package with several modules
   ├─ Sources/SMPCore       Models, SMPError, SecureBytes, SSHEnvironment, logging
   ├─ Sources/SMPSSH        SSHToolRunner, ProcessExecutor, askpass broker;
   │                        later: key parsing, fingerprints, config/known_hosts parsers, agent codec
   ├─ Sources/SMPServices   KeychainService, ServiceContainer;
   │                        later: Key, Agent, Config, KnownHosts, Provider, Audit, FileWatcher services
   ├─ Sources/SMPUI         SwiftUI feature views and view models
   └─ Tests/                Swift Testing suites per module
```

Dependency direction: `SMPCore` ← `SMPSSH` ← `SMPServices` ← `SMPUI` ← `App`.
Provider clients (`SMPProviders`) and the metadata store (`SMPPersistence`) will be added as
separate modules when their milestones start.

## Services and dependency injection

Every service is a protocol (`SSHToolRunning`, `KeychainServicing`, …) with a live
implementation and an in-memory or fake one. `ServiceContainer` bundles them; the app injects
`ServiceContainer.live()` through the SwiftUI environment (`\.services`). Previews and UI tests
use `ServiceContainer.preview()`, which never touches the real `~/.ssh` or Keychain.

## Running OpenSSH: `SSHToolRunner`

All calls to `ssh-keygen`, `ssh-add`, `ssh` and `ssh-keyscan` go through `SSHToolRunning`:

- absolute `/usr/bin` paths; never resolved through `PATH`, never through a shell
- arguments as an array; NUL bytes are rejected
- an explicit, minimal child environment (`HOME`, `USER`, `LOGNAME`, `PATH`, `TMPDIR`, `LC_ALL=C`,
  `SSH_AUTH_SOCK`)
- stdin is `/dev/null` unless input is given, so tools never block on a hidden prompt
- timeouts with SIGTERM → SIGKILL escalation, and Swift task cancellation
- bounded output capture
- only the tool name and argument count are logged

**Passphrases** use `SSH_ASKPASS` with `SSH_ASKPASS_REQUIRE=force`. The askpass broker creates a
private 0700 directory containing a FIFO and a tiny script (`exec /bin/cat <fifo>`). It writes
each queued passphrase into the FIFO when the tool asks for it. A passphrase is therefore never
in argv, the environment or a regular file. When OpenSSH asks for more passphrases than were
queued, it treats the failed prompt as an empty passphrase. Any operation that sets a
passphrase must therefore verify the result afterwards (for example, by checking that the private
key's cipher is not `none`).

## Secrets

| Secret | Where it lives |
| --- | --- |
| Private keys | `~/.ssh` files (or the encrypted archive) |
| Key passphrases | macOS Keychain through OpenSSH's own `UseKeychain` / `--apple-use-keychain` |
| Provider tokens | Keychain (`KeychainService`, `…ThisDeviceOnly`, never synchronized) |
| Secure Enclave keys | Secure Enclave; only an opaque reference in the Keychain |
| Archive / backup keys | Keychain |

In memory, secrets are held in `SecureBytes`, which are locked against swapping and zeroed on
release. The metadata store never contains secrets.

## Data model (metadata only)

| Entity | Key fields |
| --- | --- |
| `KeyRecord` | id, SHA256 fingerprint (identity), display name, private/public/certificate paths, kind (file / secureEnclave / fido / agentOnly), algorithm, bits/curve, comment, passphrase-protected, format, created/modified/last-used, expiry, rotation reminder, notes, favorite, archived-at, archive location |
| `Tag` | id, name, color (many-to-many with keys and hosts) |
| `KeyGroup` | id, name, sort index, member keys |
| `SecureEnclaveKey` | key record id, Keychain reference, access control, require-every-use |
| `HostProfile` | config alias (the `~/.ssh/config` block remains the source of truth), tags, group, favorite, preferred terminal, last connected |
| `TunnelProfile` | id, name, host alias, forwards (local/remote/dynamic), auto-start |
| `ProviderAccount` | id, provider type, base URL, username, Keychain token reference, scopes, last sync |
| `Deployment` | key record, target (provider account or `user@host:port`), remote key id, usage (auth/signing), deployed/verified dates, status |
| `RotationJob` | id, old key, new key, state (generated → deployed → configUpdated → verified → retired), step log, timestamps; resumable |
| `AuditSnapshot` | date, score, findings (rule id, severity, subject, fix available) |
| Settings | `UserDefaults`: watched folders, terminal app, lock policy, backup schedule |

## Third-party dependencies

None yet. Planned: Sparkle 2 (updates, milestone 9). Any other dependency must be justified in
the pull request that adds it.
