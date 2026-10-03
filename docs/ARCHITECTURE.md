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
   ├─ Sources/SMPSSH        SSHToolRunner, ProcessExecutor, askpass broker, wire-format reader/writer,
   │                        public key parsing + fingerprints, randomart, private key header inspection,
   │                        PuTTY conversion, lossless SSHConfigDocument; later: known_hosts, agent codec
   ├─ Sources/SMPPersistence  GRDB metadata store (tags, groups, notes, favorites, expiry)
   ├─ Sources/SMPServices   KeychainService, KeyDiscoveryService, AgentService, KeyService,
   │                        ArchiveService, ConfigService, SafeFileWriter, DeviceAuthenticator,
   │                        FileWatcherService (FSEvents), KeyFolderSettings, ServiceContainer;
   │                        later: Config, KnownHosts, Provider, Audit services
   ├─ Sources/SMPUI         SwiftUI views and view models (LibraryModel, sidebar, list, detail, settings)
   ├─ Sources/SMPTestFixtures  test-only key fixtures (not part of any product)
   └─ Tests/                Swift Testing suites per module
```

Dependency direction: `SMPCore` ← `SMPSSH` ← `SMPServices` ← `SMPUI` ← `App`.
Provider clients (`SMPProviders`) will be added as a separate module in milestone 6.

## Key discovery

`KeyDiscoveryService` scans `~/.ssh` and user-added folders (non-recursively) and classifies
files by content, not by name. It pairs `name`, `name.pub` and `name-cert.pub`, and reports
private-only keys and orphaned public keys. Each key carries a list of issues: permissions,
no passphrase, weak algorithm, legacy format, mismatched `.pub`. `FileWatcherService` (FSEvents)
triggers a rescan when the folders change outside the app.

**Private key files** are inspected by `PrivateKeyInspector`. The file is read into
`SecureBytes`, base64-decoded into `SecureBytes`, and only the unencrypted header is parsed:
format, cipher, KDF rounds and the embedded public key. The private section is never
interpreted, copied or logged, and the buffers are zeroed afterwards. This is how SMP shows
fingerprints and passphrase status without asking for a passphrase.

Metadata (tags, groups, notes, favorites, expiry) is stored per SHA256 fingerprint, so it
survives renames and moves, and applies to every copy of the same key.

## Key lifecycle (`KeyService`)

All operations run `ssh-keygen` through `SSHToolRunner`. Passphrases go through the askpass
pipe; an empty passphrase is passed as `-N ""` or `-P ""`, which is not a secret.

- **Create / import:** files are written into a private staging folder
  (`~/.ssh/.smp-staging.XXXXXX`, mode 0700), checked, given the right permissions
  (600 private, 644 public, 700 for `~/.ssh`), then atomically renamed into place. An existing
  key with the same name is only replaced on explicit request, and is archived first.
- **Verification after every passphrase change:** the private key's header is read back.
  If a passphrase was requested but the key is unencrypted (OpenSSH treats a failed prompt as
  an empty passphrase), the key is deleted and an error is shown.
- **Import** validates the key with `ssh-keygen -y`. PuTTY files are converted by
  `PuTTYKeyConverter`: it verifies the file's MAC (v2: HMAC-SHA-1, v3: HMAC-SHA-256), assembles
  an `openssh-key-v1` file in `SecureBytes`, and checks Ed25519 seeds against the public key.
  Encrypted `.ppk` files must be exported from PuTTYgen first.
- **Rename** moves private key, public key and certificate together and updates `IdentityFile`
  references in `~/.ssh/config` and included files, rolling back if anything fails.

## Config files

`SSHConfigDocument` is a lossless, line-based model: unchanged documents render byte-for-byte
identical. `ConfigService` follows `Include` (globs, `~`, relative to `~/.ssh`) and finds
`IdentityFile` references (`~`, `%d`, `%u`, relative paths). `SafeFileWriter` writes text files:
advisory lock (lock files live in Application Support, never in `~/.ssh`) → refuse if the file
changed since it was read → timestamped backup in `Application Support/Backups` → write to a
temporary file → atomic rename. Symlinked configs (dotfile managers) are written through.

## Hosts, known_hosts, tunnels and deployment

- **Host editor.** `SSHConfigDocument.blocks()` exposes `Host`/`Match` blocks; edits
  (`setValues`, `setPatterns`, `removeBlock`, `duplicateBlock`) touch only the lines involved, so
  comments, ordering and formatting survive. Every change is staged as a `ConfigChange`: the user
  sees a line diff (`TextDiff`) and the problems `ssh -G -F <temporary copy>` reports, and only then
  is the file written through `SafeFileWriter`. The raw editor highlights unknown keywords.
  Favorites, notes, tags and last-connected dates live in the metadata database, keyed by alias;
  the config file stays the source of truth.
- **Connection test.** `ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -T <alias> true`;
  stderr is classified (authentication, unknown/changed host key, DNS, refused, timeout,
  unreachable) into a plain-language explanation. Git hosts' "no shell access" greetings count as
  success. Nothing is ever prompted and `known_hosts` is never modified by a test.
- **Connect.** Terminal and iTerm2 via Apple Events (`ssh <alias>` with the alias shell-quoted);
  Ghostty and WezTerm via launch arguments; Warp via a launch configuration and its URL scheme.
- **known_hosts.** `KnownHostsDocument` is lossless, understands markers, `[host]:port`, negated
  patterns and hashed entries (`|1|salt|HMAC-SHA1`). New keys are fetched with `ssh-keyscan` but
  only added after the user pasted a matching fingerprint or explicitly confirmed it was checked
  another way; a changed host key can only be replaced with a verified fingerprint. New entries
  follow the file's style (hashed if most entries are hashed).
- **Tunnels.** `ssh -N -o BatchMode=yes -o ExitOnForwardFailure=yes …` per profile, managed by
  `TunnelService`; failures keep ssh's last error message. All tunnels stop when SMP quits.
- **Deploying keys.** Like `ssh-copy-id`: a short POSIX `sh` script runs on the server
  (`exec sh -c '<script>'`) and the key line arrives on stdin. It creates `~/.ssh` (700) and
  `authorized_keys` (600), is idempotent, and removal deletes only the exact line after making
  `authorized_keys.smp-backup`. An optional login test with only the new key (`IdentitiesOnly`,
  no agent) confirms it works. A server password, if needed, goes through the askpass pipe with
  public-key authentication disabled so it can only answer a password prompt.

## Archive

`ArchiveService` stores archived keys in `Application Support/Archive`: a public JSON manifest
and an AES-256-GCM sealed payload (the manifest id is authenticated data). The archive key is
generated on first use and kept in the Keychain. Archiving decrypts the result and compares it
with the files on disk before the originals are deleted. Restoring never overwrites; on a name
conflict the key is restored as `<name>_restored`.

## Deletion and export

Permanent deletion shows an impact report (config references, agent, git signing), lets the
user decide what happens to each config reference, requires typing the key name and Touch ID or
the login password (`LocalAuthentication`), removes the key from the agent and its Keychain
passphrase (`ssh-add -d --apple-use-keychain`), then overwrites and unlinks the files.
Exporting a private key also requires re-authentication; the file is copied by the kernel and
never read into SMP's memory.

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
private 0700 directory containing one FIFO per queued passphrase and a tiny script. Each time the
tool asks, the script atomically claims the next unused FIFO (by renaming it) and reads it, and
the broker writes that one passphrase into it. Because every FIFO is used exactly once, a
passphrase can never be read by the wrong prompt. A passphrase is never in argv, the environment
or a regular file. When OpenSSH asks for more passphrases than were
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
| `HostMetadata` | config alias (the `~/.ssh/config` block remains the source of truth), favorite, notes, last connected; tags via `hostTag` |
| `TunnelProfile` | id, name, host alias, forwards (local/remote/dynamic, stored as JSON) |
| `ProviderAccount` | id, provider type, base URL, username, Keychain token reference, scopes, last sync |
| `Deployment` | key record, target (provider account or `user@host:port`), remote key id, usage (auth/signing), deployed/verified dates, status |
| `RotationJob` | id, old key, new key, state (generated → deployed → configUpdated → verified → retired), step log, timestamps; resumable |
| `AuditSnapshot` | date, score, findings (rule id, severity, subject, fix available) |
| Settings | `UserDefaults`: watched folders, terminal app, lock policy, backup schedule |

## Third-party dependencies

- **GRDB** (SQLite toolkit, `SMPPersistence`): explicit, versioned migrations, mature, and works
  with Swift 6 strict concurrency. Chosen over SwiftData. Stores metadata only.
- Planned: Sparkle 2 (updates, milestone 9).

Any other dependency must be justified in the pull request that adds it.
