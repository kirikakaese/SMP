# Architecture

SSH Management Platform (SMP) is a SwiftUI app (macOS 14+, Swift 6 with strict concurrency)
built as MVVM on top of a protocol-based services layer.

## Layout

```
SMP/
├─ project.yml              XcodeGen spec for the app target (SMP.xcodeproj is generated)
├─ App/                     Thin app target: @main, AppDelegate, Info.plist, entitlements
│  └─ AgentHelper/          Login-item helper (SMPAgentHelper.app, “SMP Agent”, menu bar extra) running the built-in agent
└─ Packages/SMPKit/         All logic, as one Swift package with several modules
   ├─ Sources/SMPCore       Models, SMPError, SecureBytes, SSHEnvironment, logging
   ├─ Sources/SMPSSH        SSHToolRunner, ProcessExecutor, askpass broker, wire-format reader/writer,
   │                        public key parsing + fingerprints, randomart, private key header inspection,
   │                        PuTTY conversion, lossless SSHConfigDocument, known_hosts, agent protocol codec
   ├─ Sources/SMPPersistence  GRDB metadata store (tags, groups, notes, favorites, expiry)
   ├─ Sources/SMPServices   KeychainService, KeyDiscoveryService, AgentService, KeyService,
   │                        ArchiveService, ConfigService, SafeFileWriter, DeviceAuthenticator,
   │                        FileWatcherService (FSEvents), KeyFolderSettings, ServiceContainer;
   │                        ProviderService; later: Audit services
   ├─ Sources/SMPProviders  HTTPS clients for GitHub, GitLab, Bitbucket, Gitea/Forgejo
   ├─ Sources/SMPAgent      The built-in agent: socket server, request handler, Touch ID approval,
   │                        forwarding to the system agent (no UI; used by the helper)
   ├─ Sources/SMPUI         SwiftUI views and view models (LibraryModel, sidebar, list, detail, settings)
   ├─ Sources/SMPTestFixtures  test-only key fixtures (not part of any product)
   └─ Tests/                Swift Testing suites per module
```

Dependency direction: `SMPCore` ← `SMPSSH` ← `SMPServices` ← `SMPUI` ← `App`, and
`SMPServices` ← `SMPAgent` ← `App/AgentHelper`.
`SMPProviders` (provider HTTP clients) depends only on `SMPCore` and `SMPSSH`; `SMPServices` uses it.

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

## Built-in agent and Secure Enclave keys

- **Secure Enclave keys** are ECDSA P-256 keys created with CryptoKit. The private key never leaves
  the Secure Enclave. **SMP Agent owns them:** it alone stores the encrypted, device-bound key
  reference, as an item in the login keychain (service `com.kirikakaese.smp.secure-enclave`). The
  item's generic attribute holds the public `SecureEnclaveKeyInfo` (name, comment, signing policy,
  public point). The login keychain needs no entitlement, so ad-hoc signed builds work; macOS
  ties the item to the agent that created it and asks before anything else reads the reference,
  including an updated agent with a new ad-hoc signature (the user answers "Always Allow" once).
  With the Touch ID policy the key's access control includes `.userPresence`; that requirement
  is fixed at creation. SMP writes the public key to `~/.ssh/<name>.pub` so `IdentityFile` can
  select it.
- **Managing them from the app:** `AgentKeyClient` (the app's `SecureEnclaveKeyStoring`) sends
  `AgentKeyCommand`s (list, create, update, delete) as JSON in an `SSH_AGENTC_EXTENSION` request
  named `manage-keys@smp.kirikakaese.com` on the agent socket; the agent answers with
  `SSH_AGENT_SUCCESS` and an `AgentKeyReply`. Only public data crosses the socket. The agent
  serves this extension only to the SMP app it is embedded in: `CodeSignaturePeerVerifier` takes
  the peer's audit token (`LOCAL_PEERTOKEN`), checks its code signature is valid (and, in
  team-signed builds, that it is SMP signed by the same team) and that its bundle is the
  `SMP.app` containing the helper. Updates can change only name, comment and policy, never the
  public key or the Touch ID requirement. Deleting asks for Touch ID in the app first. When the
  agent is not running, the Secure Enclave list offers to start it.
- **SMP Agent** (`App/AgentHelper`, bundle id `com.kirikakaese.smp.agent`) is a login item
  registered with `SMAppService`. It listens on
  `~/Library/Application Support/com.kirikakaese.smp/agent.sock` (socket 0600, folder 0700) and
  speaks the SSH agent protocol (`SSHAgentCodec`). `AgentRequestHandler`:
  - lists Secure Enclave keys first, then the system agent's keys (from the launchd
    `SSH_AUTH_SOCK`; SMP's own socket is never used as upstream);
  - signs for Secure Enclave keys after `LocalSignatureAuthorizer` approved the request
    (Touch ID / password via `LAContext`, reused for the key's reuse window; the evaluated context
    is handed to the Secure Enclave so there is one prompt);
  - forwards other signature requests to the system agent, after Touch ID if
    "Ask for Touch ID before using keys from the macOS agent" is on (shared `UserDefaults` suite);
  - refuses requests that carry secrets (add identity, smartcard PINs, lock/unlock) so private
    keys and passphrases never pass through SMP; forwards the rest unchanged.
  The requesting process is identified with `LOCAL_PEERPID` and shown in the Touch ID prompt and
  the menu bar's activity list. Reuse windows end when the screen locks or the Mac sleeps.
- **Using it:** SSH → Agent proposes `IdentityAgent "<socket>"` in a `Host *` block of
  `~/.ssh/config` through the usual diff review, and checks with `ssh -G` that it took effect.
- **Security keys (FIDO2):** creation uses `ssh-keygen -t ed25519-sk/ecdsa-sk`; resident keys can be
  downloaded with `ssh-keygen -K` (PIN through askpass) into `~/.ssh`. The OpenSSH shipped with
  macOS needs a FIDO provider library for both.

## Providers

- **Accounts** use personal access tokens. When an account is added, `ProviderService` asks the
  provider who the token belongs to, then stores the token in the Keychain
  (`com.kirikakaese.smp.provider-token`, keyed by account id, `…ThisDeviceOnly`) and the account
  (kind, server, user name, last refresh) in the metadata database. Tokens are read from the
  Keychain for each operation and wiped from memory afterwards.
- **Clients** (`SMPProviders`): GitHub / GitHub Enterprise (`/user/keys`, `/user/ssh_signing_keys`),
  GitLab (`/api/v4/user/keys` with `usage_type`), Bitbucket Cloud (`/2.0/users/{uuid}/ssh-keys`, Basic
  auth with email + API token) and Gitea/Forgejo (`/api/v1/user/keys`). Requests go through an
  ephemeral `URLSession` (no cookies, cache or credential storage), HTTPS only; redirects are refused
  and pagination links to another host are rejected, so a token is only ever sent to the configured
  server. Responses are capped at 4 MiB and error bodies are reduced to the provider's message.
  Keys are uploaded as `type base64`, without the local comment.
- **Matching:** keys returned by providers are parsed locally and matched to library keys by SHA256
  fingerprint. The last known key list per account is cached in the database (public data only), so
  the Providers section works offline.
- **Sync** happens when SMP launches, when an account's section is opened (at most every two
  minutes) and with Refresh. There is no other network traffic.
- **Removing** a key from a provider needs Touch ID or the login password and lists the local key and
  the `~/.ssh/config` hosts that use it. Removing an account from SMP only deletes its token and cache.

## Security audit, rotation, commit signing and reminders

- **Audit** (`AuditEngine`, pure): turns key discovery issues, expiry/rotation dates and risky
  `~/.ssh/config` settings (ForwardAgent for `Host *`, StrictHostKeyChecking no, UserKnownHostsFile
  /dev/null, ForwardX11Trusted) into findings with a severity and an optional one-click fix. The score
  is 100 minus a weight per finding. Fixes: file modes (inside key folders only, never through
  symlinks), the passphrase/format sheets, the rotation assistant, or removing a config line through
  the usual diff review.
- **Rotation** (`RotationService` + `RotationJob`, persisted in the metadata database after every
  step): plan (provider accounts holding the key, `Host` aliases whose `IdentityFile` uses it) →
  create the new key → upload/install it (connecting with the old key) → rewrite `IdentityFile`
  lines → test logins with only the new key (`ssh -T git@<provider>` for providers) → after an
  explicit confirmation, remove the old key from providers and servers and archive it locally.
  Each target records its own result; failed targets can be retried or skipped.
- **Commit signing** (`GitSigningService`): reads and writes only the global git config through
  `/usr/bin/git config --global` (`gpg.format ssh`, `user.signingkey`, `commit.gpgsign`, optional
  `tag.gpgsign`, `gpg.ssh.allowedSignersFile`, `user.email` if unset) and adds the key to
  `~/.ssh/allowed_signers`. Every change is listed before it is applied.
- **Reminders:** keys can carry a rotation date (`KeyMetadata.rotateAt`) next to the expiry date. The
  app writes `reminders.json` (key names, fingerprints, dates; mode 0600) to Application Support;
  SMP Agent checks it at launch and every six hours and shows each reminder once, 14 days and 1 day
  before and on the date.

## Archive

`ArchiveService` stores archived keys in `Application Support/Archive`: a public JSON manifest
and an AES-256-GCM sealed payload (the manifest id is authenticated data). The archive key is
generated on first use and kept in the Keychain. Archiving decrypts the result and compares it
with the files on disk before the originals are deleted. Restoring never overwrites; on a name
conflict the key is restored as `<name>_restored`.

## Backups (`BackupService`)

File → Back Up… writes one encrypted `.smpbackup` file (mode 0600) to a place the user chooses:

- **Contents:** every key file in the key folders (private keys, `.pub`, certificates), not
  archived keys and not Secure Enclave keys (they cannot leave the Mac); `~/.ssh/config` and
  `known_hosts`; SMP's metadata (key notes and dates, tags, groups and their assignments, host
  settings and tags, tunnels). Provider tokens and rotation jobs are left out.
- **Format:** `"SMPBACKUP" || version || PBKDF2 iterations || salt || AES-256-GCM box`. The key
  comes from the user's passphrase through PBKDF2-HMAC-SHA256 (600,000 rounds, 16-byte random
  salt); the header is authenticated data, so changing the iterations or salt breaks decryption.
  The plaintext is the manifest JSON followed by each file's contents, as SSH `string`s, so the
  file names are encrypted too. Key material is built and parsed in `SecureBytes`.
- **Restore** (File → Restore from Backup…) decrypts into memory, then shows a plan before
  anything is written. Files are never overwritten: identical files are skipped, a different file
  with the same name gets the backup's version next to it as `<name>-restored` (keeping `.pub`
  and `-cert.pub` so pairs stay pairs). Config files can only go to `~/.ssh/config` and
  `~/.ssh/known_hosts`; key files only to `~/.ssh` or a folder SMP watches, otherwise into
  `~/.ssh`, so a crafted backup cannot write anywhere else. Metadata is merged: tags and groups
  are matched by name, existing notes, host settings and tunnels are kept.

## Deletion and export

Permanent deletion shows an impact report (config references, agent, git signing), lets the
user decide what happens to each config reference, requires typing the key name and Touch ID or
the login password (`LocalAuthentication`), removes the key from the agent and its Keychain
passphrase (`ssh-add -d --apple-use-keychain`), then overwrites and unlinks the files.
Exporting a private key also requires re-authentication; the file is copied by the kernel and
never read into SMP's memory.

## App lock and first run

- **App lock** (`AppLockModel`, on by default): while locked, `RootView` replaces the whole
  workspace with `LockView`, so every sheet it presented goes away too; observable models keep
  their state, and the keys stay loaded in memory. Unlocking uses `DeviceAuthenticator`
  (`.deviceOwnerAuthentication`: Touch ID, Apple Watch or the login password). SMP locks at
  launch, after `idleMinutes` without keyboard or mouse input in SMP (default 5; 0 = never for
  idleness), when the screen locks and before the Mac sleeps, and on Lock SMP (⌃⌘L). On a Mac
  without a login password the lock is unavailable and stays off, so nobody can be locked out.
  Actions with their own confirmation (delete, export, …) keep it regardless of the lock.
- **Onboarding** (`OnboardingView`) runs once, before the first lock: what SMP does and doesn't
  do with data, the keys and audit score it found, the app lock settings, and starting SMP Agent.
  Settings → General can show it again.

## Shortcuts

`App/Sources/Shortcuts.swift` defines App Intents (they live in the app target so Xcode extracts
their metadata): Copy Public Key, List SSH Keys, Connect to SSH Host, Start / Stop SSH Tunnel and
Check SSH Security, with entities for keys, hosts and tunnels and suggested phrases for Siri and
Spotlight. They use the running app's `ServiceContainer` (`AppContext`), so a tunnel started from
Shortcuts is the same one SMP's window shows. The logic is in `SMPServices/ShortcutSupport.swift`
(tested in the package). Actions only read and return public data (public key lines,
fingerprints, aliases, tunnel names, the audit score); none touches private keys.

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
| Secure Enclave keys | Secure Enclave; only an encrypted, device-bound reference in the login keychain, owned by SMP Agent |
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
| `ProviderAccount` | id, provider kind, server URL, username, login email (Bitbucket), last sync; token in the Keychain under the account id |
| `RemoteKey` (cache) | account, remote id, title, public key line, fingerprint, usages (authentication/signing), created/last used/expires |
| `Deployment` | key record, target (provider account or `user@host:port`), remote key id, usage (auth/signing), deployed/verified dates, status |
| `RotationJob` | id, old key (name, fingerprint, paths), new key (name, path, public key), targets with per-target deployed/verified/retired/skipped/error, completed steps, log, timestamps; stored as JSON, resumable |
| Audit | computed on demand (findings: rule, severity, subject, fix); not stored |
| Settings | `UserDefaults`: watched folders, terminal app, lock policy, backup schedule |

## Third-party dependencies

- **GRDB** (SQLite toolkit, `SMPPersistence`): explicit, versioned migrations, mature, and works
  with Swift 6 strict concurrency. Chosen over SwiftData. Stores metadata only.
- **Sparkle 2** (updates, app target only): the standard for updating apps outside the App Store;
  verifies EdDSA signatures and replaces the app bundle (including SMP Agent) atomically.

## Releases and updates

- **Release workflow** (`.github/workflows/release.yml`, on tags `vX.Y.Z` or `vX.Y.Z-beta.N`):
  builds a universal, ad-hoc signed app with `MARKETING_VERSION` from the tag and
  `CURRENT_PROJECT_VERSION` = commit count (Sparkle compares the build number), verifies the
  signature, architectures, version and update key, then packages `SMP-<version>.zip` (for
  Sparkle) and `SMP-<version>.dmg` (for people and Homebrew) with SHA-256 checksums.
- **Appcast:** `sign_update` (from the latest Sparkle release) signs the zip with the EdDSA key
  from the `SPARKLE_PRIVATE_KEY` secret; `scripts/appcast.py` adds the entry to the previous
  `appcast.xml` (newest 20 kept) and the workflow attaches it to the release. The app reads
  `releases/latest/download/appcast.xml`. Betas are prereleases with
  `<sparkle:channel>beta</sparkle:channel>`; their appcast is also uploaded to the latest stable
  release so opted-in users see them.
- **Homebrew:** for stable releases the workflow writes `Casks/smp.rb` (from
  `scripts/smp.rb.template`) into `kirikakaese/homebrew-tap` with the DMG's SHA-256, using the
  `TAP_TOKEN` secret. `auto_updates true` leaves updating to Sparkle.
- **App:** `UpdateModel` (`App/Sources/Updates.swift`) wraps `SPUStandardUpdaterController`.
  Settings → Updates exposes automatic checks, the interval (daily, weekly, monthly), automatic
  download and install, the beta channel (`allowedChannels`), the last check and Check Now; the
  app menu has Check for Updates…. Builds without `SUPublicEDKey` (local builds) never check.

Any other dependency must be justified in the pull request that adds it.
