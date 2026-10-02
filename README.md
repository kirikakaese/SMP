# SSH Management Platform (SMP)

**SSH Management Platform** (short: **SMP**) is a native macOS app for creating, organizing,
deploying, auditing and deleting SSH keys and SSH host configurations. It aims to feel like a
first-party Apple utility: fast, safe and keyboard-friendly.

> **Status:** early development. Milestone 1 (project skeleton, architecture, CI, tool runner,
> Keychain service) is in progress. Features below describe the planned scope.

## Features (planned)

- **Key library:** discovers keys in `~/.ssh` and other folders, watches them live, and shows
  fingerprints, randomart, permissions, usage and expiry. Supports tags, groups, favorites and search.
- **Create, import, export, edit:** Ed25519 (default), ECDSA, RSA ≥ 3072, FIDO2 `-sk` keys and
  Secure Enclave keys. Import supports OpenSSH, PEM/PKCS#8 and PuTTY formats.
- **Safe deletion:** an impact report before anything is removed, a restorable archive, and
  permanent deletion with re-authentication.
- **Hosts:** a lossless `~/.ssh/config` editor, connection tests, one-click connect in your
  terminal, tunnels, a `known_hosts` manager and deploying keys to servers.
- **Agent:** control the system `ssh-agent`, plus a built-in agent for Secure Enclave keys with
  Touch ID confirmation, and a menu bar extra.
- **Providers:** GitHub, GitLab, Bitbucket, Gitea/Forgejo and custom servers. Sync and match keys by fingerprint.
- **Security audit:** findings with one-click fixes, a key rotation assistant, git commit signing
  setup and expiry reminders.
- **Backup & restore:** encrypted `.smpbackup` bundles.

## Requirements

- macOS 14 Sonoma or later, Apple Silicon or Intel.

## Install

Signed and notarized releases (DMG, Sparkle auto-updates and a Homebrew cask) will be published
once milestone 9 is complete.

## Build from source

Requirements: Xcode 16 or later (Swift 6) and [XcodeGen](https://github.com/yonaskolb/XcodeGen).

```sh
git clone https://github.com/kirikakaese/SMP.git
cd SMP

# Run the package tests (uses temporary HOME folders; never touches your real ~/.ssh)
swift test --package-path Packages/SMPKit

# Generate the Xcode project and open it
brew install xcodegen
xcodegen generate
open SMP.xcodeproj
```

The Xcode project is generated from `project.yml` and is not checked in.

## Project layout

```
App/                 App target (entry point, Info.plist, entitlements)
Packages/SMPKit/     All logic, as a Swift package
  Sources/SMPCore      Models, errors, secret-handling primitives
  Sources/SMPSSH       SSHToolRunner and everything that talks to OpenSSH
  Sources/SMPServices  Protocol-based services (Keychain, keys, agent, config, ...)
  Sources/SMPUI        SwiftUI views
docs/                Architecture, entitlements and design notes
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for details.

## Security model

- SMP never sends private key material anywhere and never writes it into its own database.
  Secrets live in `~/.ssh`, the macOS Keychain or the Secure Enclave.
- OpenSSH tools are always run from `/usr/bin` with argument arrays, never through a shell.
  Passphrases reach them through a private pipe, never through command-line arguments or
  environment variables.
- There is no telemetry.
- The app uses the Hardened Runtime and is intentionally not sandboxed, so it can read `~/.ssh`
  and reach the `ssh-agent` socket.

See [SECURITY.md](SECURITY.md) for the threat model and how to report a vulnerability.

## License

SMP is released under the [MIT License](LICENSE).
