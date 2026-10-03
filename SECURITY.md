# Security Policy

SSH Management Platform (SMP) manages SSH private keys, so security issues are taken seriously.

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/kirikakaese/SMP/security/advisories/new).
Include the affected version, steps to reproduce and the impact you expect.

You can expect an acknowledgement within 7 days. Fixes for confirmed issues are released as soon
as practical, and reporters are credited unless they prefer otherwise.

## Supported versions

Until 1.0, only the latest release receives security fixes.

## Threat model

### Assets

1. SSH private keys and their passphrases.
2. Provider access tokens (GitHub, GitLab, Bitbucket, Gitea).
3. The integrity of `~/.ssh/config`, `known_hosts` and `authorized_keys` files.
4. Secure Enclave keys, which cannot be exported by design.

### Trust boundaries

- **Trusted:** the logged-in macOS user, the OS (Keychain, Secure Enclave, `/usr/bin` OpenSSH).
- **Untrusted:** provider API responses, remote servers, pasted or imported key files, config
  files written by other programs, and other processes that request signatures from SMP's agent.

### In scope

| Threat | Mitigation |
| --- | --- |
| Secrets leaking through process arguments (visible to `ps`) | Passphrases go through a private askpass pipe or stdin. Argument arrays only, never shell strings. |
| Secrets leaking through logs, crash reports or analytics | No telemetry. Unified logging never receives secrets; paths are logged as `.private`. |
| Secrets lingering in memory | `SecureBytes` buffers are locked against swapping and zeroed after use. |
| Malicious tool on `PATH` | OpenSSH tools are run from absolute `/usr/bin` paths with a minimal environment. |
| Corrupting config files | Timestamped backups, atomic writes, file locking, and change detection before saving. |
| Malicious input (pasted keys, API responses, config files) | All external input is validated and parsed defensively. |
| Unwanted use of agent keys by other local processes | Built-in agent prompts with Touch ID and shows the requesting process. Per-key "confirm every use". |
| Loss of keys through accidental deletion | Impact report, encrypted archive (AES-256-GCM, key in the Keychain) with undo, typed confirmation and Touch ID / password before permanent deletion. |
| A key the user believes is protected is silently stored without passphrase | After every operation that sets a passphrase, SMP re-reads the key header; an unprotected result is deleted and reported. |
| Private key export | Requires Touch ID / password; the file is copied without passing through SMP's memory. |
| Leftover key material after deletion | Files are overwritten with zeros before unlinking. On APFS (copy-on-write, SSD) this cannot guarantee erasure; FileVault is the real protection. |
| Token theft from disk | Provider tokens are stored only in the Keychain, never synchronized. |

### Out of scope

- An attacker running code as the same macOS user with full disk access. They can read
  `~/.ssh` directly; SMP cannot protect against that beyond what macOS provides.
- A compromised macOS installation or a compromised `/usr/bin/ssh*`.
- Physical attacks on an unlocked Mac.

## Hardened Runtime entitlements

SMP uses the Hardened Runtime without exceptions. Every entitlement is documented in
[docs/ENTITLEMENTS.md](docs/ENTITLEMENTS.md).
