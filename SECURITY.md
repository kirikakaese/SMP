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
| Unwanted use of agent keys by other local processes | SMP's agent asks for Touch ID (per key: every use, or a short reuse window that ends on screen lock/sleep), names the requesting process in the prompt and logs every request in the menu bar. Optionally the same for keys forwarded to the macOS agent. The socket is mode 0600 in a 0700 folder. |
| Secrets passing through SMP's agent | Requests that carry private keys, PINs or lock passphrases are refused, never relayed. Secure Enclave keys sign inside the Secure Enclave; the private key never exists in memory or on disk. |
| Malformed agent requests | Messages are capped at 256 KiB and parsed with bounds-checked readers; anything unexpected is answered with SSH_AGENT_FAILURE. |
| Loss of keys through accidental deletion | Impact report, encrypted archive (AES-256-GCM, key in the Keychain) with undo, typed confirmation and Touch ID / password before permanent deletion. |
| A key the user believes is protected is silently stored without passphrase | After every operation that sets a passphrase, SMP re-reads the key header; an unprotected result is deleted and reported. |
| Private key export | Requires Touch ID / password; the file is copied without passing through SMP's memory. |
| Leftover key material after deletion | Files are overwritten with zeros before unlinking. On APFS (copy-on-write, SSD) this cannot guarantee erasure; FileVault is the real protection. |
| Accepting a malicious host key (MITM) | Host keys fetched with `ssh-keyscan` are only added after the user pasted a matching fingerprint or explicitly confirmed an out-of-band check. A changed host key can only be replaced with a verified fingerprint. Connection tests, tunnels and deployments use `StrictHostKeyChecking=yes` and never modify `known_hosts`. |
| Locking yourself out of a server | Deployment never replaces `authorized_keys`; removal deletes one exact line after a backup on the server, and asks for confirmation. |
| Server password exposure during deployment | The password is passed through the askpass pipe only, public-key authentication is disabled for that connection so it can only answer a password prompt, and it is never stored. |
| Token theft from disk | Provider tokens are stored only in the Keychain (`…ThisDeviceOnly`, never synchronized) and wiped from memory after each request. |
| Token sent to the wrong server | HTTPS only; an ephemeral session without cookies or cache; redirects are refused and pagination links to other hosts are rejected. |
| Malicious provider responses | Responses are size-capped and decoded into typed models; keys are parsed and fingerprinted locally before they are matched. |
| Unintended removal of keys on a provider | Removal asks for Touch ID or the login password and shows the local key and hosts that depend on it. |

### Out of scope

- An attacker running code as the same macOS user with full disk access. They can read
  `~/.ssh` directly; SMP cannot protect against that beyond what macOS provides.
- A compromised macOS installation or a compromised `/usr/bin/ssh*`.
- Physical attacks on an unlocked Mac.

## Hardened Runtime entitlements

SMP uses the Hardened Runtime without exceptions. Every entitlement is documented in
[docs/ENTITLEMENTS.md](docs/ENTITLEMENTS.md).
