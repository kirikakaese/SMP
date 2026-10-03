# Releasing SMP

Releases are built and published by GitHub Actions when you push a version tag. Nothing is signed
or uploaded from your Mac.

## One-time setup

### 1. The update signing key (Sparkle EdDSA)

Sparkle installs an update only if it is signed with this key. Create it on your Mac:

```sh
# Download the Sparkle tools (no installation needed)
curl -L -o /tmp/Sparkle.tar.xz \
  "$(curl -s https://api.github.com/repos/sparkle-project/Sparkle/releases/latest \
     | grep -o 'https://[^"]*Sparkle-[0-9.]*\.tar\.xz' | head -1)"
mkdir -p /tmp/sparkle && tar -xf /tmp/Sparkle.tar.xz -C /tmp/sparkle

/tmp/sparkle/bin/generate_keys                     # creates the key in your login keychain,
                                                   # prints the PUBLIC key
/tmp/sparkle/bin/generate_keys -x /tmp/sparkle-private-key.txt   # exports the PRIVATE key
```

In GitHub → the SMP repository → **Settings → Secrets and variables → Actions**:

- **Variables → New repository variable:** `SPARKLE_PUBLIC_KEY` = the public key that
  `generate_keys` printed.
- **Secrets → New repository secret:** `SPARKLE_PRIVATE_KEY` = the contents of
  `/tmp/sparkle-private-key.txt`.

Then delete the exported file: `rm -P /tmp/sparkle-private-key.txt`. The key stays in your login
keychain (item "Private key for signing Sparkle updates"); keep it, because without it you can
never ship another update to existing installs.

### 2. The Homebrew tap

1. Create a **public** repository named `homebrew-tap` under your account
   (`kirikakaese/homebrew-tap`), with a README so it isn't empty.
2. Create a fine-grained personal access token (GitHub → Settings → Developer settings →
   Fine-grained tokens): repository access **only `kirikakaese/homebrew-tap`**, permission
   **Contents: Read and write**, an expiry you're comfortable with.
3. Add it to the SMP repository as the secret `TAP_TOKEN`.

Without `TAP_TOKEN` releases still work; the workflow just skips the tap and says so.

## Making a release

```sh
git checkout main && git pull
git tag v0.9.0          # or v0.9.1-beta.1 for a beta
git push origin v0.9.0
```

The **Release** workflow then:

1. builds a universal, ad-hoc signed SMP with that version;
2. checks the signature, both architectures, the version and the update key;
3. packages `SMP-<version>.dmg` and `SMP-<version>.zip` with `SHA256SUMS.txt`;
4. signs the zip with the EdDSA key and adds it to `appcast.xml`;
5. publishes the GitHub release (betas as prereleases, offered only to people who opted in);
6. for stable releases, updates `Casks/smp.rb` in the tap.

Version numbers: `vMAJOR.MINOR.PATCH`, optionally `-beta.N`. Tag commits on `main` only; the build
number is the commit count, so it must keep growing.

If a release fails halfway, delete the tag and the (draft) release on GitHub, fix the problem
and push the tag again.
