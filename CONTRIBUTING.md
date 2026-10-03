# Contributing to SMP

Thanks for your interest in SSH Management Platform.

## Development setup

1. Install Xcode 16 or later (the Command Line Tools alone cannot run the tests) and
   [XcodeGen](https://github.com/yonaskolb/XcodeGen).
2. Copy `Config/Local.xcconfig.example` to `Config/Local.xcconfig` and set your Team ID. The file is
   git-ignored; never commit it.
3. Run `xcodegen generate` and open `SMP.xcodeproj`, or work on the package directly with
   `swift build --package-path Packages/SMPKit`.

## Before opening a pull request

```sh
swift test --package-path Packages/SMPKit
swiftlint lint --strict
xcrun swift-format lint --recursive App Packages/SMPKit/Sources Packages/SMPKit/Tests
```

To format code in place: `xcrun swift-format format --in-place --recursive App Packages/SMPKit`.

## Rules

- **Never touch the real `~/.ssh` in tests.** Use a temporary `HOME` (see `TemporaryHome`).
- **Never put secrets in `String`, argv, the environment, logs or the metadata database.**
  Use `SecureBytes`, and pass passphrases through `ToolRunOptions.passphrases`.
- Run OpenSSH tools only through `SSHToolRunning`.
- Services are protocols with live and fake implementations, injected through `ServiceContainer`.
- Every user-facing error explains what happened and how to fix it (`SMPError`).
- Keep third-party dependencies to a minimum and justify each one in the pull request.

## Branches and commits

Use descriptive branch names such as `feature/key-generation` or `fix/agent-reconnect`, and
small commits with clear messages.
