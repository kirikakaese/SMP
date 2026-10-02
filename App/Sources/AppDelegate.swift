import AppKit
import SMPCore

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationWillFinishLaunching(_ notification: Notification) {
        // SMP writes to pipes of child processes (ssh-keygen, ssh-add). If a child exits early,
        // the write must fail with EPIPE instead of terminating the app.
        signal(SIGPIPE, SIG_IGN)
        Log.app.info("SMP launching")
    }
}
