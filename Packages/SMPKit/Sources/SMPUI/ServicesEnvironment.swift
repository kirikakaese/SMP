import SMPServices
import SwiftUI

private struct ServicesKey: EnvironmentKey {
    static let defaultValue: ServiceContainer = .preview()
}

extension EnvironmentValues {
    /// The injected service container. Defaults to preview services so a missing injection never
    /// touches the real system.
    public var services: ServiceContainer {
        get { self[ServicesKey.self] }
        set { self[ServicesKey.self] = newValue }
    }
}
