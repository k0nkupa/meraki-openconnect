import Foundation

enum TunnelIconPresentation: Equatable {
    case steady
    case transition

    init(phase: AppPhase) {
        switch phase {
        case .connecting, .disconnecting:
            self = .transition
        default:
            self = .steady
        }
    }

    var shouldAnimate: Bool {
        self == .transition
    }
}
