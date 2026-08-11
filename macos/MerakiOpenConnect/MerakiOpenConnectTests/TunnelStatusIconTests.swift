import XCTest
@testable import MerakiOpenConnect

@MainActor
final class TunnelStatusIconTests: XCTestCase {
    func testTransitionPhasesRequestAnimation() {
        XCTAssertTrue(TunnelIconPresentation(phase: .connecting).shouldAnimate)
        XCTAssertTrue(TunnelIconPresentation(phase: .disconnecting).shouldAnimate)
    }

    func testStableAndProblemPhasesRemainStatic() {
        XCTAssertFalse(TunnelIconPresentation(phase: .disconnected).shouldAnimate)
        XCTAssertFalse(
            TunnelIconPresentation(
                phase: .connected(VPNStatus(connected: true, pid: 44, interface: "utun9", transport: "dtls"))
            ).shouldAnimate
        )
        XCTAssertFalse(TunnelIconPresentation(phase: .error("safe")).shouldAnimate)
        XCTAssertFalse(
            TunnelIconPresentation(
                phase: .setupRequired(SetupIssue(message: "Setup required", command: nil))
            ).shouldAnimate
        )
    }
}
