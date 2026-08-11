import AppKit
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

    func testReducedMotionSuppressesTransitionAnimation() {
        XCTAssertFalse(
            TunnelIconPresentation(phase: .connecting, reduceMotion: true).shouldAnimate
        )
        XCTAssertTrue(
            TunnelIconPresentation(phase: .connecting, reduceMotion: false).shouldAnimate
        )
    }

    func testTransitionFramesAdvanceAndWrap() {
        XCTAssertEqual(TunnelIconPresentation.nextActiveArc(after: 0), 1)
        XCTAssertEqual(TunnelIconPresentation.nextActiveArc(after: 1), 2)
        XCTAssertEqual(TunnelIconPresentation.nextActiveArc(after: 2), 3)
        XCTAssertEqual(TunnelIconPresentation.nextActiveArc(after: 3), 1)
    }

    func testMenuBarImageIsTemplateWithVisibleInkOnTransparentCanvas() throws {
        let image = TunnelMenuBarImage.image(activeArc: 0)

        XCTAssertTrue(image.isTemplate)
        XCTAssertEqual(image.size, NSSize(width: 18, height: 18))

        let bitmap = try XCTUnwrap(
            image.tiffRepresentation.flatMap(NSBitmapImageRep.init(data:))
        )
        XCTAssertEqual(bitmap.colorAt(x: 0, y: 0)?.alphaComponent, 0)

        let opaquePixelCount = (0..<18).reduce(0) { count, x in
            count + (0..<18).filter { y in
                (bitmap.colorAt(x: x, y: y)?.alphaComponent ?? 0) > 0.5
            }.count
        }
        XCTAssertGreaterThan(opaquePixelCount, 20)
    }

    func testMenuBarImageIsCachedForStatusItemLifetime() {
        XCTAssertTrue(TunnelMenuBarImage.image(activeArc: 0) === TunnelMenuBarImage.image(activeArc: 0))
    }
}
