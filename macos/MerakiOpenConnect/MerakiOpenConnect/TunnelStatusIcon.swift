import AppKit
import SwiftUI

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

    init(phase: AppPhase, reduceMotion: Bool) {
        self.init(phase: phase)
        if reduceMotion {
            self = .steady
        }
    }

    var shouldAnimate: Bool {
        self == .transition
    }

    static func nextActiveArc(after activeArc: Int) -> Int {
        activeArc == 3 ? 1 : min(max(activeArc, 0) + 1, 3)
    }
}

struct TunnelStatusIcon: View {
    let phase: AppPhase
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var activeArc = 0

    var body: some View {
        Image(nsImage: TunnelMenuBarImage.image(activeArc: activeArc))
            .renderingMode(.template)
            .task(id: presentation) {
                guard presentation.shouldAnimate else {
                    activeArc = 0
                    return
                }

                while !Task.isCancelled {
                    try? await Task.sleep(for: .milliseconds(270))
                    guard !Task.isCancelled else { return }
                    activeArc = TunnelIconPresentation.nextActiveArc(after: activeArc)
                }
            }
        .accessibilityHidden(true)
    }

    private var presentation: TunnelIconPresentation {
        TunnelIconPresentation(phase: phase, reduceMotion: reduceMotion)
    }
}

enum TunnelMenuBarImage {
    private static let size = NSSize(width: 18, height: 18)
    private static let images = (0...3).map(makeImage)

    static func image(activeArc: Int) -> NSImage {
        images[min(max(activeArc, 0), 3)]
    }

    private static func makeImage(activeArc: Int) -> NSImage {
        let image = NSImage(size: size)
        image.lockFocus()
        defer { image.unlockFocus() }

        drawArch(left: 1.5, top: 16.5, right: 16.5, bottom: 2.5, opacity: opacity(for: 3, activeArc: activeArc))
        drawArch(left: 4.0, top: 14.0, right: 14.0, bottom: 3.5, opacity: opacity(for: 2, activeArc: activeArc))
        drawArch(left: 6.5, top: 11.5, right: 11.5, bottom: 4.5, opacity: opacity(for: 1, activeArc: activeArc))

        let rails = NSBezierPath()
        rails.move(to: NSPoint(x: 6.5, y: 1.5))
        rails.line(to: NSPoint(x: 9, y: 4.5))
        rails.line(to: NSPoint(x: 11.5, y: 1.5))
        rails.lineWidth = 1.6
        rails.lineCapStyle = .round
        rails.lineJoinStyle = .round
        NSColor.black.setStroke()
        rails.stroke()

        image.isTemplate = true
        return image
    }

    private static func drawArch(
        left: CGFloat,
        top: CGFloat,
        right: CGFloat,
        bottom: CGFloat,
        opacity: CGFloat
    ) {
        let path = NSBezierPath()
        path.move(to: NSPoint(x: left, y: bottom))
        path.curve(
            to: NSPoint(x: right, y: bottom),
            controlPoint1: NSPoint(x: left, y: top),
            controlPoint2: NSPoint(x: right, y: top)
        )
        path.lineWidth = 1.6
        path.lineCapStyle = .round
        path.lineJoinStyle = .round
        NSColor.black.withAlphaComponent(opacity).setStroke()
        path.stroke()
    }

    private static func opacity(for arc: Int, activeArc: Int) -> CGFloat {
        guard activeArc != 0 else { return 1 }
        return activeArc == arc ? 1 : 0.42
    }
}
