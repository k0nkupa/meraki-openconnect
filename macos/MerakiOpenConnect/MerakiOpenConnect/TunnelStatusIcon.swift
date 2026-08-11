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
}

struct TunnelStatusIcon: View {
    let phase: AppPhase
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        TimelineView(.periodic(from: .now, by: 0.27)) { timeline in
            TunnelMark(activeArc: activeArc(at: timeline.date))
                .frame(width: 18, height: 18)
        }
        .accessibilityHidden(true)
    }

    private func activeArc(at date: Date) -> Int {
        guard TunnelIconPresentation(phase: phase, reduceMotion: reduceMotion).shouldAnimate else {
            return 0
        }
        return Int(date.timeIntervalSinceReferenceDate / 0.27) % 3 + 1
    }
}

private struct TunnelMark: View {
    let activeArc: Int

    var body: some View {
        ZStack {
            arch(left: 1.5, top: 1.5, right: 16.5, bottom: 15.5)
                .stroke(.primary, style: strokeStyle)
                .opacity(opacity(for: 3))
            arch(left: 4.0, top: 4.0, right: 14.0, bottom: 14.5)
                .stroke(.primary, style: strokeStyle)
                .opacity(opacity(for: 2))
            arch(left: 6.5, top: 6.5, right: 11.5, bottom: 13.5)
                .stroke(.primary, style: strokeStyle)
                .opacity(opacity(for: 1))
            pathRails
                .stroke(.primary, style: strokeStyle)
        }
        .drawingGroup()
    }

    private var strokeStyle: StrokeStyle {
        StrokeStyle(lineWidth: 1.6, lineCap: .round, lineJoin: .round)
    }

    private var pathRails: Path {
        var path = Path()
        path.move(to: CGPoint(x: 6.5, y: 16.5))
        path.addLine(to: CGPoint(x: 9, y: 13.5))
        path.addLine(to: CGPoint(x: 11.5, y: 16.5))
        return path
    }

    private func arch(left: CGFloat, top: CGFloat, right: CGFloat, bottom: CGFloat) -> Path {
        let centerX = (left + right) / 2
        var path = Path()
        path.move(to: CGPoint(x: left, y: bottom))
        path.addCurve(
            to: CGPoint(x: right, y: bottom),
            control1: CGPoint(x: left, y: top),
            control2: CGPoint(x: right, y: top)
        )
        path.addLine(to: CGPoint(x: right, y: bottom - 0.5))
        path.move(to: CGPoint(x: centerX, y: bottom))
        return path
    }

    private func opacity(for arc: Int) -> Double {
        guard activeArc != 0 else { return 1 }
        return activeArc == arc ? 1 : 0.42
    }
}
