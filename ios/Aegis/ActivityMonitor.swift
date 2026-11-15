import SwiftUI
import UIKit
import UIKit.UIGestureRecognizerSubclass

/// Reports every touch in the window (including sheets) without interfering
/// with it, so the inactivity auto-lock can be reset.
struct ActivityMonitor: UIViewRepresentable {
    let onActivity: () -> Void

    func makeUIView(context: Context) -> ActivityHostView {
        let view = ActivityHostView()
        view.isUserInteractionEnabled = false
        view.backgroundColor = .clear
        view.onActivity = onActivity
        return view
    }

    func updateUIView(_ uiView: ActivityHostView, context: Context) {
        uiView.onActivity = onActivity
    }
}

final class ActivityHostView: UIView {
    var onActivity: (() -> Void)?
    private var recognizer: ActivityGestureRecognizer?

    override func didMoveToWindow() {
        super.didMoveToWindow()
        if let recognizer {
            recognizer.view?.removeGestureRecognizer(recognizer)
            self.recognizer = nil
        }
        guard let window else { return }
        let newRecognizer = ActivityGestureRecognizer(target: nil, action: nil)
        newRecognizer.cancelsTouchesInView = false
        newRecognizer.delaysTouchesBegan = false
        newRecognizer.delaysTouchesEnded = false
        newRecognizer.onTouch = { [weak self] in
            self?.onActivity?()
        }
        window.addGestureRecognizer(newRecognizer)
        recognizer = newRecognizer
    }
}

/// Fails immediately on the first touch, so it never blocks other gestures.
final class ActivityGestureRecognizer: UIGestureRecognizer {
    var onTouch: (() -> Void)?

    override func touchesBegan(_ touches: Set<UITouch>, with event: UIEvent) {
        onTouch?()
        state = .failed
    }
}
