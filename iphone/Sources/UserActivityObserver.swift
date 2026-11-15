// SPDX-License-Identifier: AGPL-3.0-only
import SwiftUI
import UIKit

struct UserActivityObserver: UIViewRepresentable {
    var onActivity: () -> Void

    func makeUIView(context: Context) -> ActivityObserverView {
        let view = ActivityObserverView(frame: .zero)
        view.isUserInteractionEnabled = false
        view.onActivity = onActivity
        return view
    }

    func updateUIView(_ view: ActivityObserverView, context: Context) {
        view.onActivity = onActivity
    }

    static func dismantleUIView(_ view: ActivityObserverView, coordinator: ()) {
        view.detach()
    }
}

final class ActivityObserverView: UIView, UIGestureRecognizerDelegate {
    var onActivity: () -> Void = {}
    private weak var observedWindow: UIWindow?
    private lazy var observer: UITapGestureRecognizer = {
        let recognizer = UITapGestureRecognizer(target: nil, action: nil)
        recognizer.delegate = self
        recognizer.cancelsTouchesInView = false
        recognizer.delaysTouchesBegan = false
        recognizer.delaysTouchesEnded = false
        return recognizer
    }()

    override func didMoveToWindow() {
        super.didMoveToWindow()
        detach()
        guard let window else { return }
        observedWindow = window
        window.addGestureRecognizer(observer)
    }

    func detach() {
        observedWindow?.removeGestureRecognizer(observer)
        observedWindow = nil
    }

    func gestureRecognizer(_ gestureRecognizer: UIGestureRecognizer, shouldReceive touch: UITouch) -> Bool {
        onActivity()
        // Observe activity without entering recognition or cancelling a control's tap.
        return false
    }
}
