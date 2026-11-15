// SPDX-License-Identifier: AGPL-3.0-only
import Foundation

// A single background job, independent of observable foreground UI state.
@MainActor final class BackgroundWork {
    private var task: Task<Void, Never>?
    func run(_ work: @escaping @MainActor () async -> Void) async {
        guard task == nil else { return }
        let running = Task { await work() }
        task = running
        await withTaskCancellationHandler(operation: { await running.value }, onCancel: { running.cancel() })
        task = nil
    }
    func cancel() { task?.cancel() }
    func cancelAndWait() async {
        let running = task
        running?.cancel()
        await running?.value
    }
}
