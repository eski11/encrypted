import XCTest
@testable import ENCPTD

@MainActor final class BackgroundWorkTests: XCTestCase {
    func testUserActionCancelsAndDrainsPollingBeforeEditingVault() async {
        let worker = BackgroundWork()
        let started = expectation(description: "Background request started")
        var events: [String] = []
        let poll = Task {
            await worker.run {
                started.fulfill()
                do {
                    try await Task.sleep(nanoseconds: 60_000_000_000)
                    events.append("stale network result")
                } catch { events.append("poll cancelled") }
            }
        }
        await fulfillment(of: [started], timeout: 2)
        await worker.cancelAndWait()
        events.append("save settings")
        await poll.value
        XCTAssertEqual(events, ["poll cancelled", "save settings"])
        await worker.run { events.append("next poll") }
        XCTAssertEqual(events.last, "next poll")
    }

    func testOverlappingPollIsSkippedInsteadOfDuplicatingInboxWork() async {
        let worker = BackgroundWork()
        let started = expectation(description: "Polling began")
        var release: CheckedContinuation<Void, Never>?
        var count = 0
        let first = Task {
            await worker.run {
                count += 1
                await withCheckedContinuation { continuation in release = continuation; started.fulfill() }
            }
        }
        await fulfillment(of: [started], timeout: 2)
        await worker.run { count += 1 }
        XCTAssertEqual(count, 1)
        release?.resume()
        await first.value
        await worker.run { count += 1 }
        XCTAssertEqual(count, 2)
    }
}
