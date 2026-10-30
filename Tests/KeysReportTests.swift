import XCTest

final class KeysReportTests: XCTestCase {

    private func report(_ name: String) throws -> Report {
        let test = try SessionTests.fixture()
        try test.seedMoreAudiences()
        test.close()
        return try KeysReport.run(session: try SessionTests.session(name, db: try Database(path: test.path)))
    }

    private func section(_ r: Report, _ audience: String) -> Report.Section {
        r.sections.first { $0.title.hasSuffix(audience) }!
    }

    private func messages(_ s: Report.Section, _ level: Report.Level) -> String {
        s.findings.filter { $0.level == level }.map(\.message).joined(separator: "\n")
    }

    func testAlicesView() throws {
        let r = try report("alice")
        let shared = Vectors.string(Vectors.object("keysRows"), "audienceId")
        XCTAssertEqual(r.sections.count, 5, r.sections.map(\.title).joined(separator: ", "))

        let own = section(r, shared)
        XCTAssertTrue(messages(own, .ok).contains("can read this audience's 1 block"))
        XCTAssertTrue(messages(own, .ok).contains("the mint rule holds"))
        XCTAssertTrue(messages(own, .ok).contains("wrapped for bob-uid opens through ECDH"))

        let bobs = section(r, "aid-bob")
        XCTAssertTrue(bobs.lines.contains { $0.contains("peer row wrapped by bob-uid") })
        XCTAssertTrue(messages(bobs, .ok).contains("can read this audience's 1 block"))

        let retired = section(r, "aid-retired")
        XCTAssertTrue(messages(retired, .note).contains("no blocks under this audience"))
        XCTAssertTrue(messages(retired, .fail).isEmpty && messages(retired, .warning).isEmpty)

        let bad = section(r, "aid-bad")
        XCTAssertTrue(messages(bad, .fail).contains("wrapped for carol-uid does not open"), bad.findings.map(\.message).joined(separator: "\n"))
        XCTAssertTrue(messages(bad, .warning).contains("dave-uid is not pinned"))
        XCTAssertTrue(r.hasFailures)

        let summary = r.sections.last!
        XCTAssertTrue(summary.lines.contains("audiences: 4 (3 owned, 1 as a member, 0 neither)"), summary.lines.joined(separator: "\n"))
        XCTAssertTrue(summary.lines.contains("readable by the account: 4 of 4"))
        XCTAssertTrue(summary.lines.contains("rows the account wrapped for members: 3, 1 re-opened with the member's published key"))
        XCTAssertTrue(summary.lines.contains { $0.hasPrefix("pinned peers: 2 (0 unfriended)") }, summary.lines.joined(separator: "\n"))
    }

    func testBobsView() throws {
        let r = try report("bob")
        let shared = Vectors.string(Vectors.object("keysRows"), "audienceId")
        XCTAssertTrue(section(r, shared).lines.contains { $0.contains("peer row wrapped by alice-uid") })
        let bobs = section(r, "aid-bob")
        XCTAssertTrue(messages(bobs, .ok).contains("the mint rule holds"))
        XCTAssertTrue(messages(bobs, .ok).contains("wrapped for alice-uid opens through ECDH"))
        XCTAssertTrue(messages(section(r, "aid-retired"), .warning).contains("cannot obtain this audience's DEK (no blocks"))
        XCTAssertTrue(messages(section(r, "aid-bad"), .fail).contains("cannot obtain this audience's DEK, yet holds 1 block"))
        XCTAssertTrue(r.sections.last!.lines.contains("audiences: 4 (1 owned, 1 as a member, 2 neither)"))
    }

    func testNeedsADatabase() throws {
        XCTAssertThrowsError(try KeysReport.run(session: try SessionTests.session("alice")))
    }
}
