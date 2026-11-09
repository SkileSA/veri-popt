import XCTest

final class BlocksDiffTests: XCTestCase {

    // MARK: JSONDiff

    private func parse(_ text: String) -> Any { try! JSON.parse(text) }
    private func paths(_ diffs: [JSONDiff]) -> [String] { diffs.map { "\($0.kind.rawValue): \($0.path)" } }

    func testEqualValuesHaveNoDifference() {
        XCTAssertEqual(JSONDiff.diff(ciphertext: parse(#"{"a":1,"b":[1,{"c":"x"}]}"#), mirror: parse(#"{"b":[1,{"c":"x"}],"a":1}"#)), [])
        // JSONSerialization numbers compare by value: 1 and 1.0 are one number.
        XCTAssertEqual(JSONDiff.diff(ciphertext: parse("{\"a\":1}"), mirror: parse("{\"a\":1.0}")), [])
        XCTAssertEqual(JSONDiff.diff(ciphertext: nil, mirror: nil), [])
    }

    func testKeySetDifferencesAreLocated() {
        let d = JSONDiff.diff(ciphertext: parse(#"{"text":"x","alert":{"on":true},"n":{"deep":{"gone":1}}}"#),
                              mirror: parse(#"{"text":"x","alerts":[],"n":{"deep":{}}}"#))
        XCTAssertEqual(paths(d), [
            "only in the ciphertext: alert",
            "only in the mirror: alerts",
            "only in the ciphertext: n.deep.gone",
        ])
        XCTAssertFalse(d.contains { $0.kind == .differentValue })
    }

    func testValueDifferencesAreLocated() {
        let d = JSONDiff.diff(ciphertext: parse(#"{"text":"x","items":[{"q":1},{"q":2}],"flag":null}"#),
                              mirror: parse(#"{"text":"y","items":[{"q":1},{"q":3}]}"#))
        XCTAssertEqual(paths(d), [
            "only in the ciphertext: flag",   // null is a present value
            "differs: items[1].q",
            "differs: text",
        ])
        let q = d.first { $0.path == "items[1].q" }!
        XCTAssertEqual(q.ciphertext as? Int, 2)
        XCTAssertEqual(q.mirror as? Int, 3)
    }

    func testArraysOfDifferentLengthDifferWhole() {
        let d = JSONDiff.diff(ciphertext: parse("[1,2,3]"), mirror: parse("[1,2]"))
        XCTAssertEqual(paths(d), ["differs: "])
        XCTAssertEqual(JSONDiff.render(d[0].ciphertext), "[1,2,3]")
    }

    func testTypeNamesHideContent() {
        XCTAssertEqual(JSONDiff.typeName("secret"), "string")
        XCTAssertEqual(JSONDiff.typeName(parse("{\"a\":1}")), "object")
        XCTAssertEqual(JSONDiff.typeName(parse("[1]")), "array")
        XCTAssertEqual(JSONDiff.typeName(parse("true")), "boolean")
        XCTAssertEqual(JSONDiff.typeName(parse("2")), "number")
        XCTAssertEqual(JSONDiff.typeName(NSNull()), "null")
        XCTAssertEqual(JSONDiff.typeName(nil), "absent")
        XCTAssertEqual(JSONDiff.render(parse(#"{"b":1,"a":"x"}"#)), #"{"a":"x","b":1}"#)
    }

    // MARK: Report

    /// Alice's fixture plus the block cases and two rows of this test's own:
    /// `case-legacy`, whose mirror lacks a key the ciphertext carries, and
    /// `case-added`, whose mirror carries a key the ciphertext lacks.
    private func fixture() throws -> TestDatabase {
        let test = try SessionTests.fixture()
        try test.seedMoreAudiences()
        try test.seedBlockCases()
        let alice = Vectors.object("vaults", "alice", "expected")
        let personal = Derivation.subkeys(masterDEK: Vectors.key(alice, "masterDEK")).personalBlocksKey
        let legacy = Data(#"{"payload":{"type":3,"value":{"text":"x","alert":{"on":true}}}}"#.utf8)
        try test.insertMirroredBlock(id: "case-legacy", owner: "alice-uid", audience: nil,
                                     payload: try Envelope(sealing: legacy, with: personal).json(), key: personal)
        test.exec("UPDATE plain_blocks SET payload = '{\"text\":\"x\"}' WHERE id = 'case-legacy';")
        let plain = Data(#"{"payload":{"type":3,"value":{"text":"x"}}}"#.utf8)
        try test.insertMirroredBlock(id: "case-added", owner: "alice-uid", audience: nil,
                                     payload: try Envelope(sealing: plain, with: personal).json(), key: personal)
        test.exec("UPDATE plain_blocks SET payload = '{\"text\":\"x\",\"alerts\":[]}' WHERE id = 'case-added';")
        test.close()
        return test
    }

    private func diffReport(_ name: String = "alice", id: String? = nil, reveal: Bool = false) throws -> Report {
        let test = try fixture()
        return try BlocksDiffReport.run(session: try SessionTests.session(name, db: try Database(path: test.path)), id: id, reveal: reveal)
    }

    private func section(_ r: Report, _ title: String) -> Report.Section? { r.sections.first { $0.title == title } }
    private func messages(_ r: Report, _ level: Report.Level) -> String {
        r.findings.filter { $0.level == level }.map(\.message).joined(separator: "\n")
    }

    func testEveryDifferingRowIsShownAndClassified() throws {
        let r = try diffReport()
        // The tampered case cannot open; blocks-diff defers to `blocks` for it.
        XCTAssertTrue(messages(r, .fail).contains("case-tampered: does not open"), r.text())
        XCTAssertEqual(section(r, "Summary")?.lines.first, "rows considered: 13; compared with the mirror: 9; differing: 3", r.text())
        XCTAssertTrue(messages(r, .note).contains("2 row(s) differ only in which keys are present"), r.text())
        XCTAssertTrue(messages(r, .warning).contains("1 row(s) carry a key whose value differs"), r.text())

        let edited = try XCTUnwrap(section(r, "Row case-edited"))
        XCTAssertEqual(edited.lines, ["personal; type 3; revision 1", "differs: text  (string vs string)"], r.text())
        XCTAssertEqual(edited.findings.map(\.level), [.warning])

        let legacy = try XCTUnwrap(section(r, "Row case-legacy"))
        XCTAssertEqual(legacy.lines.last, "only in the ciphertext: alert  (object vs absent)")
        XCTAssertEqual(legacy.findings.map(\.level), [.note])

        let added = try XCTUnwrap(section(r, "Row case-added"))
        XCTAssertEqual(added.lines.last, "only in the mirror: alerts  (absent vs array)")
        XCTAssertEqual(added.findings.map(\.level), [.note])

        // Content stays out of the report unless revealed.
        XCTAssertFalse(r.text().contains("\"edited\""), r.text())
        XCTAssertTrue(r.text().contains("add --reveal"))
    }

    func testRevealPrintsBothValues() throws {
        let r = try diffReport(id: "case-edited", reveal: true)
        let row = try XCTUnwrap(section(r, "Row case-edited"))
        XCTAssertEqual(row.lines.last, "differs: text  ciphertext = \"x\"  mirror = \"edited\"")
        XCTAssertFalse(r.text().contains("add --reveal"))
    }

    func testOneIdentityIsReportedAsSuch() throws {
        let r = try diffReport(id: "block-personal")
        XCTAssertTrue(messages(r, .ok).contains("decrypts to exactly what the mirror holds"), r.text())
        XCTAssertEqual(r.sections.count, 1)
    }

    func testOneRowNotYetMirrored() throws {
        let r = try diffReport(id: "case-stale")
        XCTAssertTrue(messages(r, .note).contains("has no mirror at its revision"), r.text())
    }

    func testUnopenableRowsDeferToBlocks() throws {
        let r = try diffReport(id: "case-tampered")
        XCTAssertTrue(r.hasFailures)
        XCTAssertTrue(messages(r, .fail).contains("case-tampered: does not open"), r.text())
    }

    func testUnknownAndForeignIdsRefuse() throws {
        XCTAssertThrowsError(try diffReport(id: "no-such-row")) { XCTAssertEqual("\($0)", "no blocks row with id no-such-row") }
        XCTAssertThrowsError(try diffReport("bob", id: "block-personal")) { XCTAssertTrue("\($0)".contains("another account"), "\($0)") }
    }
}
