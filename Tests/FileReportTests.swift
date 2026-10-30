import CryptoKit
import XCTest

/// Serves the vectors' objects by key, with a few misbehaving keys.
struct FixtureFetcher: ObjectFetcher {
    let file = Vectors.object("file")
    var tamperMain = false

    func fetch(objectKey: String) throws -> Fetched {
        let key = Vectors.string(file, "storageKey")
        if objectKey == key {
            let bytes = Vectors.base64(file, "combined")
            return .bytes(tamperMain ? FileReport.flippedByte(bytes, at: 20) : bytes)
        }
        if objectKey == Vectors.string(file, "thumbObjectKey") { return .bytes(Vectors.base64(file, "thumbCombined")) }
        if objectKey == "alice-uid/plain" { return .bytes(Data("this is plaintext, not ciphertext at all".utf8)) }
        return .status(404)
    }
}

final class FileReportTests: XCTestCase {

    private func report(_ build: (TestDatabase) throws -> Void = { _ in }, fetcher: FixtureFetcher = FixtureFetcher(),
                        options: FileReport.Options = FileReport.Options()) throws -> Report {
        let test = try SessionTests.fixture()
        try build(test)
        test.close()
        let session = try SessionTests.session("alice", db: try Database(path: test.path))
        return try FileReport.run(session: session, fetcher: fetcher, environment: .staging, options: options)
    }

    private func messages(_ r: Report, _ level: Report.Level) -> String {
        r.findings.filter { $0.level == level }.map(\.message).joined(separator: "\n")
    }

    func testTheVectorsObjectOpensAndIsConsistent() throws {
        let r = try report()
        XCTAssertFalse(r.hasFailures, r.text())
        let oks = messages(r, .ok)
        XCTAssertTrue(oks.contains("the object opens under the row's file key"))
        XCTAssertTrue(oks.contains("one changed byte in the served object fails authentication"))
        XCTAssertTrue(oks.contains("the thumbnail (") && oks.contains("opens under the same file key"))
        XCTAssertTrue(oks.contains("every object fetched is ciphertext that opens"))
        // The vectors' bytes are a pattern, not a JPEG: the declared type does not match.
        XCTAssertTrue(messages(r, .warning).contains("does not start with the image/jpeg signature"))
        XCTAssertTrue(r.sections.last!.lines[0].hasPrefix("rows: 1; objects: 1; checked: 1; fetched: 1; opened: 1; consistent: 1; thumbnails opened: 1"))
    }

    func testNoAttachmentRows() throws {
        let r = try report { $0.exec("DELETE FROM blocks WHERE id = 'block-attachment';") }
        XCTAssertFalse(r.hasFailures)
        XCTAssertTrue(messages(r, .note).contains("no attachment rows (no block carries the attachment storage bit)"), r.text())
        XCTAssertEqual(r.sections.count, 2)
    }

    func testAliasesShareTheObjectAndTheKey() throws {
        let attachment = Vectors.object("blocks", "attachment")
        let r = try report { test in
            // A copy of the photo: same storage_key, same attachmentRef.
            try test.insertMirroredBlock(id: "block-attachment-copy", owner: "alice-uid", audience: nil,
                                         payload: Vectors.string(attachment, "payload"), key: Vectors.key(attachment, "key"),
                                         storageKey: Vectors.string(attachment, "storageKey"), storage: BlocksReport.attachmentStorageBit)
        }
        XCTAssertFalse(r.hasFailures, r.text())
        XCTAssertTrue(messages(r, .ok).contains("the 2 rows pointing at this object carry the same file key"))
        XCTAssertTrue(r.sections.last!.lines[0].hasPrefix("rows: 2; objects: 1; checked: 1; fetched: 1"))
    }

    func testTamperedObjectFails() throws {
        var fetcher = FixtureFetcher(); fetcher.tamperMain = true
        let r = try report(fetcher: fetcher)
        XCTAssertTrue(r.hasFailures)
        XCTAssertTrue(messages(r, .fail).contains("does not open under the row's file key"))
    }

    func testMissingAndPlaintextObjects() throws {
        let attachment = Vectors.object("blocks", "attachment")
        let r = try report { test in
            try test.insertMirroredBlock(id: "block-gone", owner: "alice-uid", audience: nil,
                                         payload: Vectors.string(attachment, "payload"), key: Vectors.key(attachment, "key"),
                                         storageKey: "alice-uid/gone", storage: BlocksReport.attachmentStorageBit)
            try test.insertMirroredBlock(id: "block-plain", owner: "alice-uid", audience: nil,
                                         payload: Vectors.string(attachment, "payload"), key: Vectors.key(attachment, "key"),
                                         storageKey: "alice-uid/plain", storage: BlocksReport.attachmentStorageBit)
        }
        XCTAssertTrue(messages(r, .warning).contains("the bucket answered HTTP 404"))
        XCTAssertTrue(messages(r, .fail).contains("the served bytes read as text"), r.text())
    }

    func testLimitAndIdAndOut() throws {
        let attachment = Vectors.object("blocks", "attachment")
        let out = FileManager.default.temporaryDirectory.appendingPathComponent("veri-popt-out-\(UUID().uuidString)").path
        defer { try? FileManager.default.removeItem(atPath: out) }
        var options = FileReport.Options(); options.limit = 1; options.outDirectory = out
        let r = try report({ test in
            try test.insertMirroredBlock(id: "block-gone", owner: "alice-uid", audience: nil,
                                         payload: Vectors.string(attachment, "payload"), key: Vectors.key(attachment, "key"),
                                         storageKey: "alice-uid/gone", storage: BlocksReport.attachmentStorageBit)
        }, options: options)
        XCTAssertTrue(r.sections[0].lines.contains { $0.contains("pointing at 2 object(s); checking 1 (--limit 1; 0 for all)") }, r.text())
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: out).sorted(), ["block-attachment-thumb.jpg", "block-attachment.jpg"])
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: out + "/block-attachment.jpg")), Vectors.base64(Vectors.object("file"), "plaintext"))

        var one = FileReport.Options(); one.id = "block-gone"
        let single = try report(options: one)
        XCTAssertTrue(messages(single, .note).contains("no attachment row with that id") || single.sections.count >= 2)
    }

    func testEnvironmentURLs() {
        XCTAssertEqual(BucketEnvironment.staging.url(for: "u/o").absoluteString, "https://storage-staging.attachments.popt.com/u/o")
        XCTAssertEqual(BucketEnvironment.production.url(for: "u/o.thumb").absoluteString, "https://storage.attachments.popt.com/u/o.thumb")
    }
}
