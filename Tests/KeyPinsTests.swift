import CryptoKit
import XCTest

final class KeyPinsTests: XCTestCase {

    func testBlockIdDerivation() {
        // Checked against the app on a real account: the block sits at this id.
        let id = KeyPins.blockId(ownerId: "bt77Cb6L97eh6kxebaDVmI9hqw92")
        XCTAssertEqual(id, "df44ad25d49467dc198e04c2d4147fee")
        XCTAssertEqual(KeyPins.blockId(ownerId: "alice-uid").count, 32)
    }

    func testPayloadParsing() throws {
        let key = Curve25519.KeyAgreement.PrivateKey().publicKey
        let json = """
        {"payload":{"type":14,"value":{"type":"key_pins","scope":"user","entries":{
          "a":{"value":{"x25519":"\(key.rawRepresentation.base64EncodedString())"},"updatedAt":5},
          "b":{"value":{"x25519":"\(key.rawRepresentation.base64EncodedString())","unfriended":true},"updatedAt":6},
          "c":{"value":{"x25519":"not a key"},"updatedAt":7},
          "d":{"value":{"future":"shape"}}}}}}
        """
        let pins = try KeyPins(decrypted: try DecryptedBlock(plaintext: Data(json.utf8)))
        XCTAssertEqual(pins.publicKey(for: "a")?.rawRepresentation, key.rawRepresentation)
        XCTAssertEqual(pins.entries["b"]?.unfriended, true)
        XCTAssertEqual(pins.pinnedIds, ["a", "b"])
        XCTAssertEqual(pins.unreadableIds, ["c", "d"])
        XCTAssertNil(pins.publicKey(for: "zzz"))

        XCTAssertThrowsError(try KeyPins(decrypted: try DecryptedBlock(plaintext: Data("{\"payload\":{\"type\":3,\"value\":{}}}".utf8)))) {
            XCTAssertEqual($0 as? KeyPins.Error, .notADictionary(typeTag: 3))
        }
        XCTAssertThrowsError(try KeyPins(decrypted: try DecryptedBlock(plaintext: Data("{\"payload\":{\"type\":14,\"value\":{\"type\":\"dashboard\",\"scope\":\"home\"}}}".utf8)))) {
            XCTAssertEqual($0 as? KeyPins.Error, .wrongTenant(type: "dashboard", scope: "home"))
        }
    }

    /// Fixtures delete their file in deinit; keep them alive for the test.
    private var kept: [TestDatabase] = []

    private func fixture(_ build: (TestDatabase) throws -> Void) throws -> Database {
        let test = try SessionTests.fixture()
        try build(test)
        test.close()
        kept.append(test)
        return try Database(path: test.path)
    }

    func testPeerRowOpensThroughThePinEvenWhenTheServerSwapsTheProfile() throws {
        let aid = Vectors.string(Vectors.object("keysRows"), "audienceId")
        let stranger = Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation.base64EncodedString()
        let db = try fixture { $0.exec("UPDATE user_profiles SET public_key = '\(stranger)' WHERE id = 'alice-uid';") }
        // Bob reads Alice's row through his pinned key for her, not the swapped profile.
        let bob = try SessionTests.session("bob", db: db)
        XCTAssertEqual(try bob.audienceKey(aid).resolution, .peerRow(ownerId: "alice-uid"))
        XCTAssertEqual(try bob.audienceKey(aid).key?.bytes.hex, Vectors.string(Vectors.object("keysRows"), "dek"))
        // And derive, on Alice's side, flags that the server publishes a different key for her? No:
        // her own profile check is the "Published key" section; on Bob's side the divergence is for alice-uid.
        var report = Report(title: "t")
        try KeyEvidence.run(session: bob, into: &report)
        let fails = report.findings.filter { $0.level == .fail }.map(\.message).joined(separator: "\n")
        XCTAssertTrue(fails.contains("the server publishes a different key for alice-uid"), report.text())
    }

    func testUnpinnedPeerIsRefusedWithTheFallbackNamed() throws {
        let aid = Vectors.string(Vectors.object("keysRows"), "audienceId")
        let bobMaster = Vectors.key(Vectors.object("vaults", "bob", "expected"), "masterDEK")
        let bobPublic = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: Vectors.base64(Vectors.object("vaults", "bob", "expected"), "curvePublic"))
        let db = try fixture { try $0.writeKeyPins(owner: "bob-uid", masterDEK: bobMaster, entries: ["bob-uid": bobPublic]) }
        let bob = try SessionTests.session("bob", db: db)
        guard case .unavailable(let why) = try bob.audienceKey(aid).resolution else { return XCTFail("expected refusal") }
        XCTAssertTrue(why.contains("alice-uid, who is not pinned; refused as the app refuses"), why)
        XCTAssertTrue(why.contains("the key published in user_profiles would open it"), why)
    }

    func testSelfEntryMismatchAndMissingBlock() throws {
        let aliceMaster = Vectors.key(Vectors.object("vaults", "alice", "expected"), "masterDEK")
        let wrongSelf = Curve25519.KeyAgreement.PrivateKey().publicKey
        let mismatch = try fixture { try $0.writeKeyPins(owner: "alice-uid", masterDEK: aliceMaster, entries: ["alice-uid": wrongSelf]) }
        var report = Report(title: "t")
        try KeyEvidence.run(session: try SessionTests.session("alice", db: mismatch), into: &report)
        XCTAssertTrue(report.findings.contains { $0.level == .fail && $0.message.contains("self entry holds a different key") }, report.text())

        let missing = try fixture { $0.exec("DELETE FROM blocks WHERE id = '\(KeyPins.blockId(ownerId: "alice-uid"))';") }
        var report2 = Report(title: "t")
        try KeyEvidence.run(session: try SessionTests.session("alice", db: missing), into: &report2)
        XCTAssertTrue(report2.findings.contains { $0.level == .warning && $0.message.contains("no key pins block") }, report2.text())
    }
}
