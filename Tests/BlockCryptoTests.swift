import CryptoKit
import XCTest

final class BlockCryptoTests: XCTestCase {
    let blocks = Vectors.object("blocks")

    func testPersonalAndSharedRowsOpenToTheAppsPlaintext() throws {
        let expected = try JSON.parse(try Vectors.json(blocks, "expectedPlaintext"))
        for name in ["personal", "shared"] {
            let row = Vectors.object("blocks", name)
            let block = try BlockCrypto.open(payload: Vectors.string(row, "payload"), with: Vectors.key(row, "key"))
            XCTAssertTrue(JSON.equal(block.object, expected), name)
        }
    }

    func testHoistedPartsMatchTheMirrorRow() throws {
        let row = Vectors.object("blocks", "personal")
        let block = try BlockCrypto.open(payload: Vectors.string(row, "payload"), with: Vectors.key(row, "key"))
        let mirror = Vectors.object("blocks", "expectedMirror")
        XCTAssertTrue(JSON.equal(block.value, mirror["payload"]))
        XCTAssertEqual(block.type, Vectors.int(mirror, "block_type"))
        XCTAssertEqual(block.parentBlockId, Vectors.string(mirror, "parent_block_id"))
        XCTAssertEqual(block.uiGroup, Vectors.int(mirror, "ui_group"))
        XCTAssertNil(block.audienceLedger)
    }

    func testAttachmentRowCarriesItsFileDEK() throws {
        let row = Vectors.object("blocks", "attachment")
        let block = try BlockCrypto.open(payload: Vectors.string(row, "payload"), with: Vectors.key(row, "key"))
        let ref = (block.value as? [String: Any])?["attachmentRef"] as? [String: Any]
        XCTAssertEqual(ref?["fileDEK"] as? String, Vectors.string(row, "expectedFileDEK"))
        XCTAssertNoThrow(try FileBlob.dek(from: try XCTUnwrap(ref?["fileDEK"] as? String)))
    }

    func testWrongKeyFails() throws {
        let row = Vectors.object("blocks", "personal")
        let shared = Vectors.object("blocks", "shared")
        XCTAssertThrowsError(try BlockCrypto.open(payload: Vectors.string(row, "payload"), with: Vectors.key(shared, "key"))) {
            XCTAssertEqual($0 as? Envelope.Error, .authenticationFailed)
        }
    }

    func testPlaintextShapeIsChecked() throws {
        XCTAssertThrowsError(try DecryptedBlock(plaintext: Data("[1]".utf8)))
        XCTAssertThrowsError(try DecryptedBlock(plaintext: Data("{\"payload\":{}}".utf8)))
        let minimal = try DecryptedBlock(plaintext: Data("{\"payload\":{\"type\":3,\"value\":{\"a\":1}}}".utf8))
        XCTAssertEqual(minimal.type, 3)
        XCTAssertNil(minimal.parentBlockId)
        XCTAssertTrue(JSON.equal(minimal.value, ["a": 1]))
    }

    func testJSONEqualityIgnoresKeyOrderAndNumberForm() throws {
        XCTAssertTrue(JSON.equal(try JSON.parse("{\"a\":1,\"b\":[1,2.0]}"), try JSON.parse("{\"b\":[1.0,2],\"a\":1}")))
        XCTAssertFalse(JSON.equal(try JSON.parse("{\"a\":1}"), try JSON.parse("{\"a\":2}")))
        XCTAssertFalse(JSON.equal(nil, try JSON.parse("{}")))
    }
}
