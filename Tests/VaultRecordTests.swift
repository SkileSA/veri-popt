import XCTest

final class VaultRecordTests: XCTestCase {
    var aliceJSON: Data { try! Vectors.json(Vectors.object("vaults", "alice"), "record") }

    func testDecodesTheServiceShape() throws {
        let record = try VaultRecord(json: aliceJSON)
        XCTAssertEqual(record.id, "alice-uid")
        XCTAssertEqual(record.kdfSalt.count, 16)
        XCTAssertEqual(record.signingPublicKey.count, 32)
        XCTAssertNotNil(record.createdAt)
    }

    func testTimestampsAreOptional() throws {
        var object = try JSONSerialization.jsonObject(with: aliceJSON) as! [String: Any]
        object.removeValue(forKey: "createdAt")
        object["updatedAt"] = NSNull()
        let record = try VaultRecord(json: try JSONSerialization.data(withJSONObject: object))
        XCTAssertNil(record.createdAt)
        XCTAssertNil(record.updatedAt)
    }

    func testUnknownKeysAreRefusedByName() throws {
        var object = try JSONSerialization.jsonObject(with: aliceJSON) as! [String: Any]
        object["recoveryCode"] = "ABCD-EFGH-JKMN-PQRS"
        object["masterDek"] = "00"
        XCTAssertThrowsError(try VaultRecord(json: try JSONSerialization.data(withJSONObject: object))) { error in
            XCTAssertEqual(error as? VaultRecord.Error, .unexpectedKeys(["masterDek", "recoveryCode"]))
        }
    }

    func testMissingAndMalformedFields() throws {
        var object = try JSONSerialization.jsonObject(with: aliceJSON) as! [String: Any]
        object.removeValue(forKey: "masterDekWrapped")
        XCTAssertThrowsError(try VaultRecord(json: try JSONSerialization.data(withJSONObject: object))) { error in
            XCTAssertEqual(error as? VaultRecord.Error, .missingField("masterDekWrapped"))
        }
        object = try JSONSerialization.jsonObject(with: aliceJSON) as! [String: Any]
        object["kdfSalt"] = Data(repeating: 1, count: 15).base64EncodedString()
        XCTAssertThrowsError(try VaultRecord(json: try JSONSerialization.data(withJSONObject: object))) { error in
            XCTAssertEqual(error as? VaultRecord.Error, .wrongLength(field: "kdfSalt", expected: 16, actual: 15))
        }
        XCTAssertThrowsError(try VaultRecord(json: Data("[]".utf8))) { error in
            XCTAssertEqual(error as? VaultRecord.Error, .notJSON)
        }
    }
}
