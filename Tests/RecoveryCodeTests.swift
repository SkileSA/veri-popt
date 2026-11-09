import XCTest

final class RecoveryCodeTests: XCTestCase {
    let canonical = Vectors.string(Vectors.object("recoveryCode"), "canonical")

    func testEveryInputFormCanonicalizes() throws {
        for typed in [canonical, canonical.lowercased(), canonical.replacingOccurrences(of: "-", with: ""),
                      "  " + canonical.replacingOccurrences(of: "-", with: " ") + "\n"] {
            XCTAssertEqual(try RecoveryCode(parsing: typed).formatted, canonical, "input: \(typed.debugDescription)")
        }
    }

    func testKeyMaterialIsTheHyphenatedString() {
        // SPEC § 3: the app derives from the 19-character formatted string.
        let expected = Vectors.string(Vectors.object("recoveryCode"), "keyMaterialHex")
        XCTAssertEqual(try RecoveryCode(parsing: canonical).keyMaterial.hex, expected)
        XCTAssertEqual(try RecoveryCode(parsing: canonical).keyMaterial.count, 19)
    }

    func testWrongLengthIsRefused() {
        XCTAssertThrowsError(try RecoveryCode(parsing: String(canonical.dropLast()))) { error in
            XCTAssertEqual(error as? RecoveryCode.Error, .wrongLength(15))
        }
        XCTAssertThrowsError(try RecoveryCode(parsing: "")) { error in
            XCTAssertEqual(error as? RecoveryCode.Error, .wrongLength(0))
        }
    }

    func testCharactersOutsideTheAlphabetAreRefused() {
        for bad: Character in ["I", "L", "O", "U", "*"] {
            let typed = String(canonical.dropLast()) + String(bad)
            XCTAssertThrowsError(try RecoveryCode(parsing: typed)) { error in
                XCTAssertEqual(error as? RecoveryCode.Error, .invalidCharacter(bad))
            }
        }
    }
}
