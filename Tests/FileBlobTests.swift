import CryptoKit
import XCTest

final class FileBlobTests: XCTestCase {
    let file = Vectors.object("file")

    func testObjectAndThumbnailOpenUnderTheRowsDEK() throws {
        let dek = try FileBlob.dek(from: Vectors.string(file, "dek"))
        let combined = Vectors.base64(file, "combined")
        let plaintext = Vectors.base64(file, "plaintext")
        XCTAssertEqual(try FileBlob.open(combined, with: dek), plaintext)
        XCTAssertEqual(combined.count, plaintext.count + FileBlob.overhead)
        XCTAssertEqual(try FileBlob.open(Vectors.base64(file, "thumbCombined"), with: dek), Vectors.base64(file, "thumbPlaintext"))
    }

    func testThumbnailObjectKey() {
        XCTAssertEqual(FileBlob.thumbObjectKey(storageKey: Vectors.string(file, "storageKey")), Vectors.string(file, "thumbObjectKey"))
    }

    func testTamperingAndWrongKeyFail() throws {
        let dek = try FileBlob.dek(from: Vectors.string(file, "dek"))
        let combined = Vectors.base64(file, "combined")
        for offset in [0, 12, combined.count / 2, combined.count - 1] {
            XCTAssertThrowsError(try FileBlob.open(flipped(combined, at: offset), with: dek)) {
                XCTAssertEqual($0 as? FileBlob.Error, .authenticationFailed, "offset \(offset)")
            }
        }
        XCTAssertThrowsError(try FileBlob.open(combined, with: SymmetricKey(size: .bits256))) {
            XCTAssertEqual($0 as? FileBlob.Error, .authenticationFailed)
        }
    }

    func testMalformedInputs() {
        XCTAssertThrowsError(try FileBlob.open(Data(repeating: 0, count: 27), with: SymmetricKey(size: .bits256))) {
            XCTAssertEqual($0 as? FileBlob.Error, .tooShort(27))
        }
        XCTAssertThrowsError(try FileBlob.dek(from: "AAAA")) { XCTAssertEqual($0 as? FileBlob.Error, .malformedDEK) }
        XCTAssertThrowsError(try FileBlob.dek(from: "not base64!")) { XCTAssertEqual($0 as? FileBlob.Error, .malformedDEK) }
    }

    func testSealRoundTrip() throws {
        let dek = SymmetricKey(size: .bits256)
        let bytes = Data((0 ..< 1000).map { UInt8($0 % 256) })
        let sealed = try FileBlob.seal(bytes, with: dek)
        XCTAssertEqual(sealed.count, bytes.count + FileBlob.overhead)
        XCTAssertEqual(try FileBlob.open(sealed, with: dek), bytes)
        XCTAssertEqual(try FileBlob.open(try FileBlob.seal(Data(), with: dek), with: dek), Data())
    }
}
