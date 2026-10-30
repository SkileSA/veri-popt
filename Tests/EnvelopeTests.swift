import CryptoKit
import XCTest

final class EnvelopeTests: XCTestCase {
    let key = SymmetricKey(size: .bits256)

    func testRoundTripAndSortedOutput() throws {
        let sealed = try Envelope(sealing: Data("hello".utf8), with: key)
        let json = try sealed.json()
        XCTAssertTrue(json.hasPrefix("{\"ciphertext\":\""))
        XCTAssertEqual(try Envelope(json: json).open(with: key), Data("hello".utf8))
    }

    func testAnyKeyOrderAndUnknownSiblingsAreAccepted() throws {
        let sealed = try Envelope(sealing: Data("x".utf8), with: key)
        let json = """
        {"tag":"\(sealed.tag.base64EncodedString())","peer":"someone","zzz":1,\
        "nonce":"\(sealed.nonce.base64EncodedString())","ciphertext":"\(sealed.ciphertext.base64EncodedString())"}
        """
        XCTAssertEqual(try Envelope(json: json).open(with: key), Data("x".utf8))
        XCTAssertEqual(Envelope.peer(in: json), "someone")
        XCTAssertNil(Envelope.peer(in: try sealed.json()))
        XCTAssertNil(Envelope.peer(in: "not json"))
    }

    func testParseErrors() {
        XCTAssertEqual(try? Envelope(json: "[]"), nil)
        XCTAssertThrowsError(try Envelope(json: "{\"nonce\":\"AA==\",\"tag\":\"AA==\"}")) {
            XCTAssertEqual($0 as? Envelope.Error, .missingField("ciphertext"))
        }
        XCTAssertThrowsError(try Envelope(json: "{\"nonce\":\"@@\",\"tag\":\"AA==\",\"ciphertext\":\"AA==\"}")) {
            XCTAssertEqual($0 as? Envelope.Error, .invalidBase64("nonce"))
        }
    }

    func testWrongKeyAndTamperingFailAuthentication() throws {
        let sealed = try Envelope(sealing: Data("payload".utf8), with: key)
        XCTAssertThrowsError(try sealed.open(with: SymmetricKey(size: .bits256))) {
            XCTAssertEqual($0 as? Envelope.Error, .authenticationFailed)
        }
        for tampered in [
            Envelope(nonce: sealed.nonce, ciphertext: flipped(sealed.ciphertext, at: 0), tag: sealed.tag),
            Envelope(nonce: sealed.nonce, ciphertext: sealed.ciphertext, tag: flipped(sealed.tag, at: 15)),
            Envelope(nonce: flipped(sealed.nonce, at: 3), ciphertext: sealed.ciphertext, tag: sealed.tag),
        ] {
            XCTAssertThrowsError(try tampered.open(with: key)) {
                XCTAssertEqual($0 as? Envelope.Error, .authenticationFailed)
            }
        }
    }

    func testWrongLengthsAreMalformedNotAuthentication() throws {
        let sealed = try Envelope(sealing: Data("payload".utf8), with: key)
        let shortNonce = Envelope(nonce: sealed.nonce.dropLast(), ciphertext: sealed.ciphertext, tag: sealed.tag)
        XCTAssertThrowsError(try shortNonce.open(with: key)) {
            XCTAssertEqual($0 as? Envelope.Error, .malformed("nonce is 11 bytes, expected 12"))
        }
        let shortTag = Envelope(nonce: sealed.nonce, ciphertext: sealed.ciphertext, tag: sealed.tag.dropLast())
        XCTAssertThrowsError(try shortTag.open(with: key)) {
            XCTAssertEqual($0 as? Envelope.Error, .malformed("tag is 15 bytes, expected 16"))
        }
    }
}
