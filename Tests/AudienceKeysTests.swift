import CryptoKit
import XCTest

final class AudienceKeysTests: XCTestCase {
    let rows = Vectors.object("keysRows")

    func testRowKindIsReadFromThePeerSibling() {
        XCTAssertEqual(AudienceKeys.kind(of: Vectors.string(Vectors.object("keysRows", "ownerRow"), "wrapped_dek")), .owner)
        let peer = Vectors.object("keysRows", "peerRow")
        XCTAssertEqual(AudienceKeys.kind(of: Vectors.string(peer, "wrapped_dek")), .peer(ownerId: Vectors.string(peer, "ownerId")))
    }

    func testOwnerRowOpensUnderOwnerWrapKey() throws {
        let owner = Vectors.object("keysRows", "ownerRow")
        let dek = try AudienceKeys.unwrapOwner(Vectors.string(owner, "wrapped_dek"), ownerWrapKey: Vectors.key(owner, "ownerWrapKey"))
        XCTAssertEqual(dek.bytes.hex, Vectors.string(rows, "dek"))
    }

    func testPeerRowOpensThroughECDH() throws {
        let peer = Vectors.object("keysRows", "peerRow")
        let recipient = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Vectors.hex(peer, "recipientPrivate"))
        let owner = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: Vectors.base64(peer, "ownerPublic"))
        let dek = try AudienceKeys.unwrapPeer(Vectors.string(peer, "wrapped_dek"), privateKey: recipient, ownerPublicKey: owner)
        XCTAssertEqual(dek.bytes.hex, Vectors.string(rows, "dek"))
        // The wrong recipient gets nothing.
        XCTAssertThrowsError(try AudienceKeys.unwrapPeer(
            Vectors.string(peer, "wrapped_dek"), privateKey: Curve25519.KeyAgreement.PrivateKey(), ownerPublicKey: owner
        )) { XCTAssertEqual($0 as? Envelope.Error, .authenticationFailed) }
    }

    func testTheMintedDEKIsTheAudienceMintKey() throws {
        // SPEC § 6.3: for an owned audience the stored DEK equals the HKDF mint.
        let tree = Derivation.subkeys(masterDEK: Vectors.key(Vectors.object("subkeys"), "masterDEK"))
        XCTAssertEqual(tree.audienceMintKey(Vectors.string(rows, "audienceId")).bytes.hex, Vectors.string(rows, "dek"))
    }

    func testWrapKeyIsCommutative() throws {
        let a = Curve25519.KeyAgreement.PrivateKey(), b = Curve25519.KeyAgreement.PrivateKey()
        XCTAssertEqual(
            try AudienceKeys.wrapKey(privateKey: a, publicKey: b.publicKey).bytes,
            try AudienceKeys.wrapKey(privateKey: b, publicKey: a.publicKey).bytes
        )
    }

    func testWrapRoundTrips() throws {
        let dek = SymmetricKey(size: .bits256)
        let ownerWrap = SymmetricKey(size: .bits256)
        XCTAssertEqual(try AudienceKeys.unwrapOwner(try AudienceKeys.wrapOwner(dek, ownerWrapKey: ownerWrap), ownerWrapKey: ownerWrap).bytes, dek.bytes)
        let owner = Curve25519.KeyAgreement.PrivateKey(), member = Curve25519.KeyAgreement.PrivateKey()
        let row = try AudienceKeys.wrapPeer(dek, ownerPrivateKey: owner, recipientPublicKey: member.publicKey, ownerId: "o")
        XCTAssertEqual(AudienceKeys.kind(of: row), .peer(ownerId: "o"))
        XCTAssertEqual(try AudienceKeys.unwrapPeer(row, privateKey: member, ownerPublicKey: owner.publicKey).bytes, dek.bytes)
    }
}
