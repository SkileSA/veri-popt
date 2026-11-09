import CryptoKit
import Foundation

/// Audience key rows (SPEC § 6.3): how a `keys.wrapped_dek` is opened.
enum AudienceKeys {

    enum Constants {
        static let ecdhSalt = "popt-it-dek-share"
        static let ecdhInfo = "dek-wrap"
    }

    /// How a row was wrapped, read from the envelope's `peer` sibling.
    enum RowKind: Equatable, Sendable {
        /// The owner's own row: symmetric wrap under `ownerWrapKey`.
        case owner
        /// A member's row: ECDH between the owner and that member.
        case peer(ownerId: String)
    }

    static func kind(of wrappedDek: String) -> RowKind {
        if let owner = Envelope.peer(in: wrappedDek) { return .peer(ownerId: owner) }
        return .owner
    }

    // MARK: - ECDH

    /// The symmetric key both sides derive from X25519 agreement. Commutative:
    /// `(myPriv, theirPub)` and `(theirPriv, myPub)` give the same key.
    static func wrapKey(
        privateKey: Curve25519.KeyAgreement.PrivateKey,
        publicKey: Curve25519.KeyAgreement.PublicKey
    ) throws -> SymmetricKey {
        let shared = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        return shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(Constants.ecdhSalt.utf8),
            sharedInfo: Data(Constants.ecdhInfo.utf8),
            outputByteCount: Derivation.Constants.keyLength
        )
    }

    // MARK: - Unwrap

    enum Error: Swift.Error, CustomStringConvertible {
        case dekLength(Int)
        var description: String {
            switch self {
            case .dekLength(let n): "wrapped_dek opened to \(n) bytes, expected 32"
            }
        }
    }

    static func unwrapOwner(_ wrappedDek: String, ownerWrapKey: SymmetricKey) throws -> SymmetricKey {
        try dek(from: try Envelope(json: wrappedDek).open(with: ownerWrapKey))
    }

    static func unwrapPeer(
        _ wrappedDek: String,
        privateKey: Curve25519.KeyAgreement.PrivateKey,
        ownerPublicKey: Curve25519.KeyAgreement.PublicKey
    ) throws -> SymmetricKey {
        let key = try wrapKey(privateKey: privateKey, publicKey: ownerPublicKey)
        return try dek(from: try Envelope(json: wrappedDek).open(with: key))
    }

    // MARK: - Wrap (for tests and negative controls)

    static func wrapOwner(_ dek: SymmetricKey, ownerWrapKey: SymmetricKey) throws -> String {
        try Envelope(sealing: dek.bytes, with: ownerWrapKey).json()
    }

    static func wrapPeer(
        _ dek: SymmetricKey,
        ownerPrivateKey: Curve25519.KeyAgreement.PrivateKey,
        recipientPublicKey: Curve25519.KeyAgreement.PublicKey,
        ownerId: String
    ) throws -> String {
        let key = try wrapKey(privateKey: ownerPrivateKey, publicKey: recipientPublicKey)
        return try Envelope(sealing: dek.bytes, with: key).json(extra: ["peer": ownerId])
    }

    private static func dek(from bytes: Data) throws -> SymmetricKey {
        guard bytes.count == Derivation.Constants.keyLength else { throw Error.dekLength(bytes.count) }
        return SymmetricKey(data: bytes)
    }
}
