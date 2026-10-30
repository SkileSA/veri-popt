import CryptoKit
import Foundation

/// The JSON ciphertext envelope (SPEC § 2.1): three base64 fields,
/// `ciphertext`, `nonce`, `tag`, AES-256-GCM, no additional data.
///
/// Parsing is as lenient as the app's: any key order, unknown sibling
/// fields ignored. The one sibling the app defines is `peer`, present on
/// peer-wrapped audience keys; `peer(in:)` reads it without parsing the
/// rest. Writing sorts keys, as the app does, so output is byte-stable.
struct Envelope: Equatable, Sendable {
    let nonce: Data
    let ciphertext: Data
    let tag: Data

    enum Error: Swift.Error, CustomStringConvertible, Equatable {
        case notJSON
        case missingField(String)
        case invalidBase64(String)
        /// The bytes do not form a valid AES-GCM input (nonce or tag of the
        /// wrong length). Distinct from `authenticationFailed` so a report
        /// can tell structural damage from a wrong key. The app makes no such
        /// distinction; this is the tool's own reporting.
        case malformed(String)
        /// The tag check failed: wrong key, or damage inside a well-formed
        /// envelope. Nothing distinguishes the two (SPEC § 5.1).
        case authenticationFailed

        var description: String {
            switch self {
            case .notJSON: "envelope is not a JSON object of strings"
            case .missingField(let f): "envelope is missing the \"\(f)\" field"
            case .invalidBase64(let f): "envelope field \"\(f)\" is not valid base64"
            case .malformed(let why): "envelope is malformed: \(why)"
            case .authenticationFailed: "authentication failed (wrong key, or the envelope was modified)"
            }
        }
    }

    init(nonce: Data, ciphertext: Data, tag: Data) {
        self.nonce = nonce
        self.ciphertext = ciphertext
        self.tag = tag
    }

    // MARK: - JSON

    /// Parses the stored form. Accepts the fields in any order and ignores
    /// unknown siblings.
    init(json: String) throws {
        guard let data = json.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { throw Error.notJSON }
        func field(_ name: String) throws -> Data {
            guard let raw = object[name] else { throw Error.missingField(name) }
            guard let string = raw as? String, let bytes = Data(base64Encoded: string) else {
                throw Error.invalidBase64(name)
            }
            return bytes
        }
        self.init(nonce: try field("nonce"), ciphertext: try field("ciphertext"), tag: try field("tag"))
    }

    /// The stored form: sorted keys, no whitespace. `extra` adds sibling
    /// fields (the app uses `peer`); they must not collide with the three
    /// envelope fields.
    func json(extra: [String: String] = [:]) throws -> String {
        var object: [String: String] = [
            "nonce": nonce.base64EncodedString(),
            "ciphertext": ciphertext.base64EncodedString(),
            "tag": tag.base64EncodedString(),
        ]
        for (key, value) in extra {
            precondition(object[key] == nil, "extra field collides with an envelope field: \(key)")
            object[key] = value
        }
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        return String(decoding: data, as: UTF8.self)
    }

    /// The `peer` sibling of a stored envelope, if present. `nil` for an
    /// owner-wrapped audience key and for anything that is not an envelope.
    static func peer(in json: String) -> String? {
        guard let data = json.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return nil }
        return object["peer"] as? String
    }

    // MARK: - AES-GCM

    /// Seals `plaintext` under `key` with a fresh random nonce.
    init(sealing plaintext: Data, with key: SymmetricKey) throws {
        let box = try AES.GCM.seal(plaintext, using: key)
        self.init(nonce: box.nonce.withUnsafeBytes { Data($0) }, ciphertext: box.ciphertext, tag: box.tag)
    }

    /// Opens the envelope under `key`.
    func open(with key: SymmetricKey) throws -> Data {
        let gcmNonce: AES.GCM.Nonce
        do {
            gcmNonce = try AES.GCM.Nonce(data: nonce)
        } catch {
            throw Error.malformed("nonce is \(nonce.count) bytes, expected 12")
        }
        let box: AES.GCM.SealedBox
        do {
            box = try AES.GCM.SealedBox(nonce: gcmNonce, ciphertext: ciphertext, tag: tag)
        } catch {
            throw Error.malformed("tag is \(tag.count) bytes, expected 16")
        }
        do {
            return try AES.GCM.open(box, using: key)
        } catch CryptoKitError.authenticationFailure {
            throw Error.authenticationFailed
        } catch {
            throw Error.malformed("\(error)")
        }
    }
}
