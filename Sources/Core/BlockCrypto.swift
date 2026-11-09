import CryptoKit
import Foundation

/// Opening a `blocks.payload` envelope and splitting the plaintext into the
/// parts the app hoists into `plain_blocks` (SPEC § 6.4). The plaintext is
/// treated as opaque JSON; no block type is interpreted.
enum BlockCrypto {

    enum Error: Swift.Error, CustomStringConvertible {
        case plaintextNotJSON
        case missingPayload
        var description: String {
            switch self {
            case .plaintextNotJSON: "decrypted block is not a JSON object"
            case .missingPayload: "decrypted block has no \"payload\" object with an integer \"type\""
            }
        }
    }

    static func open(payload envelopeJSON: String, with key: SymmetricKey) throws -> DecryptedBlock {
        let plaintext = try Envelope(json: envelopeJSON).open(with: key)
        return try DecryptedBlock(plaintext: plaintext)
    }
}

/// A decrypted block: the whole object plus the hoisted parts.
struct DecryptedBlock {
    /// The decrypted JSON object, as `JSONSerialization` parsed it.
    let object: [String: Any]
    /// `payload.type`, the integer block-type tag.
    let type: Int
    /// `payload.value`, the type-specific content (`plain_blocks.payload`).
    let value: Any
    /// `parentBlockId.value` (`plain_blocks.parent_block_id`).
    let parentBlockId: String?
    /// `parentBlockId.updatedAt` (`plain_blocks.parent_updated_at`).
    let parentUpdatedAt: Int64?
    /// `uiGroup.value`, an integer raw value (`plain_blocks.ui_group`).
    let uiGroup: Int?
    /// `uiGroup.updatedAt` (`plain_blocks.ui_group_updated_at`).
    let uiGroupUpdatedAt: Int64?
    /// `audienceLedger`, if present (`plain_blocks.audience_ledger`).
    let audienceLedger: Any?

    init(plaintext: Data) throws {
        guard let object = try? JSONSerialization.jsonObject(with: plaintext) as? [String: Any] else {
            throw BlockCrypto.Error.plaintextNotJSON
        }
        guard let payload = object["payload"] as? [String: Any],
              let type = (payload["type"] as? NSNumber)?.intValue
        else { throw BlockCrypto.Error.missingPayload }
        self.object = object
        self.type = type
        self.value = payload["value"] ?? [String: Any]()
        let parent = object["parentBlockId"] as? [String: Any]
        self.parentBlockId = parent?["value"] as? String
        self.parentUpdatedAt = (parent?["updatedAt"] as? NSNumber)?.int64Value
        let group = object["uiGroup"] as? [String: Any]
        self.uiGroup = (group?["value"] as? NSNumber)?.intValue
        self.uiGroupUpdatedAt = (group?["updatedAt"] as? NSNumber)?.int64Value
        self.audienceLedger = object["audienceLedger"]
    }
}

/// Semantic JSON comparison (SPEC § 6.4): parsed values, never bytes.
/// `JSONSerialization` yields Foundation objects whose `isEqual` ignores
/// key order and compares numbers by value.
enum JSON {
    static func parse(_ data: Data) throws -> Any {
        try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
    }

    static func parse(_ text: String) throws -> Any {
        try parse(Data(text.utf8))
    }

    static func equal(_ a: Any?, _ b: Any?) -> Bool {
        switch (a, b) {
        case (nil, nil): return true
        case (let x?, let y?): return (x as AnyObject).isEqual(y)
        default: return false
        }
    }
}
