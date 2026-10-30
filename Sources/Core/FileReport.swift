import CryptoKit
import Foundation

/// Where the bucket is reached (SPEC § 7). Downloads are open by design:
/// a plain GET of the object key, no token. The secrecy is in the keys.
enum BucketEnvironment: String, CaseIterable {
    case production, staging

    var baseURL: URL {
        switch self {
        case .production: URL(string: "https://storage.attachments.popt.com")!
        case .staging: URL(string: "https://storage-staging.attachments.popt.com")!
        }
    }

    /// The app appends each path component of the key to the base.
    func url(for objectKey: String) -> URL {
        objectKey.split(separator: "/").reduce(baseURL) { $0.appendingPathComponent(String($1)) }
    }
}

/// What a fetch returned: the bytes, or the HTTP status that denied them.
enum Fetched {
    case bytes(Data)
    case status(Int)
}

/// The one network seam: the CLI fetches over HTTPS, the tests from the
/// vectors.
protocol ObjectFetcher {
    func fetch(objectKey: String) throws -> Fetched
}

/// `file`: the attachment objects as the bucket serves them, opened under
/// the file key carried in the owning row (SPEC § 7).
enum FileReport {
    static let maxListed = 15

    /// Leading bytes a decrypted file must start with, by declared type.
    /// Types not listed get no signature check.
    static let signatures: [String: [UInt8]] = [
        "image/jpeg": [0xFF, 0xD8, 0xFF],
        "image/png": [0x89, 0x50, 0x4E, 0x47],
        "image/gif": [0x47, 0x49, 0x46, 0x38],
        "application/pdf": [0x25, 0x50, 0x44, 0x46],
    ]

    enum Error: Swift.Error, CustomStringConvertible {
        case noDatabase
        var description: String { "file needs the database copy in the folder" }
    }

    struct Options {
        var id: String? = nil
        /// 0 means every attachment row.
        var limit: Int = 10
        var outDirectory: String? = nil
    }

    struct Tally {
        var rows = 0, objects = 0, fetched = 0, opened = 0, consistent = 0, thumbs = 0, missing = 0, failed = 0
    }

    /// One attachment row's reference, decrypted.
    struct Reference {
        let id: String
        let storageKey: String
        let dek: SymmetricKey
        let dekString: String
        let mime: String
        let ext: String
        let byteSize: Int?
        let hasThumb: Bool
    }

    /// The rows that point at one object. Copies and clones of a photo
    /// alias the object: a fresh row with the same storage_key and the
    /// same attachmentRef, file key included (docs/attachments.md).
    struct ObjectGroup {
        let storageKey: String
        var references: [Reference]
    }

    static func run(session: Session, fetcher: ObjectFetcher, environment: BucketEnvironment, options: Options) throws -> Report {
        guard let db = session.db else { throw Error.noDatabase }
        var report = Report(title: "veri-popt file")
        var tally = Tally()
        var problems: [String] = []
        var controlDone = false

        // Every attachment row (the plaintext storage bit), its reference
        // decrypted, grouped by object.
        var sql = "SELECT id, audience_id, storage_key, payload FROM blocks WHERE (storage & \(BlocksReport.attachmentStorageBit)) != 0"
        var parameters: [Database.Value] = []
        if let id = options.id { sql += " AND id = ?"; parameters.append(.text(id)) }
        sql += " ORDER BY id"
        let rows = try db.query(sql, parameters)
        var groups: [ObjectGroup] = []
        var index: [String: Int] = [:]
        for row in rows {
            let id = row.string("id") ?? "?"
            tally.rows += 1
            guard let key = try session.blockKey(audienceId: row.string("audience_id")).key,
                  let block = try? BlockCrypto.open(payload: row.string("payload") ?? "", with: key),
                  let ref = (block.value as? [String: Any])?["attachmentRef"] as? [String: Any],
                  let dekString = ref["fileDEK"] as? String, let dek = try? FileBlob.dek(from: dekString)
            else {
                tally.failed += 1
                problems.append("\(id): the row does not open, or carries no usable attachmentRef (see `blocks`)")
                continue
            }
            guard let storageKey = row.string("storage_key") else {
                tally.failed += 1
                problems.append("\(id): attachment row without a storage_key")
                continue
            }
            let reference = Reference(
                id: id, storageKey: storageKey, dek: dek, dekString: dekString,
                mime: ref["mimeType"] as? String ?? "?", ext: ref["fileExtension"] as? String ?? "bin",
                byteSize: (ref["byteSize"] as? NSNumber)?.intValue, hasThumb: ref["hasThumb"] as? Bool ?? false
            )
            if let i = index[storageKey] {
                groups[i].references.append(reference)
            } else {
                index[storageKey] = groups.count
                groups.append(ObjectGroup(storageKey: storageKey, references: [reference]))
            }
        }
        tally.objects = groups.count
        let checked = options.limit > 0 ? Array(groups.prefix(options.limit)) : groups

        report.section("Bucket") { s in
            s.line("environment: \(environment.rawValue) (\(environment.baseURL))")
            s.line("downloads are open by design: a plain GET of the object key, no token (SPEC § 7). This is the tool's only network traffic")
            if tally.rows == 0 {
                s.note(options.id == nil
                       ? "this database has no attachment rows (no block carries the attachment storage bit); nothing to fetch"
                       : "no attachment row with that id")
            } else {
                s.line("attachment rows: \(tally.rows), pointing at \(groups.count) object(s); checking \(checked.count)\(checked.count < groups.count ? " (--limit \(options.limit); 0 for all)" : "")")
            }
        }

        for group in checked {
            let first = group.references[0]
            try report.section("Object \(group.storageKey)") { s in
                s.line("rows: \(group.references.map(\.id).joined(separator: ", "))")
                s.line("type: \(first.mime)  declared size: \(first.byteSize.map(String.init) ?? "?")  thumbnail: \(first.hasThumb ? "yes" : "no")")
                if group.references.count > 1 {
                    if Set(group.references.map(\.dekString)).count == 1 {
                        s.ok("the \(group.references.count) rows pointing at this object carry the same file key")
                    } else {
                        tally.failed += 1
                        s.fail("the rows pointing at this object carry different file keys; at most one can open it")
                    }
                }

                // Fetch once.
                let served: Data
                switch try fetcher.fetch(objectKey: group.storageKey) {
                case .status(let code):
                    tally.missing += 1
                    s.warning("the bucket answered HTTP \(code) for the object (gone after a cleanup pass, or the wrong --env)")
                    return
                case .bytes(let data):
                    served = data
                }
                tally.fetched += 1
                s.line("served: \(served.count) bytes")
                if Inspection.looksLikeText(served) {
                    s.fail("the served bytes read as text; the bucket should hold ciphertext only")
                }
                if let signature = Self.signatures[first.mime], served.starts(with: signature) {
                    s.fail("the served bytes start with the \(first.mime) signature; the bucket holds the file in the clear")
                }

                // Open under the (shared) file key.
                let plaintext: Data
                do {
                    plaintext = try FileBlob.open(served, with: first.dek)
                } catch {
                    tally.failed += 1
                    s.fail("the object does not open under the row's file key: \(error)")
                    return
                }
                tally.opened += 1
                s.ok("the object opens under the row's file key")
                var consistent = true
                if served.count != plaintext.count + FileBlob.overhead {
                    consistent = false
                    s.fail("served \(served.count) bytes but plaintext is \(plaintext.count): not nonce + ciphertext + tag")
                }
                if let byteSize = first.byteSize, byteSize != plaintext.count {
                    consistent = false
                    s.fail("the row declares \(byteSize) bytes, the object opened to \(plaintext.count)")
                }
                if let signature = Self.signatures[first.mime] {
                    if plaintext.starts(with: signature) {
                        s.ok("the plaintext starts with the \(first.mime) signature")
                    } else {
                        s.warning("the plaintext does not start with the \(first.mime) signature the row declares")
                    }
                } else {
                    s.line("no signature known for \(first.mime); content not checked")
                }
                if consistent { tally.consistent += 1 } else { tally.failed += 1 }

                // Negative control, once per run.
                if !controlDone {
                    controlDone = true
                    let tampered = flippedByte(served, at: served.count / 2)
                    if (try? FileBlob.open(tampered, with: first.dek)) == nil {
                        s.ok("one changed byte in the served object fails authentication")
                    } else {
                        s.fail("one changed byte in the served object still opened")
                    }
                }

                // Thumbnail, under the same key.
                if first.hasThumb {
                    switch try fetcher.fetch(objectKey: FileBlob.thumbObjectKey(storageKey: group.storageKey)) {
                    case .status(let code):
                        s.warning("the thumbnail object answered HTTP \(code)")
                    case .bytes(let thumb):
                        do {
                            let thumbPlain = try FileBlob.open(thumb, with: first.dek)
                            tally.thumbs += 1
                            s.ok("the thumbnail (\(thumb.count) bytes) opens under the same file key to \(thumbPlain.count) bytes")
                            try write(thumbPlain, name: "\(first.id)-thumb.jpg", to: options.outDirectory, s: &s)
                        } catch {
                            s.fail("the thumbnail does not open under the row's file key: \(error)")
                        }
                    }
                }
                try write(plaintext, name: "\(first.id).\(first.ext)", to: options.outDirectory, s: &s)
            }
        }

        var summary = Report.Section(title: "Summary")
        summary.line("rows: \(tally.rows); objects: \(tally.objects); checked: \(checked.count); fetched: \(tally.fetched); opened: \(tally.opened); consistent: \(tally.consistent); thumbnails opened: \(tally.thumbs); missing: \(tally.missing); failed: \(tally.failed)")
        if tally.rows == 0 {
            summary.note("nothing fetched: no attachment rows")
        } else if tally.failed == 0, tally.opened > 0 {
            summary.ok("every object fetched is ciphertext that opens, under its row's key alone, to the file the row describes")
        } else if tally.failed > 0 {
            summary.fail("\(tally.failed) problem(s)")
        }
        for line in problems.prefix(Self.maxListed) { summary.line(line) }
        report.sections.append(summary)
        return report
    }

    private static func write(_ data: Data, name: String, to directory: String?, s: inout Report.Section) throws {
        guard let directory else { return }
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
        let path = (directory as NSString).appendingPathComponent(name)
        try data.write(to: URL(fileURLWithPath: path), options: [.atomic])
        s.line("written: \(path)")
    }

    static func flippedByte(_ data: Data, at offset: Int) -> Data {
        var copy = data
        copy[copy.startIndex + offset] ^= 0x01
        return copy
    }
}
