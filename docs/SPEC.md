# Popt crypto, as implemented

This is the normative description of the cryptography that `veri-popt`
re-implements and checks. It is written to stand on its own: an auditor
should be able to read this file, read the tool's sources, and judge
whether the tool actually tests what the Popt app claims, without reading
the app's code. Every constant below was read from the app's sources
(see § 9). Where the tool and this file disagree, this file is
wrong or the tool is wrong, never the app by definition; file an issue.

Scope of this version: key derivation, block encryption, file encryption,
the key-pins block and secret vaults. What is not covered yet is listed
in the README, § Not covered yet.

## 1. Conventions

- **HKDF** means HKDF with SHA-256 (RFC 5869), as CryptoKit's
  `HKDF<SHA256>.deriveKey(inputKeyMaterial:salt:info:outputByteCount:)`.
  Every derivation in this document outputs 32 bytes.
- **AES-GCM** means AES-256-GCM with a random 12-byte nonce and a 16-byte
  tag. No additional authenticated data is ever used.
- **ECDH** means X25519 key agreement (CryptoKit `Curve25519.KeyAgreement`).
- **Signing** means Ed25519 (CryptoKit `Curve25519.Signing`).
- **base64** means standard base64 with padding (RFC 4648 § 4).
- **Raw key bytes** means CryptoKit's `rawRepresentation`: 32 bytes for a
  Curve25519 private or public key, 32 bytes for an Ed25519 private or
  public key, and the bare 32 bytes of a symmetric key.
- **User id** means the Firebase Authentication uid of the account.
- Strings fed to a KDF are UTF-8 encoded, no terminator.

## 2. Envelopes

Two ciphertext formats exist.

### 2.1 JSON envelope

Used for every key wrap and every block payload. A JSON object with three
base64 string fields, keys sorted, no whitespace:

```json
{"ciphertext":"<base64>","nonce":"<base64>","tag":"<base64>"}
```

`nonce` decodes to 12 bytes, `tag` to 16 bytes. Readers accept the fields
in any order and ignore unknown sibling fields. One sibling field is
defined: `"peer"`, a user id, present only on peer-wrapped audience keys
(§ 6.3).

### 2.2 Combined blob

Used for attachment objects. The AES-GCM combined representation,
`nonce ‖ ciphertext ‖ tag`, as raw bytes. Its length is the plaintext
length plus 28.

## 3. Recovery code

The recovery code is the one secret a user holds. Everything else is
derived from it plus data the server stores.

- 16 characters from the Crockford base32 alphabet
  `0123456789ABCDEFGHJKMNPQRSTVWXYZ` (no `I`, `L`, `O`, `U`).
- Generated from 16 random bytes, each reduced modulo 32, so every
  character is uniform. Entropy: 80 bits.
- Displayed and stored as four groups of four joined by hyphens:
  `XXXX-XXXX-XXXX-XXXX`, 19 characters.

**Normalization.** The code reaches the KDF by two routes. A code synced
through iCloud Keychain is used as stored, in the hyphenated form the app
generated. A code entered by hand is trimmed of surrounding whitespace and
uppercased. **The hyphens are part of the key material**:
the KDF input is the UTF-8 bytes of the 19-character formatted string.

## 4. The vault record

One row per user in the server's `vaults` table, served to the app by the
connections service's `getVault` call and exported by the app for this
tool as `popt-locked-keys.json` (My Account ▸ Security ▸ Export Locked
Keys; the app calls it "locked keys" because "vault" means something else
in its UI). Field names below are the JSON names the service returns; the
Postgres column is in parentheses.

| Field | Content |
|---|---|
| `id` | the user id |
| `kdfSalt` | 16 random bytes, base64 |
| `masterKekRecoveryWrapped` | JSON envelope: the KEK, sealed under the recovery KEK |
| `masterDekWrapped` | JSON envelope: the Master DEK, sealed under the KEK |
| `privateKeyWrapped` | JSON envelope: the raw Curve25519 private key, sealed under the KEK |
| `signingKeyWrapped` | JSON envelope: the raw Ed25519 private key, sealed under the KEK |
| `signingPublicKey` | raw Ed25519 public key, base64, plaintext |
| `createdAt`, `updatedAt` | epoch milliseconds |

The record is inert without the recovery code. It contains no plaintext
key other than the signing public key, and it must never contain the
recovery code. The tool refuses a record that carries a field named
`recoveryCode` or any unwrapped key.

## 5. Key derivation

### 5.1 From the recovery code to the three long-lived keys

```
recoveryKEK = HKDF(ikm = utf8(recoveryCode),      salt = kdfSalt,  info = "popt-recovery-kek-v1")
KEK         = open(masterKekRecoveryWrapped, recoveryKEK)        // 32 bytes
masterDEK   = open(masterDekWrapped,         KEK)                // 32 bytes
curvePriv   = open(privateKeyWrapped,        KEK)                // raw Curve25519 private key
signPriv    = open(signingKeyWrapped,        KEK)                // raw Ed25519 private key
```

`open(envelope, key)` is AES-GCM decryption of a JSON envelope. A wrong
code fails at the first `open` with an authentication error. The app
treats every failure to unwrap the same way, a wrong code and a damaged
record alike, and asks for the code again. The tag is the only verifier
of the code; there is no separate check value, by design.

The KEK is random (32 bytes, generated at sign-up), not derived from any
user secret. Its only job is to wrap the three keys above. The recovery
KEK wraps the KEK so the code can be rotated without re-wrapping anything
else (rotation is not covered yet, README § Not covered yet).

Checks the tool performs after unwrapping:

- `curvePriv`'s public key, raw bytes base64, equals the user's
  `user_profiles.public_key` when a DB is given.
- `signPriv`'s public key, raw bytes base64, equals `signingPublicKey`.

### 5.2 The subkey tree

Every subkey is one HKDF step. Salts and info strings are literal ASCII.

| Key | IKM | Salt | Info |
|---|---|---|---|
| `personalBlocksKey` | `masterDEK` | `popt-it-master-dek` | `popt-personal-blocks-v1` |
| `sharedRootKey` | `masterDEK` | `popt-it-master-dek` | `popt-shared-root-v1` |
| `ownerWrapKey` | `sharedRootKey` | `popt-it-shared-root` | `popt-owner-wrap-v1` |
| `shareExtensionKey` | `sharedRootKey` | `popt-it-shared-root` | `popt-share-extension-v1` |
| `audienceMintKey(aid)` | `sharedRootKey` | `popt-it-shared-root` | `popt-audience-v1:` + aid |

Properties this layout is meant to give, and which the tool can show:

- `sharedRootKey` is one-way. Holding it (as the app's extensions do)
  does not yield `masterDEK` or `personalBlocksKey`.
- `audienceMintKey(aid)` is the audience DEK itself for an audience the
  user owns (§ 6.3). Two devices of the same owner mint the same DEK with
  no coordination.

### 5.3 Identifiers that are hashes, not secrets

The audience id is derived, not random:

```
audienceId = hex( SHA256("popt-v1|" + ownerId + "|" + join(sorted(peerIds), ","))[0..<16] )
```

It is an identifier, not key material. The tool recomputes it only to
label audiences; it proves nothing cryptographic.

## 6. Block encryption

### 6.1 What the server stores

Every piece of user content is a row in `blocks`. The server, and anyone
reading the sync stream, sees these columns in plaintext:

`id`, `created_at`, `updated_at`, `revision`, `device_id`, `owner_id`,
`root_id`, `audience_id`, `storage`, `storage_updated_at`, `project_id`,
`storage_key`.

The content is the single `payload` column: a JSON envelope (§ 2.1). The
local database mirrors this table unchanged, so a copy of the local DB is
also a faithful sample of what the server holds for that user. An install
from before October 2026 may still carry two retired columns, `conflicts`
and `conflict_id`: SQLite never drops a column, they are NULL on every
row, and the server's table no longer has them.

What syncs up is decided by PowerSync's triggers: a table is uploaded only
through a trigger that writes the upload queue (`powersync_crud`, landing
in `ps_crud`). A table without such a trigger never leaves the device
through sync, whatever it holds.

The local database additionally holds `plain_blocks`, the decrypted mirror
the UI reads. That table is local-only and never syncs. On iOS and iPadOS
the whole database directory is marked excluded from backup, so it is in
neither iCloud nor local device backups, and its files carry the
"complete until first user authentication" data-protection class.
`plain_blocks` therefore exists on the device only. The tool uses it as
the expected value when checking its own decryption.

### 6.2 Which key opens a row

```
if audience_id IS NULL:   key = personalBlocksKey
else:                     key = audienceDEK(audience_id)     // § 6.3
```

When no `keys` row exists for the reader and the reader owns the audience,
the app uses `audienceMintKey(audience_id)` directly (§ 5.2). The tool
does the same and reports that it did.

### 6.3 Audience keys

The `keys` table has one row per (audience, member):

| Column | Content |
|---|---|
| `id` | row id |
| `audience_id` | the audience |
| `owner_id` | the audience owner |
| `peer_id` | the member this row is for |
| `wrapped_dek` | JSON envelope of the 32-byte audience DEK |

To read audience `aid`, a user with id `me` takes the row where
`audience_id = aid AND peer_id = me` and unwraps it by the row's shape:

- **Owner row** (no `peer` sibling field): `DEK = open(wrapped_dek, ownerWrapKey)`.
- **Peer row** (`"peer": ownerId` present):

```
shared   = X25519(curvePriv(me), curvePub(ownerId))           // the pinned key, § 6.4
wrapKey  = HKDF(ikm = shared, salt = "popt-it-dek-share", info = "dek-wrap")
DEK      = open(wrapped_dek, wrapKey)
```

The owner produced the same `wrapKey` from `X25519(curvePriv(owner),
curvePub(me))`; the two agree by the commutativity of X25519.

`curvePub(ownerId)` is the owner's raw Curve25519 public key as the
account **pinned** it (§ 6.4), never the copy the server publishes in
`user_profiles.public_key`. An unpinned owner is refused, not looked up.

A device holds only the rows for its own user: the sync stream serves
`keys` rows `WHERE peer_id = <me>`. An owner that mints a share writes the
members' rows locally, uploads them, and loses them at the next sync
checkpoint, since they match no stream query. A copy of the database
therefore shows the member side of a share only when the share is still
waiting to upload.

For an audience the user owns, the unwrapped DEK must also equal
`audienceMintKey(aid)` (§ 5.2). The tool reports an owned audience whose
DEK does not match as a finding, not as a failure: it means that DEK was
not minted by the deterministic rule.

### 6.4 Peer keys: the pins block

The server can serve any key in `user_profiles`, so no key decision
reads that column. Every ECDH takes the peer's key from the account's
**key-pins block**: a personal block (`audience_id` NULL, under
`personalBlocksKey`) at the deterministic id

```
hex( SHA256("popt-synced-dict-v1|" + ownerId + "|key_pins|user")[0..<16] )
```

Its decrypted payload is a synced dictionary (`payload.type` 14) whose
value echoes `"type": "key_pins"` and `"scope": "user"` and holds
`entries`: one per user id, the account's own included, each
`{"value": {"x25519": "<base64 raw key>", "unfriended": true?}, "updatedAt": ms}`.
An entry the reader cannot parse counts as unpinned. A key is written
once per user and never changed in place; the `unfriended` flag is the
one field that flips.

What the tool checks: the block exists at its id and opens; its `type`
and `scope` fields echo `key_pins` and `user`; the self entry equals the derived Curve25519 public key;
every ECDH above used the pinned key; and, as a cross-check only, the
key the server publishes for each pinned peer equals the pinned one. A
divergence there is the substitution the pins defend against, and is
reported as a failure. How a pin comes to exist (the two verified
moments, the acceptance tags, the verification pass) is not checked
(README § Not covered yet).

### 6.5 The decrypted payload

Opening a block envelope yields UTF-8 JSON of this shape:

```json
{
  "parentBlockId": {"value": "<id or null>", "updatedAt": 0},
  "payload":       {"type": <int>, "value": { ... }},
  "uiGroup":       {"value": <int or null>, "updatedAt": 0},
  "audienceLedger": { ... }
}
```

Only `payload` is required. `payload.type` is the integer block-type tag;
`payload.value` is the type-specific content; `uiGroup.value` is an
integer tag as well. Several fields are
`{value, updatedAt}` pairs (per-field last-writer-wins timestamps). The
tool treats the decrypted bytes as opaque JSON; it does not need to
understand any block type.

**Comparison with the local mirror.** `plain_blocks` does not store the
decrypted object whole. It hoists the parts into columns:

| Decrypted field | `plain_blocks` column |
|---|---|
| `payload.value` | `payload` (JSON text of the value object alone) |
| `payload.type` | `block_type` |
| `parentBlockId.value` | `parent_block_id` |
| `uiGroup.value` | `ui_group` |
| `audienceLedger` | `audience_ledger` (JSON text) |

JSON is compared as parsed values, never as bytes. Only the envelope
(§ 2.1) is written with sorted keys; the plaintext inside it, and the
mirror's `payload` column, come from the default encoder, which does not
sort, so two encodings of one value can differ in key order.

**What the mirror is.** The app does not copy the decrypted bytes into
the mirror. It decodes them into its typed payload model and encodes
that model again (`PlainBlocksRow.fromSyncedBlock`). The mirror is
therefore the model's view of the row as held by the build that last
mirrored it. A row is mirrored again only when its `revision` changes;
an app update never refreshes a mirror. Two consequences follow, and
the tool treats them differently:

- The key sets may differ. A key the current model has retired stays in
  the ciphertext and is absent from the mirror; a key added to the model
  after a row was mirrored is in the ciphertext (written by a newer
  build) and absent from the mirror (written by an older one). Either
  way every key present on both sides holds the same value. `blocks`
  counts such rows as *legacy key set* and reports them as a note;
  `blocks-diff` names the keys.
- A key present on both sides with different values, or any other
  mirror column that differs, has no explanation in the app and is a
  failure.

A retired key is not deleted by being dropped from the model: it stays
inside the ciphertext, under the row's key, until the row is next
edited and re-encrypted.

Attachment rows carry, inside `payload.value`, an `attachmentRef` whose
`fileDEK` field is the base64 32-byte key of the file (§ 7). The file key
is therefore protected by whatever key protects the block.

## 7. File encryption

- Each attached file gets its own random 32-byte DEK at attach time. It is
  stored only inside the owning row's encrypted payload
  (`attachmentRef.fileDEK`, base64) and never rotates.
- The uploaded object is the combined blob (§ 2.2) of the file bytes under
  that DEK. Nothing else is in the object: no header, no metadata.
- The object's bucket key is the row's plaintext `storage_key`, of the form
  `{uploaderUserId}/{objectId}`. A thumbnail, when the row says it has
  one, is the sibling object `{storage_key}.thumb`, encrypted under the
  same DEK.
- Objects are immutable and the bucket is public-read by design: a fetch
  is a plain GET of the key with no token, at
  `https://storage.attachments.popt.com/<key>` (production) or
  `https://storage-staging.attachments.popt.com/<key>` (staging), each
  path component of the key appended in turn. Listing is disabled; the
  key, `{uploaderUserId}/{objectId}`, is the only gate. What that GET
  returns is ciphertext; the secrecy is in the file key, which lives
  inside an encrypted block. Several rows may point at one object (a copy
  of a photo aliases it) and then carry the same file key.
- Checks: the blob opens under the DEK; its length is the plaintext length
  plus 28; the thumbnail opens under the same DEK; a one-byte change
  anywhere in the blob fails authentication.

## 8. Secret vaults

A vault is a second layer inside the personal space: content a passphrase
opens, on top of the recovery code. Everything about it is ordinary
personal data on the outside, so the server cannot tell a vault block
from any other.

### 8.1 The config block

One personal block per user at

```
configId = hex( HKDF(masterDEK, salt "popt-it-master-dek", info "popt-secret-config-v1", 16 bytes) )
```

type 8, under `personalBlocksKey`. Its decrypted value is
`{"version": 2, "slots": [...]}`, one slot per vault:

| Field | Content |
|---|---|
| `vaultId` | 16 random bytes, hex; the vault's identity, never rotated |
| `name`, `hidden` | the label, and whether the device's UI lists it |
| `wrappedDEK` | JSON envelope (§ 2.1) of the vault DEK under the slot's KEK |
| `kekSalt` | 16 bytes base64, PBKDF2 salt; rotated on passphrase change |
| `hkdfSalt` | 16 bytes base64, HKDF salt for the per-row keys; never rotated |

Names need not be unique and several vaults may share a passphrase;
`vaultId` is the only identity. Hidden vaults are hidden from the
device's UI only: whoever holds the Master DEK reads every slot.

### 8.2 Keys

```
KEK         = PBKDF2-SHA256(passphrase UTF-8, kekSalt, 600000 iterations, 32 bytes)
vaultDEK    = open(wrappedDEK, KEK)                                        // 32 random bytes
rowKey(id)  = HKDF(vaultDEK, salt hkdfSalt, info "secret-mode-v1/" + rowId)
thumbKey    = HKDF(vaultDEK, salt hkdfSalt, info "popt-vault-thumbnails-v1")
```

The vault DEK is random and independent of the Master DEK: the recovery
code alone opens nothing inside a vault, and a passphrase change
re-wraps the same DEK under a new salt without touching any row. A wrong
passphrase fails the wrapped DEK's tag check, like a wrong recovery code
fails the KEK's.

Ids derived from the vault DEK, where the vault's own containers live:

```
containerId(uiGroup) = hex( HKDF(vaultDEK, salt "popt-vault-default-container", info "popt-vault-default-container-v1|" + uiGroup, 16) )
dictionaryId(t, s)   = hex( HKDF(vaultDEK, salt "popt-vault-synced-dict",       info "popt-vault-synced-dict-v1|" + t + "|" + s, 16) )
```

### 8.3 Wrapper rows

Every block inside a vault is a type-9 personal block whose decrypted
value is `{"version": 1, "vaultId": ..., "innerCiphertext": {nonce, ciphertext, tag}}`.
The inner envelope opens under `rowKey(rowId)`, the key derived from
the wrapper's own row id, to a block JSON of the usual shape (§ 6.5).
Parents never cross the vault boundary. The main database's mirror
holds the wrapper value with the inner envelope still sealed; only the
separate vault database (`popt-vault.sqlite`), rebuilt at every unlock
and wiped at lock, holds the inner content in the clear.

What the tool checks: the config block at its id opens and lists its
slots; the passphrase opens the chosen slot and one changed character
does not; every wrapper of that vault opens under its row key; parents
stay inside the vault; the main mirror keeps the inner layer sealed;
rows exist at ids derived from the vault DEK; and, when
`popt-vault.sqlite` was copied while the vault was unlocked, the inner
decryptions equal that mirror.

## 9. Provenance

Every constant, id rule and format in this file was read from the Popt
iOS app's sources, `popt-it-ios` version 1.0.0, on Nov 3 2026. The
known-answer vectors in `Tests/Fixtures/vectors.json` were produced on
the same day by throwaway tests run once against that version's own
crypto code, then deleted; the fixture's `generatedBy` header records
which types produced each section. A later app version may change any
of this; when the tool and the app disagree, check this version first.
