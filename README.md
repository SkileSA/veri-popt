# veri-popt
`veri-popt` is a macOS CLI which aims to document our end-to-end encryption design and facilitate verifying it against real data from **Popt**.

## The Popt app
[Popt](https://popt.com) is an iOS personal productivity app developed and published by Skile SA, rue de Riant-Coteau 7, 1196 Gland, Switzerland.

- **Bundle ID:** `ch.skile.popt-it`
- **Platforms:** iOS, iPadOS, macOS (Designed for iPad)
- **Minimum OS version:** 26.2

### Data model summary
Our data architecture is local-first, with an authoritative server.
- SQLite database on the device contains encrypted blocks and a plaintext mirror. The database folder is excluded from both iCloud and local iOS backup.
- Postgres authoritative store, encrypted blocks only
- Replication of user-scoped rows to their signed-in devices with [PowerSync](https://powersync.com)
- Upload through our own endpoint, client-side conflict resolution at upload time

The core tables for user content and sharing are the following:

#### `blocks` table
All content is modeled as blocks structured in trees. The actual content is stored in the encrypted `payload` column. Metadata necessary for replicating the appropriate rows to users, detecting conflicts server-side, managing attachments, and validating uploaded rows is stored in plaintext columns.

The `audience_id` column is used for shared blocks, and is `null` for personal blocks. PowerSync syncs down all personal blocks the user owns, and all blocks associated with an audience they are a member of.

On sync-down of new or updated blocks, Popt decrypts block payloads into the local-only `plain_blocks` table. That table is never synced; it is a purely local cache. The `veri-popt` CLI verifies encryption by decrypting block payloads and comparing against the corresponding rows in the `plain_blocks` table.

#### `keys` table
Shared content is encrypted per audience, an audience being defined as an owner and a set of peers. Therefore, Alice and Bob can constitute two distinct audiences: Alice as owner, Bob as peer; Bob as owner, Alice as peer. The owner mints an audience's key, and wraps it for each peer with the unique ECDH secret they share with them, and for themselves with a separate owner-wrap key.

PowerSync syncs down key grants by `peer_id`. The delivery of a key to the wrong user is harmless: the key simply fails to unwrap.

#### `user_profiles` table
This table holds a user's screen name, status text, avatar image data, and public key. The entire table is in plaintext, which the app discloses in the profile editing screen. We decided against encrypting user profiles so that friends of friends can be displayed in group chats, and to enable user discovery in the future. For now, there is no searchable directory and users only connect via direct invite links. If we do add a directory, it will be strictly opt-in.

PowerSync syncs down the self profile, profiles with which we have a connection, and profiles of peers of audiences we are a member of.

#### `user_connections` table
Models connections between users, and connection status (pending, active, blocked).

PowerSync syncs down all `user_connections` rows where the user is the initiator or recipient.

## The `veri-popt` tool

The CLI inspects real SQLite databases produced by Popt. It does not require Full Disk Access, but asks you to provide a path to a non-sandboxed folder in which you place a copy of the Popt database to verify, along with encrypted keys which you export directly from Popt. You provide your recovery code in a hidden prompt or as a file path, and `veri-popt` unwraps the keys, performs the required key derivations, and verifies that the data matches our cryptographic spec.

Because Popt's binary can run on Apple silicon Macs, the most convenient way to extract a database is to install Popt from the App Store on a Mac, and copy the database from the app's sandbox. Extracting from an iOS device is much less practical since the database is excluded from backups.

Building the tool needs Xcode 27.2 or later on macOS 26.2 or later. To get started with the CLI, follow the instructions in [docs/VERIFYING.md](docs/VERIFYING.md).

Learn more about our cryptographic specifications in [docs/SPEC.md](docs/SPEC.md).

### Commands and what they verify
Every command except `find-db` takes as its single positional argument the path to a non-sandboxed folder containing the following:

- `powersync-popt-it.sqlite` and its `-wal` file, copied from the app's sandbox
- `popt-locked-keys.json`, exported from the app in **My Account ▸ Security ▸ Export Locked Keys**
- `popt-vault.sqlite`, optional, copied from the app's sandbox while a vault is unlocked

The recovery code is typed at a hidden prompt, or read from a file with `--code-file`. It is never a command-line argument. Reports never print a key unless you ask with `--reveal`. Every command has `--help` and `--json`. The exit status is 1 when a check fails and 2 when the tool could not run.

#### `find-db`
Finds the running app's database folder and shows it in Finder so you can copy the database and journal file.

#### `inspect`
Reads the database copy without requiring secrets.

- Lists the plaintext columns of `blocks` and the other synced tables, from the triggers that feed PowerSync's upload queue.
- Checks that every stored `blocks.payload` and every `keys` row is an encryption envelope, never plaintext.
- Checks the pending uploads in the queue the same way.
- Checks that `plain_blocks` and the other local-only tables have no upload trigger, so the plaintext mirror never syncs.
- Fails if no upload trigger is found at all, since then the plaintext claim would be vacuous.
- Lists your audiences and profiles, and notes retired columns and a missing WAL file.

#### `derive`

Rebuilds every key from your recovery code and the exported locked keys.

- Checks that the exported record belongs to the account in the database.
- Walks the chain: recovery code to recovery KEK, KEK to Master DEK, Curve25519 key and signing key, then every subkey. Prints a fingerprint for each.
- Checks that the derived public keys match the ones published in your profile.
- Tries a wrong recovery code and shows that it fails.
- With the database present, shows each key opening something the app wrote, or says plainly that nothing was there to check it against.
- Checks your key pins block: it opens, and every pinned peer key is a valid public key.

#### `keys`

Checks the keys of every audience you own or are a peer of.

- Opens each `keys` row you hold: an owner row under your owner-wrap key, a peer row through ECDH with the owner's pinned key.
- Uses only your pinned keys for ECDH, never the key the server publishes, and reports peers that are not pinned.
- For audiences you own, checks that the stored key equals the deterministic mint rule, and that rows wrapped for members open with the same key.
- Fails when the database holds blocks under an audience whose key it cannot obtain.

#### `blocks`

Decrypts every payload in the `blocks` table and compares it with the corresponding local-only `plain_blocks` row.

- Opens each `blocks.payload` under the documented key: the personal key, the audience key, or the share-extension key for sentinel rows.
- Compares the decrypted payload, parent, UI group and audience ledger with the matching `plain_blocks` row, field by field.
- Counts rows the app has not mirrored at this revision yet as pending, and deep-link seeds separately.
- Flags orphaned `plain_blocks` rows, and warns about personal rows owned by another account, which the sync stream never serves and no key here could open.
- Lists every failure and keeps going.

#### `blocks-diff`

Shows where a mirror row differs from the ciphertext, for the rows `blocks` reports as "mirror differs" or for one row named with `--id`.

- Decrypts the row and compares its payload with the mirror's key by key, nested objects and arrays included, and names each differing key by its path.
- Tells keys present on one side only apart from keys whose values differ. The app writes the mirror by decoding the ciphertext into its typed model and encoding that model again, so a row written by an older app version can carry keys the current model drops, or lack keys it now adds, until the row is next edited. Those are notes.
- Warns when a key present on both sides has different values, or when another mirror column differs, since nothing in the app explains that.
- Names the two sides by their JSON type only, so the report can be shared. `--reveal` prints the values, which are your content.

#### `file`

Fetches attachments from the attachment bucket (Cloudflare R2) and opens them. The only command that uses the network.

- Fetches each object with a plain GET, as the app does, grouping rows that point at the same object.
- Checks that the served bytes are ciphertext: not text, not a known file signature, and the right length for nonce plus ciphertext plus tag.
- Opens the object under the file key stored inside its row, and checks the size and the file type the row declares.
- Opens the thumbnail under the same key.
- Changes one byte and checks that the object no longer opens.
- With `--out`, writes the decrypted files. Checks ten objects by default, `--limit 0` for all.

#### `vault-list`

Lists your secret vaults from the vault config block.

- Finds the config block at the id derived from your Master DEK and checks that it opens under your personal key.
- Checks that the row carries no audience, since a vault config is personal.
- Lists every vault, hidden ones included, with the id to pass to `vault`.
- Notes vaults that share a name.

#### `vault`

Opens one vault with its passphrase and checks everything inside it.

- Opens the vault's key: PBKDF2 over the slot's salt gives the KEK, the KEK opens the wrapped vault key.
- Tries a passphrase with one extra character and checks that it fails.
- Opens every wrapper row in the vault under its own per-row key derived from the vault key.
- Checks that parents stay inside the vault and that the main database keeps the inner layer sealed.
- Checks that rows exist at the container ids derived from the vault key.
- With `popt-vault.sqlite` in the folder, compares with the app's own decryption row by row.

### Not covered yet
`veri-popt` is still a work in progress. The following need to be documented and verified:

- the Keychain flow (what is cached on device, synced in iCloud Keychain, the extension boundary)
- the Share Extension transit key (`shareExtensionKey`): a block it wrote is re-encrypted under the personal key as soon as the app runs, so a database copy never holds one; checking it needs its own flow
- recovery code rotation and the `rotateVault` signature
- inside a vault: the quick-unlock Keychain item and the encrypted thumbnail store (the config block, the passphrase path, the per-row keys and the vault database are checked, SPEC § 8)
- how a key pin comes to exist: the two verified moments, the acceptance tags, the verification pass (the pins block itself is already checked)
- live traffic between client and server
- invite links and the App Clip
- push payloads and the notification extension
- abuse reports and the server public keys they encrypt to

### Limits of the approach
The tool checks the data the app produces, not the app's code. We considered publishing our crypto module as a signed dynamic library that could verifiably be linked into Popt's binary, but that would add little guarantee: the app could bypass it entirely. Short of open-sourcing the entire app, offering tools to audit what the app produces is a reasonable compromise.

## Repo layout

- `docs/SPEC.md`: the cryptography specifications, as implemented.
- `docs/VERIFYING.md`: how to run a verification, step by step.
- `Sources/Core`: the pure parts, compiled into the tool and the tests.
- `Sources/CLI`: the commands.
- `Tests`: the known-answer tests and the small database fixture.

## License

MIT, see [LICENSE](LICENSE).
