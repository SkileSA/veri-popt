# Verifying your own data

## 1. Get ready
You will need:
- An Apple Silicon Mac running macOS 26.2 or above
- Xcode 27.2 or higher
- A Popt account (free plan is fine)
- Popt installed on the Mac
- Some data in Popt: notes, tasks, journal entries...

In addition, in order to verify sharing features, you'll need at least one friend and some shared content, both ways (they share with you, you share with them). You may open two Popt accounts for the purpose of testing.

## 2. Build the tool
After cloning the repo, open `veri-popt.xcodeproj`, build the `veri-popt` scheme, and note where
the binary is (Product ▸ Show Build Folder in Finder), or from a
Terminal in the repository:

```bash
xcodebuild -scheme veri-popt -destination 'platform=macOS' build
```

The commands below write `veri-popt` for the binary; use its full path or
put it on your `PATH`.

## 3. Create a folder for the verification job
The tool needs to be pointed at a folder which you'll populate with the necessary files. Create that folder now, for example at
`~/popt-check` which is the path we'll use as an example in this guide.

## 4. Export your locked keys, save your recovery code

- Launch Popt, navigate to **Me tab -> My Account** and tap _Export Locked Keys_. 
- Save it to the `~/popt-check` folder you just created, it should be named `popt-locked-keys.json`. The file holds the encrypted copy of your keys, and your recovery code is the only thing that unlocks them.
- If you haven't already, copy your recovery code somewhere safe. Tap **Show Recovery Code** in the _My Account_ view to display it in Popt.

## 5. Extract the database

With Popt still running on the Mac, run the following command:

```bash
veri-popt find-db
```

It prints the folder where the running app keeps its database and opens
that folder in Finder with the file selected.

- Quit Popt first, so its write-ahead log is at rest
- Copy and paste `powersync-popt-it.sqlite` and `powersync-popt-it.sqlite-wal` into `~/popt-check`

## 6. Run the verification commands
At this point, the `~/popt-check` folder should hold at least a copy of your database, and the exported encrypted keys.

### Db structure

```bash
veri-popt inspect ~/popt-check
```

This reads the copy and reports what the server sees: the plaintext
columns, every payload and wrapped key checked for being ciphertext, the
upload queue, your audiences, and the fact that the app's plaintext
mirror has no sync trigger. Nothing here uses your code.

### Key derivation

```bash
veri-popt derive ~/popt-check
```

You are prompted for your recovery code, typed with echo off; any form
is fine, with or without hyphens. The report walks the
chain from the code to every key, showing fingerprints rather than keys,
then shows each key opening something the app wrote, or says plainly
when the database holds nothing to check it against. A deliberately
wrong code is tried too and must fail.

If you want to script this, put the code alone in a file and pass
`--code-file`; delete the file afterwards.

### Keys and blocks

```bash
veri-popt keys ~/popt-check
veri-popt blocks ~/popt-check
```

`keys` goes through every share: how each audience key is obtained and
whether the ones you own were minted by the documented rule. `blocks`
opens every row of your content under the documented key and compares
it with the corresponding row in `plain_blocks`. Rows the app had not mirrored yet
are reported as pending, not as failures.

### Attachments

```bash
veri-popt file ~/popt-check --out ~/popt-check/decrypted
```

This is the one command that uses the network: it fetches your
attachment objects from the bucket exactly as the app does, by plain
GET, and opens each under the file key carried in its row. With `--out`
the decrypted files are persisted. The default checks ten objects; pass
`--limit 0` for all. If your account is on the staging environment, add
`--env staging`.

### Vaults

```bash
veri-popt vault-list ~/popt-check
veri-popt vault ~/popt-check --vault <id>
```

`vault-list` needs only the recovery code: it finds the secret config
block at its id derived from your Master DEK and lists every vault,
hidden ones included. `vault` then asks for that
vault's passphrase and checks every block in it. Without `--vault` it
tries the one passphrase on every slot and says which it opened. To
compare the inner content with the app's own decryption, copy
`popt-vault.sqlite` from the databases folder into your folder while
that vault is unlocked in Popt; the file is wiped at lock.

## Reading a report

Each line is tagged:

- `ok`: the check passed.
- `note`: a fact worth knowing, not a problem (for example, a key with no
  example to check against in this database).
- `WARN`: something unexpected that is not a failed check.
- `FAIL`: a check failed. The run continues.

The exit status is 0 on pass, 1 when any check failed, 2 when the tool
could not run at all (a missing file, a wrong code).

## If something fails

A report contains no key and no code unless you asked for `--reveal`,
so it is safe to share. Open an issue on this repository with the
report, the version of Popt, and whether the copy was taken while Popt
was running. A failure is either a bug in this tool, a change in the app
the spec has not caught up with, or a real problem, and the spec's
provenance table says which version of the app it describes.

## Cleaning up

The `~/popt-check` folder holds a readable copy of your content: the database carries the app's own decrypted mirror, and `--out` writes attachments unencrypted, so make sure you delete it when you are done.
