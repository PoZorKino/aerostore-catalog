# Manifest format

One JSON file per app in `manifests/`. CI and the AeroStore server both check these rules.


One file per app: `manifests/<id>.json`.

```json
{
  "id": "videolan.vlc",
  "name": "VLC media player",
  "publisher": "VideoLAN",
  "summary": "Plays almost any video or audio file.",
  "description": "Paragraphs separated by a blank line.\n\nPlain text, no markup.",
  "category": "multimedia",
  "license": "GPL-2.0-or-later",
  "homepage": "https://www.videolan.org/vlc/",
  "source": "https://code.videolan.org/videolan/vlc",
  "icon": "https://example.org/vlc-256.png",
  "screenshots": ["https://example.org/vlc-1.png"],
  "version": "3.0.21",
  "released": "2024-06-10",
  "install": {
    "type": "installer",
    "url": "https://get.videolan.org/vlc/3.0.21/win64/vlc-3.0.21-win64.exe",
    "sha256": "<64 lowercase hex>",
    "size": 44000000,
    "format": "exe",
    "silent_args": "/S",
    "detect": "VLC media player"
  }
}
```

Rules:

- `id`: `^[a-z0-9]+(\.[a-z0-9-]+)+$`, `publisher.app` style, max 64 chars, equal to the file name.
- `name` <= 60 chars, `summary` <= 100 chars, `description` <= 4000 chars.
- `category`: one of `development graphics internet multimedia office system games utilities education security`.
- `license`: SPDX id. Must be an OSI-approved or FSF-free license, since this is an open source store.
- `source`: required, public source repository URL.
- `icon`: PNG (or ICO), square, ideally 256px. `screenshots`: 0-6 PNG/JPEG urls.
- `version`: free-form, compared with a numeric-dotted compare (`1.10.2 > 1.9`).
- All urls must be `https://`.
- `install.type`:
  - `installer`: `format` is `exe` or `msi`. `silent_args` optional (empty = interactive installer).
    `detect` = prefix of the `DisplayName` in `HKLM/HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall`,
    used to find it after install and for uninstall.
  - `portable`: `archive` is `zip` or `exe`. For zip, `exe` = relative path of the main exe inside
    the archive (used for the Start menu shortcut). For a bare exe, `exe` is the file name to save as.
- `install.sha256` is required and checked by the client before running anything.

## Signatures

Every published manifest is signed with an ed25519 key that only the maintainer holds,
offline. The server never has the private key, so a compromised server or git host can't
change what the app installs.

- Signature file: `catalog/manifests/<id>.sig` next to `<id>.json`. Content: one line,
  `<key id> <base64 signature>`, where the signature covers the exact bytes of `<id>.json`.
- Key id: first 16 hex chars of sha256(raw 32-byte public key).
- Keys: `tools/cmd/sign keygen -out <path>` writes a private key file and prints the public
  key (base64) and key id. `tools/cmd/sign manifests [-key <path>] <dir>` signs every
  manifest whose `.sig` is missing or doesn't verify, and leaves the rest alone. Default key
  path: `%USERPROFILE%\.aerostore\catalog-signing.key` (env `AEROSTORE_SIGNING_KEY` overrides).
- Trusted public keys: `catalog/keys.json` = `{"keys": [{"id": "...", "pub": "<base64>", "comment": "..."}]}`.
  The client also has them compiled in (`client/src/trusted_keys.h`); the compiled list is
  the one that counts, keys.json is for the server and CI.
- Publishing flow: approve (admin page) or merge (PR) stages the manifest; the maintainer
  pulls, runs `sign manifests`, commits the `.sig` files, pushes. Until then the entry is
  "waiting for signature" and the app doesn't show it.

In `/api/catalog`, each app object gets one extra key:

```json
"signed": { "manifest": "<base64 of the raw <id>.json bytes>", "key": "<key id>", "sig": "<base64 signature>" }
```

The server only adds it when the `.sig` verifies against a key in `keys.json`, and omits it
otherwise. The client verifies the signature itself against its compiled-in keys, then parses
the manifest **from the signed bytes** and ignores the server's copy of the fields. Entries
without a valid signature are hidden (dev override: env `AEROSTORE_ALLOW_UNSIGNED=1`).

