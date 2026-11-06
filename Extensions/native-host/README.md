# Native messaging host manifests (templates)

`rampart-nmh` is launched by Chromium browsers through Chrome's native messaging protocol.
Each browser looks for a JSON manifest named after the host (`app.rampart.nmh.json`) in its own folder.
These templates are identical in content; the build/install scripts (owned by the daemon/packaging agent)
copy one to each browser's folder after replacing:

- `__NMH_PATH__` → absolute path of the `rampart-nmh` binary inside `RamPart.app/Contents/MacOS/rampart-nmh`
- `__EXTENSION_ID__` → the extension's ID. For an unpacked extension Chrome derives the ID from the folder path;
  for a Web Store build it is fixed. Multiple origins may be listed in `allowed_origins`.

Per-user install locations (no admin needed; never done during development):

| Browser  | Manifest folder |
|----------|-----------------|
| Chrome   | `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/` |
| Chromium | `~/Library/Application Support/Chromium/NativeMessagingHosts/` |
| Brave    | `~/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts/` |
| Edge     | `~/Library/Application Support/Microsoft Edge/NativeMessagingHosts/` |
| Arc      | `~/Library/Application Support/Arc/User Data/NativeMessagingHosts/` |
| Vivaldi  | `~/Library/Application Support/Vivaldi/NativeMessagingHosts/` |

System-wide equivalents live under `/Library/Google/Chrome/NativeMessagingHosts/`, `/Library/Microsoft/Edge/NativeMessagingHosts/`, etc.
The file must be named exactly `app.rampart.nmh.json` in the destination.

Safari does not use these: its extension talks to the `SafariWebExtensionHandler` inside the app's `.appex` (see `Extensions/safari/README.md`).

Install the extension itself (Chrome/Brave/Edge/Arc): `chrome://extensions` → Developer mode → Load unpacked → `Extensions/chromium`.
Then note the ID shown on the card and put it in the manifest. Test the host from a shell with
`printf '\x10\x00\x00\x00{"type":"ping"}' | rampart-nmh | tail -c +5`.
