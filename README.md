# RamPart

A free, open-source security app for macOS: real-time malware protection, scans, and a friendly pixel guard watching over your Mac.

## What it does

- **Real-time protection**: watches file, process and network activity (eslogger, FSEvents, process sweeps) and scans new files with YARA rules and heuristics, including inside archives and packed files.
- **Scans**: quick and full scans, quarantine and restore.
- **Calm alerts**: findings are sorted into *Needs you*, *Handled* and *FYI*, so real problems don't get buried.
- **Protection Activity**: every event is listed, with full details on click.
- **Cat & Mouse deception**: bait files and a decoy port that catch snooping malware.
- **Download Gate, Camera/Mic Guard, App Firewall, scam link checks.**
- **Emergency lockdown with a Touch ID kill switch** that always lifts it.
- **Desktop Mode**: an animated RamPart desktop with live protection widgets.

RamPart only claims what it actually does. Network use is limited to: optional Gemini AI help (your own key, stored in the Keychain), Pwned Passwords k-anonymity checks, DNS-over-HTTPS, and blocklist/definition downloads.

## Build

Requires macOS and the Swift Command Line Tools (no Xcode needed).

```sh
./scripts/build.sh --quick        # app bundle in dist/RamPart.app
swift run rampart-selftest        # self-tests
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for how the pieces fit together.

## Status

Early and in active development. Windows and iOS versions are planned.

## License

MIT, see [LICENSE](LICENSE).
