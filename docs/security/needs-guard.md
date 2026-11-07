# needs-guard — fix proposals from attack set X4 (do NOT edit production source; owner = G1/Fable)

Source: `Sources/rampart-selftest/SelfTest+AttackX4.swift`, `docs/security/attacks-X4.md`.
All three are in `Sources/RampartGuard/TamperProtection.swift` (+ a small clock-monotonicity helper).

## 1. (High) Unqualified `tccutil reset SystemPolicyAllFiles` revokes our FDA undetected — X4.8

`TamperDetector.inspectExec` only reaches the `resetters` (`tccutil`/`profiles`) branch after `mentionsUs`
is true, and `mentionsUs` requires the command line to contain our label / "rampart" / a protected path.
`tccutil reset SystemPolicyAllFiles` (no bundle id) resets **every** app's Full Disk Access — including
RamPart's — but is ignored.

Proposed fix: treat a `tccutil reset` of an FDA-bearing service as tampering even when unqualified.

```swift
// in inspectExec, BEFORE the `guard mentionsUs else { return [] }` line:
if tool == "tccutil", args.dropFirst().first == "reset" {
    let service = args.dropFirst(2).first ?? ""
    let global = ["SystemPolicyAllFiles", "All", "Accessibility", "ScreenCapture"].contains(service)
    // unqualified (no bundle id operand) OR explicitly naming us
    let bundleOperand = args.dropFirst(3).first
    if global, bundleOperand == nil || paths.isOurLabel(bundleOperand ?? "") {
        guard dedupe("tccreset:\(p.pid)", at: ev.date) else { return [] }
        return [detection(.fileTamper, severity: .high, score: 80,
                          title: "tccutil reset would strip \(Product.name)'s Full Disk Access",
                          detail: joined + " (resets all apps; \(Product.name) loses FDA too)", ev: ev, path: nil)]
    }
}
```

Self-test (add to `attackX4Checks` once merged): the unqualified reset now yields one high detection.

## 2. (Medium) Clock changes are not detected — X4.9

Rolling the clock expires remote-access allowances, defeats signature/definition freshness, re-opens token
windows, and (with finding #4 below) pins an authenticated session open. No clock-setting tool is watched.

Proposed fix: add a `clockTamper` `TamperKind` and flag the exec of clock tools (defensive alert; macOS
lets admins set the clock, so this is detect-and-explain, not block):

```swift
public static let clockTools: Set<String> = ["systemsetup", "sntp", "date", "ntpdate"]
// in inspectExec, before mentionsUs:
if Self.clockTools.contains(tool) {
    let sets = (tool == "systemsetup" && (lower.contains("-setdate") || lower.contains("-settime") || lower.contains("-setusingnetworktime")))
            || (tool == "date" && args.dropFirst().contains { !$0.hasPrefix("-") && $0.rangeOfCharacter(from: .decimalDigits) != nil })
            || tool == "sntp" || tool == "ntpdate"
    if sets, dedupe("clock:\(p.pid)", at: ev.date) {
        return [detection(.configTamper, severity: .medium, score: 55,
                          title: "System clock is being changed",
                          detail: joined + " — can expire \(Product.name) allowances and definition freshness", ev: ev, path: nil)]
    }
}
```
(`TamperKind.clockTamper` + a `.medium` Severity path if not already present.)

## 3. (Medium) Time-boxed trust uses wall clock only — X4.18

`ProtectionDisableFlow.hasActiveSession` / `redeem` compare `clock.now()` to a stored `Date`. A backward
wall-clock jump keeps a redeemed `.uninstall`/`.pause` session (during which the actor's tamper is exempt)
alive indefinitely; a forward jump expires allowances early.

Proposed fix: anchor session/token lifetimes to a **monotonic** source and require BOTH wall-clock and
monotonic to be within bounds. Minimal change:

```swift
// store issuedAtMono = DispatchTime.now().uptimeNanoseconds alongside each session/token
// hasActiveSession: valid only if clock.now() <= until AND (nowMono - issuedMono) <= sessionSeconds
```
This makes a backward jump unable to extend trust (monotonic still advances) and a forward jump unable to
shorten it below the real elapsed time. Add a self-test that rolls the injected `GuardClock` backward and
asserts the session still expires on the monotonic budget.
