import Foundation
import RampartShared

// Self-test runner. Command Line Tools ship no usable XCTest or Swift Testing macros,
// so each module registers checks in its own file in this folder: SelfTest+<Module>.swift.
// Each file adds an extension with a static func and appends it in `allSuites` below.

var failures = 0
var passes = 0
func check(_ cond: @autoclosure () -> Bool, _ name: String, file: String = #fileID, line: Int = #line) {
    if cond() { passes += 1 } else { failures += 1; print("FAIL \(name) (\(file):\(line))") }
}

enum SelfTest {
    static func shared() {
        check(Product.name == "RamPart", "product name")
        let d = Detection(name: "x", category: .test, severity: .low, confidence: 50, evidence: [])
        let data = try! JSONEncoder.rampart.encode(d)
        check((try? JSONDecoder.rampart.decode(Detection.self, from: data))?.id == d.id, "detection codable")
    }
}

let filter = CommandLine.arguments.dropFirst().first
var suites: [(String, () -> Void)] = [("shared", SelfTest.shared)]
suites += SelfTest.moduleSuites
for (name, run) in suites where filter == nil || filter == name {
    print("== \(name)"); run()
}
print("\(passes) passed, \(failures) failed")
exit(failures == 0 ? 0 : 1)
