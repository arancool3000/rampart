// Fixed list; each module fills in its own SelfTest+<Module>.swift file.
extension SelfTest {
    static var moduleSuites: [(String, () -> Void)] {
        [
            ("engine", SelfTest.engine),
            ("yara", SelfTest.yara),
            ("signing", SelfTest.signing),
            ("telemetry", SelfTest.telemetry),
            ("behaviour", SelfTest.behaviour),
            ("remediation", SelfTest.remediation),
            ("network", SelfTest.network),
            ("posture", SelfTest.posture),
            ("daemon", SelfTest.daemon),
        ]
    }
}
