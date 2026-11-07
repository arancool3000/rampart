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
            ("guard", SelfTest.guardSuite),
            ("web", SelfTest.web),
            ("vault", SelfTest.vault),
            ("ai", SelfTest.ai),
            ("netscan", SelfTest.netscan),
            ("publicwifi", SelfTest.publicWiFiChecks),
            ("fp1", SelfTest.fp1Checks),
            ("sandbox", SelfTest.sandboxChecks),
        ]
    }
}
