import Foundation

// Entry point of the .appex executable. App extensions start through Foundation's
// NSExtensionMain, which reads NSExtensionPrincipalClass from Info.plist and serves XPC
// requests from Safari. The symbol is exported by Foundation but not declared for Swift.
@_silgen_name("NSExtensionMain")
func NSExtensionMain(_ argc: Int32, _ argv: UnsafePointer<UnsafeMutablePointer<CChar>?>) -> Int32

exit(NSExtensionMain(CommandLine.argc, CommandLine.unsafeArgv))
