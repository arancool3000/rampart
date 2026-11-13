// Default behaviour rule file (data, not code). Override at runtime with RuleSet.load(from:).
// Rule IDs follow docs/research/05 §14 (R01–R58); L/M/RW IDs are extra LOLBin, marker and ransomware rules.
enum DefaultRules {
    static let json = #"""
{
  "version": "2026.11.2",
  "lists": {
    "shells": ["(ba|z|da|k|tc|c)?sh", "fish", "pwsh"],
    "interpreters": ["python[0-9.]*", "Python", "perl[0-9.]*", "ruby", "node", "osascript", "php", "tclsh[0-9.]*", "deno", "bun", "lua", "expect"],
    "scriptHosts": ["osascript", "Script Editor", "Script Debugger", "ScriptMonitor"],
    "browsers": ["Google Chrome( Helper.*)?", "Safari", "com\\.apple\\.WebKit\\..*", "Brave Browser( Helper.*)?", "Microsoft Edge( Helper.*)?", "Arc( Helper.*)?", "firefox", "Firefox", "plugin-container", "Opera( Helper.*)?", "Vivaldi( Helper.*)?", "Chromium( Helper.*)?", "Orion", "Zen( Browser)?", "Comet( Helper.*)?", "Dia( Helper.*)?"],
    "terminals": ["Terminal", "iTerm2", "iTerm", "Warp", "stable", "WezTerm", "wezterm-gui", "Alacritty", "kitty", "Ghostty", "Hyper", "tmux", "screen", "sshd", "sshd-session"],
    "editors": ["vim?", "nvim", "nano", "pico", "emacs.*", "code", "Code( Helper.*)?", "Cursor( Helper.*)?", "TextEdit", "BBEdit", "sublime_text", "Sublime Text", "zed", "Zed", "Xcode", "mate", "micro", "hx", "helix", "Nova", "CotEditor"],
    "installers": ["installer", "installd", "system_installd", "package_script_service", "Installer", "softwareupdated", "mdmclient", "Jamf.*", "jamf", "Kandji.*", "brew", "conda", "pyenv", "rustup(-init)?", "volta", "mise", "asdf", "fnm", "uv", "pixi", "chezmoi", "stow", "yadm", "nix.*", "git"],
    "devtools": ["swift-build", "swift", "swift-frontend", "swiftc", "cargo", "rustc", "go", "node", "npm", "npx", "pnpm", "yarn", "bun", "deno", "make", "gmake", "cmake", "ninja", "clang(\\+\\+)?", "ld", "python[0-9.]*", "pip[0-9.]*", "uv", "poetry", "gradle.*", "java", "mvn", "dotnet", "xcodebuild", "Code Helper.*", "Cursor Helper.*", "Electron", "git", "brew", "bundle", "rake", "gem", "docker", "claude", "codex"],
    "officeApps": ["Microsoft (Word|Excel|PowerPoint|Outlook)", "Pages", "Numbers", "Keynote", "Preview", "Adobe Acrobat.*", "AdobeAcrobat", "Acrobat.*"],
    "memoryTools": ["lldb", "lldb-rpc-server", "gdb", "vmmap", "leaks", "sample", "heap", "malloc_history", "footprint", "stringdups", "lsmp", "dtrace", "dtruss", "frida.*", "debugserver"],
    "minerArgs": ["stratum\\+(tcp|ssl|tls)://", "--donate-level", "(^|\\s)(-o|--url)(\\s+|=)\\S+:(3333|4444|5555|7777|14444|14433|45700)\\b", "--randomx", "--coin(\\s+|=)(monero|xmr)\\b", "--cpu-max-threads-hint", "\\bxmrig\\b"],
    "passwordManagers": ["1Password.*", "Bitwarden.*", "Dashlane.*", "KeePassXC", "Enpass", "LastPass", "Keeper.*", "Proton Pass"],
    "backup": ["Backblaze.*", "bztransmit", "bzfilelist", "Arq.*", "backupd", "CCC.*", "Carbon Copy Cloner", "Dropbox.*", "bird", "cloudd", "fileproviderd", "Google Drive.*", "OneDrive.*", "mds", "mds_stores", "mdworker.*", "mdworker_shared", "Time Machine", "rampartd", "rampart"],
    "fetchers": ["curl", "wget", "nscurl", "aria2c", "fetch", "http", "xh"],
    "archivers": ["ditto", "zip", "tar", "bsdtar", "gzip", "7z", "7za", "7zz", "rar", "aa", "hdiutil"],
    "uploaders": ["curl", "wget", "nc", "ncat", "python[0-9.]*", "scp", "rsync", "sftp", "ftp", "nscurl"],
    "messagingApps": ["Telegram.*", "Discord.*", "Slack.*", "WhatsApp.*", "Signal.*"],
    "torApps": ["tor", "Tor Browser", "firefox", "obfs4proxy", "snowflake-client", "lyrebird", "Orbot.*"],
    "recon": ["system_profiler", "sw_vers", "ioreg", "sysctl", "uname", "csrutil", "kextstat", "hostinfo", "dscl", "scutil", "sysadminctl", "pmset", "lsappinfo", "spctl"],
    "installerHosts": ["raw\\.githubusercontent\\.com/(Homebrew|nvm-sh|ohmyzsh|rbenv|pyenv|Jarred-Sumner|tj|starship|junegunn)/", "brew\\.sh", "sh\\.rustup\\.rs", "astral\\.sh/(uv|ruff)", "install\\.python-poetry\\.org", "bun\\.sh/install", "deno\\.land/install", "get\\.sdkman\\.io", "fnm\\.vercel\\.app", "claude\\.ai/install", "mise\\.run", "tailscale\\.com/install", "ollama\\.com/install", "nixos\\.org/nix/install", "install\\.determinate\\.systems", "get\\.pnpm\\.io", "starship\\.rs/install", "pyenv\\.run", "rvm\\.io", "volta\\.sh"],
    "sensitivePaths": [
      "Library/Keychains/",
      "Library/Application Support/(Google/Chrome|BraveSoftware/Brave-Browser|Microsoft Edge|Arc/User Data|Vivaldi|com\\.operasoftware\\.Opera[^/]*|Chromium|Yandex/YandexBrowser)/.*(Login Data|Cookies|Web Data|Local State|Local Extension Settings|IndexedDB)",
      "Library/Application Support/Firefox/Profiles/[^/]+/(logins\\.json|key4\\.db|cookies\\.sqlite|formhistory\\.sqlite)",
      "Library/Cookies/",
      "Library/Group Containers/group\\.com\\.apple\\.notes",
      "Telegram Desktop/tdata",
      "Library/Application Support/(Exodus|Electrum|atomic|Atomic Wallet|Ledger Live|Coinomi|Guarda|Wasabi|Bitcoin|Monero|Binance|TrustWallet)/",
      "/\\.electrum/",
      "/\\.ssh/id_[a-z0-9_]+(\\s|$|\")",
      "/\\.aws/credentials",
      "/\\.config/gcloud/",
      "/\\.kube/config",
      "/\\.config/gh/hosts\\.yml",
      "/\\.npmrc$|/\\.npmrc(\\s|\")",
      "/\\.pypirc(\\s|$|\")",
      "/\\.docker/config\\.json",
      "/\\.git-credentials(\\s|$|\")",
      "/\\.netrc(\\s|$|\")",
      "/\\.gnupg/",
      "/\\.(zsh|bash)_history(\\s|$|\")",
      "Library/Messages/chat\\.db",
      "Library/Safari/(History\\.db|Form Values)",
      "\\.kdbx(\\s|$|\")",
      "/\\.config/solana/",
      "Library/Application Support/[Rr]am[Pp]art/(Vault|Chats)(/|\\s|$|\")",
      "\\.rpvault(\\s|$|\")",
      "Local Extension Settings/(nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa|ejbalbakoplchlghecdalmeeeajnimhm|hnfanknocfeofbddgcijnmhnfnkdnaad|fhbohimaelbohpjbbldcngcnapndodjp|egjidjbpglichdcondbcbdnbeeppgdph|acmacodkjbdgmoleebolmdjonilkdbch|aholpfdialjgjfhomihkjbmgjidlcdno)"
    ],
    "sshDirArg": ["/\\.ssh/?(\\s|$|\")", "(^|\\s)\\.ssh/?(\\s|$)", "/\\.ssh/id_[a-z0-9_]+(\\s|$|\")"],
    "appleCredReaders": ["@interpreters", "sqlite3", "cp", "ditto", "cat", "tar", "bsdtar", "zip", "rsync", "scp", "curl", "base64", "xxd", "strings", "head", "tail", "dd", "openssl", "plutil", "security"],
    "securityTools": ["(?i)(rampart|lulu|blockblock|little ?snitch|knockknock|oversight|reikey|xprotect|malwarebytes|sentinel(one|d)|crowdstrike|falcon|jamf ?protect|sophos|avast|norton|bitdefender|intego|clamav|eset)"],
    "browserRegex": ["(?i)(chrome|safari|firefox|brave|edge|arc|opera|vivaldi|chromium|orion|webkit)"]
  },
  "rules": [
    {"id": "R01", "name": "Canary document modified", "type": "strong", "category": "ransomware", "score": 95, "stage": "impact", "subject": "actor", "alwaysActive": true, "builtin": true,
     "why": "A Rampart decoy document was modified, renamed or deleted. Nothing legitimate should touch these files; ransomware walks folders and hits them early."},
    {"id": "R02", "name": "Encrypted-output burst", "type": "strong", "category": "ransomware", "score": 85, "stage": "impact", "subject": "actor", "alwaysActive": true, "builtin": true,
     "why": "Many user files were rewritten with random-looking (encrypted) content in a short time."},
    {"id": "R03", "name": "Document rewritten as random data", "type": "strong", "category": "ransomware", "score": 80, "stage": "impact", "subject": "actor", "builtin": true,
     "why": "A file that was a valid document or image is now random-looking data, the signature of encryption in place."},
    {"id": "R04", "name": "Mass rename to a new extension", "type": "weak", "category": "ransomware", "score": 55, "stage": "impact", "subject": "actor", "builtin": true,
     "why": "Many user files were renamed to the same unfamiliar extension within a minute."},
    {"id": "R05", "name": "Ransom-note pattern", "type": "weak", "category": "ransomware", "score": 50, "stage": "impact", "subject": "actor", "builtin": true,
     "why": "The same text/HTML file name appeared in many folders within two minutes, as ransom notes do."},
    {"id": "RW1", "name": "Mass file modification velocity", "type": "weak", "category": "ransomware", "score": 40, "stage": "impact", "subject": "actor", "builtin": true,
     "why": "One process modified many user files across several folders in seconds."},
    {"id": "R06", "name": "Backup or snapshot tampering", "type": "strong", "category": "ransomware", "score": 75, "stage": "impact", "subject": "lineage", "interactiveFactor": 0.4,
     "why": "Time Machine backups or local APFS snapshots were deleted or disabled by a non-interactive process chain.",
     "matchers": [
       {"kinds": ["exec"], "process": ["tmutil"], "argsAny": ["\\b(delete|deletelocalsnapshots|thinlocalsnapshots|disable|deleteinprogress)\\b"]},
       {"kinds": ["exec"], "process": ["diskutil"], "argsAny": ["apfs\\s+deletesnapshot"]}
     ]},
    {"id": "R07", "name": "New launch item runs untrusted code", "type": "strong", "category": "persistence", "score": 70, "stage": "persistence", "subject": "target", "alwaysActive": true, "builtin": true,
     "why": "A new LaunchAgent/LaunchDaemon starts a program that is unsigned, ad-hoc signed, or lives in a temporary or hidden folder."},
    {"id": "R07L", "name": "Launch item runs your own unsigned script", "type": "weak", "category": "persistence", "score": 25, "stage": "persistence", "subject": "target", "alwaysActive": true, "builtin": true,
     "why": "A LaunchAgent starts an unsigned script or tool kept in your own home folder, with no sign of malicious behaviour. Logged for review only."},
    {"id": "R08", "name": "Launch item written by a script chain", "type": "sequence", "category": "persistence", "score": 80, "stage": "persistence", "subject": "lineage", "devSensitive": true,
     "why": "A shell or script interpreter descended from a browser, a pasted Terminal command or untrusted code wrote or loaded a launchd plist.",
     "matchers": [
       {"kinds": ["fileCreate", "fileWrite", "fileRename"], "path": ["/Library/Launch(Agents|Daemons)/[^/]+\\.plist$"], "pathNot": ["homebrew\\.mxcl\\."], "process": ["@shells", "@interpreters", "cp", "mv", "tee", "ditto", "cat", "curl", "wget", "defaults", "plutil", "PlistBuddy", "echo", "printf"], "ancestor": ["@browsers", "@scriptHosts"]},
       {"kinds": ["fileCreate", "fileWrite", "fileRename"], "path": ["/Library/Launch(Agents|Daemons)/[^/]+\\.plist$"], "pathNot": ["homebrew\\.mxcl\\."], "process": ["@shells", "@interpreters", "cp", "mv", "tee", "ditto", "cat", "curl", "wget", "defaults", "plutil", "PlistBuddy", "echo", "printf"], "requireMark": {"name": "pasteEntry", "scope": "global", "window": 600}},
       {"kinds": ["fileCreate", "fileWrite", "fileRename"], "path": ["/Library/Launch(Agents|Daemons)/[^/]+\\.plist$"], "pathNot": ["homebrew\\.mxcl\\."], "lineageUntrusted": true},
       {"kinds": ["exec"], "process": ["launchctl"], "args": ["\\b(load|bootstrap|submit)\\b"], "argsNot": ["homebrew\\.mxcl\\."], "lineageUntrusted": true},
       {"kinds": ["fileCreate", "fileWrite", "fileRename"], "path": ["/Library/Launch(Agents|Daemons)/~\\$[^/]*\\.plist$"]},
       {"kinds": ["fileCreate", "fileWrite", "fileRename"], "path": ["/Library/Launch(Agents|Daemons)/[^/]+\\.plist$"], "ancestor": ["@officeApps"]}
     ]},
    {"id": "R09", "name": "Launch item injects a dylib", "type": "strong", "category": "persistence", "score": 75, "stage": "persistence", "subject": "lineage", "builtin": true,
     "why": "A launchd job sets DYLD_* environment variables, which injects code into the launched program.",
     "matchers": [
       {"kinds": ["exec"], "process": ["launchctl"], "args": ["setenv\\s+DYLD_"]}
     ]},
    {"id": "R10", "name": "New login item runs untrusted code", "type": "weak", "category": "persistence", "score": 45, "stage": "persistence", "subject": "target", "builtin": true,
     "why": "A new background or login item (BTM) points at an unsigned, ad-hoc or temp-located executable."},
    {"id": "R11", "name": "New cron or periodic job", "type": "weak", "category": "persistence", "score": 50, "stage": "persistence", "subject": "lineage", "builtin": true, "interactiveFactor": 0.6,
     "why": "A cron, at or periodic job was added. These are rare on modern macOS and are used for stealthy persistence.",
     "matchers": [
       {"kinds": ["exec"], "process": ["crontab"], "argsNot": ["\\s-(l|e|r)\\b"]},
       {"kinds": ["exec"], "process": ["at", "batch"], "argsNot": ["\\s-(l|r|d)\\b"]},
       {"kinds": ["exec"], "process": ["launchctl"], "args": ["\\b(load|enable|bootstrap)\\b.*com\\.apple\\.atrun"]},
       {"kinds": ["fileCreate", "fileWrite", "fileRename"], "path": ["^(/private)?/usr/lib/cron/(tabs|jobs)/", "^(/private)?/etc/crontab$", "^(/private)?/etc/periodic/", "^/usr/local/etc/periodic/", "^(/private)?/etc/periodic\\.conf"], "processNot": ["cron", "atrun", "periodic", "crontab", "@installers"]},
       {"kinds": ["fileCreate", "fileWrite", "fileRename"], "path": ["^(/private)?/var/at/(tabs|jobs)/"], "processNot": ["cron", "atrun", "@installers"]}
     ]},
    {"id": "R12", "name": "Shell startup file gains a fetch or hidden-exec line", "type": "strong", "category": "persistence", "score": 70, "stage": "persistence", "subject": "lineage", "builtin": true,
     "why": "A line added to a shell startup file downloads remote content, runs something from a hidden or temp path, decodes an encoded blob, exports DYLD_* or overrides sudo/ssh."},
    {"id": "R13", "name": "Shell startup file modified by a non-shell process", "type": "weak", "category": "persistence", "score": 35, "stage": "persistence", "subject": "actor",
     "why": "A shell startup file was changed by a process that is not an editor, a shell, a terminal or a known installer.",
     "matchers": [
       {"kinds": ["fileWrite", "fileCreate", "fileRename"], "path": ["/\\.(zshenv|zprofile|zshrc|zlogin|zlogout|bash_profile|bashrc|profile|bash_login)$", "^(/private)?/etc/(zshrc|zprofile|zshenv|profile|bashrc)$"], "processNot": ["@shells", "@editors", "@installers", "@terminals", "@devtools", "cp", "mv", "tee", "cat", "sed", "awk", "perl"]}
     ]},
    {"id": "R14", "name": "New SSH authorized key", "type": "strong", "category": "backdoor", "score": 70, "stage": "persistence", "subject": "lineage", "alwaysActive": true, "interactiveFactor": 0.5,
     "why": "A key was added to ~/.ssh/authorized_keys outside an interactive ssh or editor session, granting remote login.",
     "matchers": [
       {"kinds": ["fileCreate", "fileWrite", "fileRename"], "path": ["/\\.ssh/authorized_keys2?$"], "processNot": ["@editors", "ssh-copy-id", "sshd", "sshd-session"], "ancestorNot": ["ssh-copy-id", "@editors"]},
       {"kinds": ["exec"], "process": ["tee", "cp", "mv", "ditto", "sed", "dd"], "args": ["/\\.ssh/authorized_keys2?(\\s|$)"], "ancestorNot": ["ssh-copy-id", "@editors"]}
     ]},
    {"id": "R15", "name": "Remote Login enabled", "type": "weak", "category": "backdoor", "score": 45, "stage": "persistence", "subject": "lineage", "interactiveFactor": 0.6,
     "why": "SSH Remote Login was switched on from the command line rather than System Settings.",
     "matchers": [
       {"kinds": ["exec"], "process": ["systemsetup"], "args": ["-setremotelogin\\s+on"]},
       {"kinds": ["exec"], "process": ["launchctl"], "args": ["\\b(load|enable|bootstrap)\\b.*(ssh\\.plist|com\\.openssh\\.sshd)"]},
       {"kinds": ["exec"], "process": ["kickstart"], "argsAny": ["(^|\\s)-activate\\b", "-access\\s+-on\\b"]},
       {"kinds": ["exec"], "process": ["launchctl"], "args": ["\\b(load|enable|bootstrap)\\b.*com\\.apple\\.screensharing"]}
     ]},
    {"id": "R16", "name": "Sudoers or authorization database changed", "type": "strong", "category": "backdoor", "score": 75, "stage": "evasion", "subject": "lineage", "interactiveFactor": 0.5,
     "why": "sudo rules or the authorization database were modified outside an installer, which can grant silent root.",
     "matchers": [
       {"kinds": ["fileCreate", "fileWrite", "fileRename"], "path": ["^(/private)?/etc/sudoers(\\.d/.*)?$"], "processNot": ["visudo", "@installers"]},
       {"kinds": ["exec"], "process": ["security"], "args": ["authorizationdb\\s+write"]},
       {"kinds": ["exec"], "process": ["tee"], "args": ["/etc/sudoers"]},
       {"kinds": ["fileCreate", "fileWrite", "fileRename"], "path": ["^(/private)?/etc/pam\\.d/", "^/usr/local/lib/pam/"], "processNot": ["@installers"]},
       {"kinds": ["exec"], "process": ["cp", "mv", "tee", "sed", "ditto", "ln", "install"], "args": ["/etc/pam\\.d/|/usr/local/lib/pam/"]}
     ]},
    {"id": "R16b", "name": "Hidden or new admin account", "type": "strong", "category": "backdoor", "score": 75, "stage": "persistence", "subject": "lineage", "alwaysActive": true, "interactiveFactor": 0.5,
     "why": "A user account was created from the command line, hidden from the login window, or added to the admin group: a classic way to keep a backdoor login.",
     "matchers": [
       {"kinds": ["exec"], "process": ["sysadminctl"], "args": ["-addUser\\b"]},
       {"kinds": ["exec"], "process": ["dscl"], "args": ["-create\\s+/Users/\\S+(\\s+IsHidden\\s+1|\\s+UniqueID\\s+[0-4]\\d\\d\\b)"]},
       {"kinds": ["exec"], "process": ["dseditgroup"], "args": ["-a\\s+\\S+.*\\badmin\\b"]},
       {"kinds": ["exec"], "process": ["dscl"], "args": ["-append\\s+/Groups/admin\\s+GroupMembership"]}
     ]},
    {"id": "R17", "name": "Authorization or directory-services plugin added", "type": "strong", "category": "backdoor", "score": 80, "stage": "credential", "subject": "target",
     "why": "A bundle was placed in SecurityAgentPlugins or DirectoryServices PlugIns, where it can see login passwords.",
     "matchers": [
       {"kinds": ["fileCreate", "fileRename"], "path": ["^/Library/Security/SecurityAgentPlugins/[^/]+$", "^/Library/DirectoryServices/PlugIns/[^/]+$"], "processNot": ["@installers"]}
     ]},
    {"id": "R18", "name": "Login or logout hook set", "type": "strong", "category": "persistence", "score": 70, "stage": "persistence", "subject": "lineage",
     "why": "A legacy loginwindow LoginHook/LogoutHook was set; it runs a script as root at every login.",
     "matchers": [
       {"kinds": ["exec"], "process": ["defaults"], "args": ["write", "com\\.apple\\.loginwindow", "(LoginHook|LogoutHook)"]}
     ]},
    {"id": "R19", "name": "Dock tile hijack", "type": "strong", "category": "malware", "score": 75, "stage": "persistence", "subject": "none", "builtin": true,
     "why": "A Dock icon opens an app outside /Applications, ~/Applications and /System, or an app whose bundle ID differs from the one the tile claims: a look-alike launcher."},
    {"id": "R20", "name": "Browser extension sideloaded or force-installed", "type": "strong", "category": "adware", "score": 70, "stage": "persistence", "subject": "lineage", "builtin": true,
     "why": "A browser extension was installed outside the web store, or a force-install policy was written outside MDM.",
     "matchers": [
       {"kinds": ["exec"], "process": ["defaults"], "args": ["write", "com\\.(google\\.chrome|brave\\.browser|microsoft\\.edgemac|vivaldi|operasoftware)", "(ExtensionInstallForcelist|ExtensionInstallSources|ExtensionSettings|ExtensionInstallAllowlist)"]},
       {"kinds": ["fileCreate", "fileWrite", "fileRename"], "path": ["^/Library/Managed Preferences/.*com\\.(google\\.Chrome|brave\\.Browser|microsoft\\.Edge).*\\.plist$", "^/Library/Preferences/com\\.(google\\.Chrome|brave\\.Browser|microsoft\\.Edge)\\.plist$", "/distribution/policies\\.json$"], "processNot": ["mdmclient", "ManagedClient", "@installers"]},
       {"kinds": ["fileCreate", "fileWrite", "fileRename"], "path": ["/(Google/Chrome|BraveSoftware/Brave-Browser|Microsoft Edge|Chromium|Vivaldi)/External Extensions/[^/]+\\.json$", "^/Library/Application Support/[^/]+/(Chrome/)?External Extensions/"], "processNot": ["@browsers", "@installers", "mdmclient"]}
     ]},
    {"id": "R20L", "name": "Browser relaunched with a sideloaded extension", "type": "strong", "category": "adware", "score": 70, "stage": "persistence", "subject": "none",
     "why": "An untrusted program or a pasted command restarted the browser with --load-extension, which loads an unpacked extension that never went through the web store (Adload/Shlayer style).",
     "matchers": [
       {"kinds": ["exec"], "process": ["@browsers"], "argsAny": ["--load-extension=", "--disable-extensions-except="], "lineageUntrusted": true},
       {"kinds": ["exec"], "process": ["@browsers"], "argsAny": ["--load-extension=", "--disable-extensions-except="], "requireMark": {"name": "pasteEntry", "scope": "global", "window": 600}}
     ]},
    {"id": "R21", "name": "High-permission browser extension added", "type": "weak", "category": "adware", "score": 35, "stage": "persistence", "subject": "target", "builtin": true,
     "why": "A new browser extension requests access to all sites together with cookies, web requests or native messaging."},
    {"id": "R22", "name": "Native-messaging host points at untrusted code", "type": "strong", "category": "persistence", "score": 70, "stage": "persistence", "subject": "target", "builtin": true,
     "why": "A browser native-messaging host manifest launches an unsigned, ad-hoc or temp-located binary."},
    {"id": "R23", "name": "Configuration profile installed", "type": "strong", "category": "adware", "score": 80, "stage": "persistence", "subject": "lineage", "builtin": true, "interactiveFactor": 0.5,
     "why": "A configuration profile was installed outside the organisation's MDM; profiles can add root certificates, proxies, DNS and browser policies.",
     "matchers": [
       {"kinds": ["other", "persistenceAdded"], "detail": {"subsystem": "com\\.apple\\.ManagedClient", "message": "install(ed|ing)?\\b.*profile"}},
       {"kinds": ["exec"], "process": ["open"], "args": ["\\.mobileconfig\\b"], "lineageUntrusted": true},
       {"kinds": ["exec"], "process": ["open"], "args": ["\\.mobileconfig\\b"], "requireMark": {"name": "pasteEntry", "scope": "global", "window": 600}},
       {"kinds": ["exec"], "process": ["profiles"], "args": ["\\b(install|-I)\\b"], "lineageUntrusted": true}
     ]},
    {"id": "R24", "name": "New trusted root certificate", "type": "strong", "category": "suspicious", "score": 80, "stage": "evasion", "subject": "lineage", "alwaysActive": true, "interactiveFactor": 0.5,
     "why": "A certificate was added to the trust store; a rogue root CA lets an attacker intercept HTTPS.",
     "matchers": [
       {"kinds": ["exec"], "process": ["security"], "args": ["add-trusted-cert"]},
       {"kinds": ["exec"], "process": ["security"], "args": ["trust-settings-import"]},
       {"kinds": ["exec"], "process": ["security"], "args": ["add-certificates.*-k\\s+\\S*System\\.keychain"]}
     ]},
    {"id": "R25", "name": "Proxy, DNS or hosts redirect", "type": "weak", "category": "adware", "score": 50, "stage": "evasion", "subject": "lineage", "interactiveFactor": 0.6,
     "why": "System proxy, DNS servers or /etc/hosts entries were changed by a script rather than a VPN client or System Settings.",
     "matchers": [
       {"kinds": ["exec"], "process": ["networksetup"], "argsAny": ["-set(webproxy|securewebproxy|socksfirewallproxy|autoproxyurl|dnsservers|proxyautodiscovery)\\b"]},
       {"kinds": ["fileWrite", "fileCreate", "fileRename"], "path": ["^(/private)?/etc/hosts$", "^(/private)?/etc/resolver/"], "processNot": ["@editors", "@installers"]},
       {"kinds": ["exec"], "process": ["tee", "sed", "cp", "mv", "ditto"], "args": ["/etc/hosts\\b|/etc/resolver/"]},
       {"kinds": ["fileWrite", "fileCreate", "fileRename"], "path": ["^/Library/Preferences/SystemConfiguration/preferences\\.plist$"], "processNot": ["configd", "networksetup", "System Settings", "System Preferences", "@installers", "mdmclient", "rampartd"]},
       {"kinds": ["exec"], "process": ["scutil"], "argsNot": ["\\s--?(get|dns|proxy|nwi|r|w|nc|renew|g|cn)\\b"], "lineageUntrusted": true}
     ]},
    {"id": "R26", "name": "System extension from an unfamiliar developer", "type": "weak", "category": "suspicious", "score": 45, "stage": "persistence", "subject": "target", "builtin": true,
     "why": "A newly activated system extension belongs to a Team ID that was not present in the baseline."},
    {"id": "RP1", "name": "Hosts or DNS resolver hijack", "type": "strong", "category": "suspicious", "score": 70, "stage": "evasion", "subject": "none", "builtin": true,
     "why": "/etc/hosts or /etc/resolver gained an entry that blocks Apple's security updates or a security tool, or sends a bank, email or cloud site to another server."},
    {"id": "RP2", "name": "SSH login backdoor", "type": "strong", "category": "backdoor", "score": 70, "stage": "persistence", "subject": "none", "builtin": true, "interactiveFactor": 0.5,
     "why": "An SSH rc/environment file now runs commands at every SSH login, or sshd was set to take login keys from a program, allow root or empty passwords."},
    {"id": "RP3", "name": "Unsigned plug-in loaded by a system process", "type": "weak", "category": "suspicious", "score": 50, "stage": "persistence", "subject": "target", "builtin": true,
     "why": "An unsigned, ad-hoc or broken Spotlight importer, Quick Look generator, screen saver, Dock tile, audio or input plug-in, or kernel extension was added; macOS loads these into its own processes."},
    {"id": "RP4", "name": "Folder Action attached", "type": "weak", "category": "suspicious", "score": 45, "stage": "persistence", "subject": "none", "builtin": true,
     "why": "Folder Actions were turned on or changed, or a Folder Action script was added; the script runs whenever files land in the watched folder."},
    {"id": "RP5", "name": "Dylib injected through an app's launch environment", "type": "strong", "category": "malware", "score": 75, "stage": "persistence", "subject": "none", "builtin": true,
     "why": "An app's Info.plist LSEnvironment (or the login environment.plist) sets DYLD_*, so code is injected every time the app starts."},
    {"id": "RP6", "name": "Persistence hidden from view", "type": "weak", "category": "suspicious", "score": 45, "stage": "persistence", "subject": "none", "builtin": true,
     "why": "A launch item plist is hidden from Finder, or macOS will re-open an app from a temporary, hidden or shared folder at login."},
    {"id": "L01", "name": "Quarantine attribute stripped", "type": "weak", "category": "suspicious", "score": 25, "stage": "evasion", "subject": "lineage", "interactiveFactor": 0.5, "devSensitive": true,
     "why": "The com.apple.quarantine attribute was removed, which skips Gatekeeper's first-launch check.",
     "matchers": [
       {"kinds": ["exec"], "process": ["xattr"], "argsAny": ["(-d|-dr|-rd)\\s+com\\.apple\\.quarantine", "\\s-(c|cr|rc|rd|dr)\\b"], "setMark": {"name": "dequarantined", "from": "args", "window": 600}},
       {"kinds": ["xattrDelete"], "detail": {"xattr": "^com\\.apple\\.quarantine$"}, "setMark": {"name": "dequarantined", "from": "path", "window": 600}}
     ]},
    {"id": "R27", "name": "Quarantine removed then executed", "type": "sequence", "category": "suspicious", "score": 65, "stage": "execution", "subject": "actor", "devSensitive": true,
     "why": "An item had its quarantine attribute stripped and was then executed within 10 minutes, bypassing Gatekeeper.",
     "matchers": [
       {"kinds": ["exec"], "pathClass": ["downloads", "temp", "hidden", "volume", "translocated", "usersShared", "applications"], "requireMark": {"name": "dequarantined", "scope": "execPath", "window": 600}, "processNot": ["xattr"]}
     ]},
    {"id": "L02", "name": "Ad-hoc re-sign of a binary", "type": "marker", "category": "suspicious", "score": 0, "subject": "lineage",
     "why": "codesign --force --sign - (ad-hoc re-sign).",
     "matchers": [
       {"kinds": ["exec"], "process": ["codesign"], "args": ["(--sign|-s)\\s+-(\\s|$)", "(--force|-f)\\b"], "setMark": {"name": "adhocResigned", "from": "args", "window": 600}}
     ]},
    {"id": "R28", "name": "Ad-hoc re-signed then executed", "type": "sequence", "category": "suspicious", "score": 60, "stage": "execution", "subject": "actor", "devSensitive": true,
     "why": "A binary was force re-signed ad-hoc (the usual workaround for Gatekeeper's 'damaged' message) and then run.",
     "matchers": [
       {"kinds": ["exec"], "pathClass": ["downloads", "temp", "hidden", "volume", "translocated", "usersShared", "applications"], "requireMark": {"name": "adhocResigned", "scope": "execPath", "window": 600}, "processNot": ["codesign"]}
     ]},
    {"id": "R29", "name": "Untrusted code run from a temp or hidden folder", "type": "weak", "category": "suspicious", "score": 40, "stage": "execution", "subject": "actor", "devSensitive": true,
     "why": "An unsigned or ad-hoc signed program started from /tmp, a per-user temp folder, /Users/Shared or a hidden folder.",
     "matchers": [
       {"kinds": ["exec"], "pathClass": ["temp", "hidden", "usersShared"], "trust": "untrusted", "pathNot": ["/Sparkle/", "Autoupdate", "/\\.Sparkle", "/go-build[0-9]+/", "/TemporaryItems/NSIRD_"]},
       {"kinds": ["exec"], "pathClass": ["developer"], "trust": "untrusted", "quarantined": true},
       {"kinds": ["exec"], "pathClass": ["developer"], "trust": "untrusted", "storyMinScore": 60}
     ]},
    {"id": "R30", "name": "Remote content piped into an interpreter", "type": "weak", "category": "suspicious", "score": 40, "stage": "execution", "subject": "lineage", "devSensitive": true,
     "why": "A downloader's output was piped straight into a shell or script interpreter.",
     "matchers": [
       {"kinds": ["exec"], "process": ["@shells", "@interpreters"], "argsAny": ["\\b(curl|wget)\\b[^|]*\\|\\s*(sudo\\s+)?(/[^ ]*/)?((ba|z|da|k)?sh|python[0-9.]*|perl|ruby|osascript|node)\\b", "(eval|source)\\s+\"?\\$\\(\\s*(curl|wget)", "<\\(\\s*(curl|wget)", "-c\\s+\"?\\$\\(\\s*(curl|wget)"], "argsNot": ["@installerHosts"]},
       {"kinds": ["exec"], "process": ["@shells", "@interpreters"], "sibling": ["@fetchers"], "siblingWindow": 3, "siblingArgsNot": ["@installerHosts"], "parent": ["@shells"]}
     ]},
    {"id": "M01", "name": "Risky clipboard copied from a browser", "type": "marker", "category": "suspicious", "score": 0,
     "why": "Session agent classified a clipboard copy from a browser as a risky command.",
     "matchers": [
       {"kinds": ["other"], "detail": {"type": "^clipboard$", "class": "^risky$", "source_app": "(?i)(chrome|safari|firefox|brave|edge|arc|opera|vivaldi|chromium|orion|webkit)"}, "detailNot": {"clip_tokens": ".+"}, "setMark": {"name": "riskyClipboard", "from": "global", "window": 600}}
     ]},
    {"id": "R31", "name": "ClickFix: browser copy pasted into Terminal", "type": "sequence", "category": "malware", "score": 70, "stage": "entry", "subject": "lineage",
     "why": "A command classified as risky was copied from a web page and, within ten minutes, a Terminal shell ran a matching download/decode/script command.",
     "matchers": [
       {"kinds": ["exec"], "ancestor": ["@terminals"], "clipboardOverlap": 0.6, "argsNot": ["@installerHosts"], "setMark": {"name": "pasteEntry", "from": "global", "window": 600}},
       {"kinds": ["exec"], "ancestor": ["@terminals"], "argsAny": ["\\b(curl|wget)\\b", "base64\\s+(-d|--decode|-D)", "\\bosascript\\b", "\\bopenssl\\s+(enc|base64)\\b", "\\bpython[0-9.]*\\s+-c\\b.*\\b(exec|eval|b64decode|urlopen)\\b", "\\b(perl|ruby)\\s+-e\\b.*\\b(eval|decode_base64|unpack)\\b"], "argsNot": ["@installerHosts"], "requireMark": {"name": "riskyClipboard", "scope": "global", "window": 600}, "setMark": {"name": "pasteEntry", "from": "global", "window": 600}}
     ]},
    {"id": "R32", "name": "Apple paste warning overridden", "type": "strong", "category": "malware", "score": 65, "stage": "entry", "subject": "lineage",
     "why": "The user bypassed macOS's 'Possible malware, paste blocked' warning in Terminal.",
     "matchers": [
       {"kinds": ["other"], "detail": {"message": "paste.*(allowed|override|overrid|anyway|proceed)|possible malware.*paste"}, "detailNot": {"message": "paste.*blocked$"}, "setMark": {"name": "pasteEntry", "from": "global", "window": 600}}
     ]},
    {"id": "R33", "name": "Script Editor launched from a browser", "type": "weak", "category": "malware", "score": 55, "stage": "entry", "subject": "lineage",
     "why": "Script Editor was opened on behalf of a web browser (applescript:// link), a known ClickFix variant.",
     "matchers": [
       {"kinds": ["exec"], "process": ["Script Editor"], "ancestor": ["@browsers"], "setMark": {"name": "pasteEntry", "from": "global", "window": 600}},
       {"kinds": ["exec"], "process": ["Script Editor"], "detail": {"responsible_path": "(?i)(chrome|safari|firefox|brave|edge|arc|opera|vivaldi)"}, "setMark": {"name": "pasteEntry", "from": "global", "window": 600}},
       {"kinds": ["exec"], "process": ["@shells", "@fetchers", "osascript"], "ancestor": ["Script Editor", "ScriptMonitor"]}
     ]},
    {"id": "L08", "name": "Shell or interpreter spawned by a browser", "type": "weak", "category": "suspicious", "score": 50, "stage": "entry", "subject": "lineage",
     "why": "A web browser started a shell, script interpreter or downloader, which browsers do not normally do.",
     "matchers": [
       {"kinds": ["exec"], "process": ["@shells", "@interpreters", "@fetchers"], "ancestor": ["@browsers"], "ancestorNot": ["@terminals"], "setMark": {"name": "entry", "from": "story", "window": 1800}},
       {"kinds": ["exec"], "process": ["@shells", "@interpreters", "@fetchers"], "detail": {"responsible_path": "(?i)(chrome|safari|firefox|brave|edge|arc|opera|vivaldi|chromium|orion)"}, "ancestorNot": ["@terminals"], "setMark": {"name": "entry", "from": "story", "window": 1800}},
       {"kinds": ["exec"], "process": ["@shells", "@interpreters", "@fetchers"], "ancestor": ["@officeApps"], "ancestorNot": ["@terminals"], "setMark": {"name": "entry", "from": "story", "window": 1800}}
     ]},
    {"id": "L09", "name": "Untrusted code launched from a disk image", "type": "weak", "category": "suspicious", "score": 30, "stage": "entry", "subject": "actor",
     "why": "An unsigned or ad-hoc signed program was run from a mounted disk image, the usual fake-installer delivery.",
     "matchers": [
       {"kinds": ["exec"], "pathClass": ["volume", "translocated"], "trust": "untrusted", "setMark": {"name": "entry", "from": "story", "window": 1800}}
     ]},
    {"id": "R34", "name": "Script-host password dialog", "type": "strong", "category": "infostealer", "score": 75, "stage": "credential", "subject": "lineage", "alwaysActive": true,
     "why": "osascript displayed a dialog with a hidden-answer (password) field, the hallmark of macOS infostealers phishing the login password.",
     "matchers": [
       {"kinds": ["exec"], "process": ["osascript"], "args": ["display\\s+dialog", "hidden\\s+answer"]}
     ]},
    {"id": "R35", "name": "Local password validated by a script", "type": "strong", "category": "infostealer", "score": 75, "stage": "credential", "subject": "lineage", "interactiveFactor": 0.6,
     "why": "A script checked a password against the local directory (dscl -authonly) or unlocked the keychain with a password on the command line.",
     "matchers": [
       {"kinds": ["exec"], "process": ["dscl"], "args": ["-authonly"]},
       {"kinds": ["exec"], "process": ["security"], "args": ["unlock-keychain\\s+-p\\s"]}
     ]},
    {"id": "R36", "name": "Browser Safe Storage key requested", "type": "strong", "category": "infostealer", "score": 80, "stage": "credential", "subject": "lineage", "alwaysActive": true,
     "why": "The keychain CLI was asked for a browser's 'Safe Storage' key (which decrypts saved passwords and cookies) by something other than the browser.",
     "matchers": [
       {"kinds": ["exec"], "process": ["security"], "args": ["find-generic-password", "safe storage|-w?a\\s+\"?(chrome|brave|edge|opera|vivaldi|arc|chromium)"], "ancestorNot": ["@browsers"]},
       {"kinds": ["exec"], "process": ["security"], "args": ["dump-keychain"], "ancestorNot": ["@passwordManagers"]},
       {"kinds": ["exec"], "process": ["security"], "args": ["find-(generic|internet)-password", "app\\.rampart\\."], "ancestorNot": ["rampartd", "RamPart", "rampart", "RampartApp", "rampart-agent"]}
     ]},
    {"id": "R37", "name": "Credential store accessed by a foreign process", "type": "weak", "category": "infostealer", "score": 50, "stage": "credential", "subject": "lineage",
     "why": "A process that is not the owning browser/app, a password manager or a backup tool referenced browser, keychain, wallet or cloud-credential files.",
     "matchers": [
       {"kinds": ["exec"], "argsAny": ["@sensitivePaths"], "processNot": ["@browsers", "@passwordManagers", "@backup", "ssh", "ssh-add", "ssh-keygen", "scp", "git", "git-credential-.*", "gh", "docker.*", "gpg.*", "kubectl", "aws", "gcloud", "security", "@editors", "@shells", "rampartd", "RamPart"]},
       {"kinds": ["exec"], "argsAny": ["@sshDirArg"], "process": ["scp", "rsync", "sftp", "tar", "bsdtar", "zip", "ditto", "7z", "7zz", "cp"], "argsNot": ["\\.pub(\\s|$)"]},
       {"kinds": ["fileClose", "other"], "path": ["@sensitivePaths"], "processNot": ["@browsers", "@passwordManagers", "@backup", "@shells", "@terminals", "@devtools", "@installers", "ssh", "ssh-add", "ssh-agent", "git", "git-credential-.*", "gh", "docker.*", "gpg.*", "pinentry.*", "twine", "atuin", "fzf", "mcfly", "kubectl", "aws", "gcloud", "securityd", "secd", "trustd", "mds.*", "backupd", "cloudd", "Safari", "com\\.apple\\.WebKit\\..*", "SafariBookmarksSyncAgent", "Messages", "imagent", "IMDPersistenceAgent", "Keychain Access", "@editors", "rampartd", "RamPart"], "trust": "nonApple", "detailNot": {"modified": "^1$"}},
       {"kinds": ["fileClose", "other"], "path": ["@sensitivePaths"], "pathNot": ["/\\.(zsh|bash)_history$"], "process": ["@appleCredReaders"], "processNot": ["securityd", "secd", "trustd", "Keychain Access", "@backup"], "detailNot": {"modified": "^1$"}},
       {"kinds": ["fileClose", "other"], "path": ["@sensitivePaths"], "process": ["@devtools", "@interpreters"], "pathNot": ["/\\.(npmrc|pypirc|netrc|git-credentials)$", "/\\.docker/config\\.json$", "/\\.config/gh/", "/\\.(zsh|bash)_history$", "/\\.kube/config$", "/\\.config/gcloud/", "/\\.aws/"], "detailNot": {"modified": "^1$"}}
     ]},
    {"id": "R38", "name": "Credential-store copy staged in temp", "type": "strong", "category": "infostealer", "score": 80, "stage": "collection", "subject": "lineage", "alwaysActive": true,
     "why": "Files named like browser, keychain or wallet stores were created in a temp or hidden folder: credentials being staged for theft.",
     "matchers": [
       {"kinds": ["fileCreate", "fileRename", "fileWrite"], "path": ["^(/private)?/(tmp|var/folders|var/tmp)/.*/(Login Data|Cookies|Web Data|Local State|logins\\.json|key4\\.db|cookies\\.sqlite|login\\.keychain-db|wallet\\.dat)$", "^/Users/(Shared|[^/]+/\\.[^/]+)/.*/(Login Data|Cookies|Web Data|logins\\.json|key4\\.db|login\\.keychain-db|wallet\\.dat)$"], "processNot": ["@browsers", "@passwordManagers", "@backup"]},
       {"kinds": ["fileCreate", "fileRename", "fileWrite"], "path": ["^(/private)?/(tmp|var/folders|var/tmp)/.*\\.(rpvault|kdbx)$", "^/Users/(Shared|[^/]+/\\.[^/]+)/.*\\.(rpvault|kdbx)$"], "processNot": ["@passwordManagers", "@backup", "rampartd", "RamPart"]}
     ]},
    {"id": "R37S", "name": "SSH keys copied to another host", "type": "strong", "category": "infostealer", "score": 70, "stage": "exfil", "subject": "lineage", "interactiveFactor": 0.5,
     "why": "The whole ~/.ssh folder or a private key was copied to a remote host with scp/rsync, which hands an attacker your SSH logins.",
     "matchers": [
       {"kinds": ["exec"], "process": ["scp", "rsync", "sftp"], "argsAny": ["@sshDirArg"], "args": ["\\S+@?\\S+:\\S*(\\s|$)"], "argsNot": ["\\.pub(\\s|$)"]}
     ]},
    {"id": "R37b", "name": "Document sweep", "type": "weak", "category": "infostealer", "score": 45, "stage": "collection", "subject": "lineage",
     "why": "One untrusted program opened many documents on the Desktop or in Documents within a minute, or copied documents into a hidden or temp staging folder, as file-grabber stealers do.",
     "matchers": [
       {"kinds": ["fileClose"], "path": ["^/Users/[^/]+/(Desktop|Documents)/.*\\.(txt|pdf|docx?|rtf|kdbx|key|wallet|xlsx?|csv|png|jpe?g)$"], "trust": "untrusted", "threshold": {"count": 25, "window": 60, "distinct": "path", "groupBy": "actor"}},
       {"kinds": ["fileCreate"], "path": ["^(/private)?/(tmp|var/folders|var/tmp)/.*\\.(txt|pdf|docx?|rtf|kdbx|key|wallet)$", "^/Users/(Shared|[^/]+/\\.[^/]+)/.*\\.(txt|pdf|docx?|rtf|kdbx|key|wallet)$"], "lineageUntrusted": true, "threshold": {"count": 10, "window": 120, "distinct": "path", "groupBy": "actor"}}
     ]},
    {"id": "R43C", "name": "Credentials or archive staged into iCloud Drive", "type": "weak", "category": "infostealer", "score": 50, "stage": "exfil", "subject": "lineage",
     "why": "An untrusted program wrote an archive or credential file into iCloud Drive, which uploads it off the Mac without any outbound connection from the program itself.",
     "matchers": [
       {"kinds": ["fileCreate", "fileWrite", "fileRename"], "path": ["/Library/Mobile Documents/com~apple~CloudDocs/(.*/)?(\\.[^/]+/|[^/]*\\.(zip|tgz|tar|gz|7z|rar|kdbx|rpvault|sqlite|db|keychain-db)$|(Login Data|Cookies|key4\\.db|logins\\.json|wallet\\.dat)$)"], "lineageUntrusted": true}
     ]},
    {"id": "R39", "name": "Honeytoken credential touched", "type": "strong", "category": "infostealer", "score": 95, "stage": "credential", "subject": "actor", "alwaysActive": true, "builtin": true,
     "why": "A Rampart decoy credential file was read, copied or modified. Nothing legitimate opens it."},
    {"id": "R40", "name": "Stealer chain", "type": "sequence", "category": "infostealer", "score": 95, "stage": "exfil", "subject": "lineage", "alwaysActive": true, "builtin": true,
     "why": "Three or more stealer stages (entry, execution from temp, credential access, archiving, upload) happened in one process chain within 10 minutes."},
    {"id": "R41", "name": "Untrusted program's first outbound connection", "type": "weak", "category": "suspicious", "score": 30, "stage": "exfil", "subject": "actor", "builtin": true,
     "why": "An unsigned or ad-hoc signed program made its first connection to the internet."},
    {"id": "R42", "name": "Messaging-API or webhook destination", "type": "weak", "category": "infostealer", "score": 55, "stage": "exfil", "subject": "lineage",
     "why": "A non-messaging program talked to a Telegram bot API or Discord/Slack webhook, a common exfiltration channel.",
     "matchers": [
       {"kinds": ["exec"], "argsAny": ["api\\.telegram\\.org/bot", "discord(app)?\\.com/api/webhooks", "hooks\\.slack\\.com/services"], "processNot": ["@messagingApps"]},
       {"kinds": ["dnsQuery", "networkConnect"], "detail": {"name": "^(api\\.telegram\\.org|discord(app)?\\.com)\\.?$"}, "processNot": ["@messagingApps", "@browsers"]},
       {"kinds": ["networkConnect"], "detail": {"remote_ip": "^(149\\.154\\.(16[0-9]|17[0-5])\\.|91\\.108\\.([4-9]|1[0-9]|2[0-3]|5[6-9])\\.|91\\.105\\.19[23]\\.|185\\.76\\.151\\.)"}, "processNot": ["@messagingApps", "@browsers"]},
       {"kinds": ["dnsQuery", "networkConnect"], "detail": {"host": "^(api\\.telegram\\.org|discord(app)?\\.com)\\.?$"}, "processNot": ["@messagingApps", "@browsers"]}
     ]},
    {"id": "R42D", "name": "DNS tunnelling pattern", "type": "weak", "category": "infostealer", "score": 55, "stage": "exfil", "subject": "actor",
     "why": "One program resolved many different long, random-looking subdomains in a minute, the signature of data smuggled out inside DNS queries.",
     "matchers": [
       {"kinds": ["dnsQuery"], "detail": {"name": "^(?=[a-z0-9]*[0-9])(?=[a-z0-9]*[a-z])[a-z0-9]{24,63}\\.|^[a-z0-9]{40,63}\\.|^([a-z0-9]{16,63}\\.){3,}"}, "processNot": ["@browsers", "mDNSResponder", "rampartd"], "trust": "nonApple", "threshold": {"count": 10, "window": 60, "distinct": "detail:name", "groupBy": "actor"}}
     ]},
    {"id": "L03", "name": "Archive of a temp staging folder", "type": "weak", "category": "infostealer", "score": 20, "stage": "collection", "subject": "lineage", "devSensitive": true,
     "why": "A temp or hidden folder was archived, as stealers do before upload.",
     "matchers": [
       {"kinds": ["exec"], "process": ["@archivers"], "argsAny": ["(^|\\s)(/private)?/(tmp|var/folders|Users/Shared)/", "/\\.[A-Za-z0-9_-]+/"], "setMark": {"name": "staged", "from": "args", "window": 600}}
     ]},
    {"id": "R43", "name": "Archive then upload from the same chain", "type": "sequence", "category": "infostealer", "score": 70, "stage": "exfil", "subject": "lineage",
     "why": "A staged archive was uploaded by a network client shortly after being created.",
     "matchers": [
       {"kinds": ["exec"], "process": ["@uploaders"], "requireMark": {"name": "staged", "scope": "argPath", "window": 600}},
       {"kinds": ["exec"], "process": ["curl"], "args": ["(-F|--form)\\s+\\S*=@(/private)?/(tmp|var/folders)/\\S+\\.(zip|tar|gz|tgz|7z)"]}
     ]},
    {"id": "R44", "name": "Tor used by a non-Tor program", "type": "weak", "category": "suspicious", "score": 50, "stage": "exfil", "subject": "actor",
     "why": "A program other than Tor Browser connected to Tor ports or resolved a .onion name.",
     "matchers": [
       {"kinds": ["networkConnect"], "detail": {"remote_port": "^(9001|9030|9050|9150)$"}, "processNot": ["@torApps"]},
       {"kinds": ["dnsQuery"], "detail": {"name": "\\.onion\\.?$"}, "processNot": ["@torApps"]}
     ]},
    {"id": "R45", "name": "DNS-over-HTTPS from a non-browser", "type": "weak", "category": "suspicious", "score": 40, "stage": "evasion", "subject": "actor",
     "why": "An untrusted, non-browser program talked HTTPS to a public DoH resolver, bypassing system DNS.",
     "matchers": [
       {"kinds": ["networkConnect"], "detail": {"remote_ip": "^(1\\.1\\.1\\.1|1\\.0\\.0\\.1|8\\.8\\.8\\.8|8\\.8\\.4\\.4|9\\.9\\.9\\.9|149\\.112\\.112\\.112|45\\.90\\.28\\.\\d+|45\\.90\\.30\\.\\d+|94\\.140\\.14\\.14|208\\.67\\.222\\.222)$", "remote_port": "^443$"}, "processNot": ["@browsers", "rampartd", "mDNSResponder"], "trust": "untrusted"}
     ]},
    {"id": "R46", "name": "Beaconing", "type": "weak", "category": "backdoor", "score": 45, "stage": "exfil", "subject": "actor", "builtin": true,
     "why": "An untrusted program connected to the same address at a fixed interval for over 30 minutes."},
    {"id": "R47", "name": "Untrusted listener on all interfaces", "type": "weak", "category": "backdoor", "score": 45, "stage": "persistence", "subject": "actor", "devSensitive": true,
     "why": "An untrusted program opened a listening TCP port on every network interface (bind shell or remote access).",
     "matchers": [
       {"kinds": ["networkConnect", "other"], "detail": {"listen": "^(1|true)$", "local_ip": "^(0\\.0\\.0\\.0|::|\\*)$"}, "trust": "untrusted"}
     ]},
    {"id": "R48", "name": "Keyboard event tap by untrusted program", "type": "strong", "category": "malware", "score": 85, "stage": "surveillance", "subject": "actor", "alwaysActive": true,
     "why": "An unsigned or ad-hoc program installed a keyboard event tap, which is how keyloggers work.",
     "matchers": [
       {"kinds": ["other"], "detail": {"type": "^eventTap$", "keyboard": "^(1|true)$"}, "trust": "untrusted"}
     ]},
    {"id": "R49", "name": "Input Monitoring or Accessibility granted to untrusted program", "type": "weak", "category": "suspicious", "score": 50, "stage": "surveillance", "subject": "actor",
     "why": "An untrusted program obtained Input Monitoring, synthetic-event or Accessibility rights.",
     "matchers": [
       {"kinds": ["tccRequest"], "detail": {"service": "(ListenEvent|PostEvent|Accessibility)"}, "detailNot": {"right": "(?i)denied"}, "trust": "untrusted"}
     ]},
    {"id": "R50", "name": "Mic or camera used by untrusted program", "type": "strong", "category": "malware", "score": 70, "stage": "surveillance", "subject": "actor", "alwaysActive": true,
     "why": "The microphone or camera was switched on by an untrusted or windowless background program.",
     "matchers": [
       {"kinds": ["other"], "detail": {"type": "^deviceInUse$"}, "trust": "untrusted"},
       {"kinds": ["other"], "detail": {"type": "^deviceInUse$", "visible_window": "^(0|false)$"}, "trust": "nonApple"}
     ]},
    {"id": "R51", "name": "Silent screen capture", "type": "weak", "category": "malware", "score": 55, "stage": "surveillance", "subject": "lineage",
     "why": "screencapture was run silently (-x) from a non-interactive or untrusted process chain.",
     "matchers": [
       {"kinds": ["exec"], "process": ["screencapture"], "args": ["(^|\\s)-[A-Za-z]*x"], "lineageUntrusted": true},
       {"kinds": ["exec"], "process": ["screencapture"], "args": ["(^|\\s)-[A-Za-z]*x"], "ancestorNot": ["@terminals", "Screenshot", "screencaptureui", "Shottr", "CleanShot.*", "@scriptHosts"], "ancestor": ["@shells", "@interpreters"]}
     ]},
    {"id": "R52", "name": "Privacy-permission request burst", "type": "weak", "category": "suspicious", "score": 50, "stage": "surveillance", "subject": "actor",
     "why": "One untrusted program asked for three or more different privacy permissions within two minutes.",
     "matchers": [
       {"kinds": ["tccRequest"], "trust": "untrusted", "threshold": {"count": 3, "window": 120, "distinct": "detail:service", "groupBy": "actor"}}
     ]},
    {"id": "R53", "name": "Privacy database tampering", "type": "strong", "category": "malware", "score": 85, "stage": "evasion", "subject": "lineage", "interactiveFactor": 0.5,
     "why": "The TCC privacy database was written by something other than tccd, or privacy grants were reset from a script.",
     "matchers": [
       {"kinds": ["fileWrite", "fileCreate", "fileRename"], "path": ["/com\\.apple\\.TCC/TCC\\.db$"], "processNot": ["tccd"]},
       {"kinds": ["exec"], "process": ["tccutil"], "args": ["\\breset\\b"], "ancestorNot": ["@terminals"]},
       {"kinds": ["exec"], "process": ["sqlite3"], "args": ["TCC\\.db"]}
     ]},
    {"id": "M02", "name": "Gatekeeper user override", "type": "marker", "category": "suspicious", "score": 0,
     "why": "User clicked Open Anyway.",
     "matchers": [
       {"kinds": ["other"], "detail": {"es_event": "^gatekeeper_user_override$"}, "setMark": {"name": "gkOverride", "from": "global", "window": 600}},
       {"kinds": ["other"], "detail": {"gatekeeper": "^override$"}, "setMark": {"name": "gkOverride", "from": "global", "window": 600}}
     ]},
    {"id": "R54", "name": "Gatekeeper override then shell activity", "type": "weak", "category": "suspicious", "score": 45, "stage": "execution", "subject": "lineage",
     "why": "Shortly after the user overrode Gatekeeper for an app, an untrusted chain started shells or interpreters.",
     "matchers": [
       {"kinds": ["exec"], "process": ["@shells", "@interpreters", "@fetchers"], "requireMark": {"name": "gkOverride", "scope": "global", "window": 600}, "lineageUntrusted": true}
     ]},
    {"id": "R55", "name": "Security tool tampering", "type": "strong", "category": "malware", "score": 85, "stage": "evasion", "subject": "lineage", "interactiveFactor": 0.3,
     "why": "A process tried to kill or unload Rampart or another security tool.",
     "matchers": [
       {"kinds": ["exec"], "process": ["pkill", "killall"], "argsAny": ["@securityTools"]},
       {"kinds": ["exec"], "process": ["launchctl"], "args": ["\\b(bootout|unload|remove|disable|kill)\\b"], "argsAny": ["@securityTools"]}
     ]},
    {"id": "R56", "name": "Host fingerprinting burst", "type": "weak", "category": "suspicious", "score": 25, "stage": "recon", "subject": "lineage",
     "why": "An untrusted process chain ran three or more system-inventory tools within 30 seconds (VM checks and host fingerprinting).",
     "matchers": [
       {"kinds": ["exec"], "process": ["@recon"], "lineageUntrusted": true, "threshold": {"count": 3, "window": 30, "distinct": "process", "groupBy": "story"}}
     ]},
    {"id": "R57", "name": "Detached background process from a script chain", "type": "weak", "category": "suspicious", "score": 35, "stage": "persistence", "subject": "lineage", "devSensitive": true,
     "why": "An untrusted or paste-derived chain detached a process to keep running in the background.",
     "matchers": [
       {"kinds": ["exec"], "process": ["nohup"], "lineageUntrusted": true},
       {"kinds": ["exec"], "process": ["screen"], "args": ["-d?m"], "lineageUntrusted": true},
       {"kinds": ["exec"], "process": ["nohup"], "requireMark": {"name": "pasteEntry", "scope": "global", "window": 600}}
     ]},
    {"id": "R58", "name": "Self-deleting binary", "type": "weak", "category": "malware", "score": 55, "stage": "evasion", "subject": "target", "builtin": true,
     "why": "An untrusted program's executable file was deleted while the program was still running."},
    {"id": "L04", "name": "Decoded payload fed to an interpreter", "type": "weak", "category": "suspicious", "score": 40, "stage": "execution", "subject": "lineage", "devSensitive": true,
     "why": "Base64/openssl-decoded data was piped into a shell or interpreter, or written into a temp folder.",
     "matchers": [
       {"kinds": ["exec"], "argsAny": ["(base64\\s+(-d|--decode|-D)|openssl\\s+(enc|base64)\\s.*-d)[^|]*\\|\\s*(sudo\\s+)?(/[^ ]*/)?((ba|z)?sh|python[0-9.]*|perl|osascript|ruby|node)\\b", "(base64\\s+(-d|--decode|-D)|openssl\\s+enc\\s.*-d).*(-o|>)\\s*(/private)?/(tmp|var/folders|Users/Shared)/", "(exec|eval)\\s*\\(\\s*(base64\\.b64decode|codecs\\.decode|zlib\\.decompress|bytes\\.fromhex|__import__\\(.base64.\\))", "osascript\\s+-l\\s+JavaScript.*(NSData|dataWithContentsOfURL|doShellScript)"]}
     ]},
    {"id": "L05", "name": "Made executable in temp then run", "type": "sequence", "category": "suspicious", "score": 45, "stage": "execution", "subject": "actor", "devSensitive": true,
     "why": "A file in a temp or hidden folder was marked executable and then run.",
     "matchers": [
       {"kinds": ["exec"], "requireMark": {"name": "madeExecutable", "scope": "execPath", "window": 600}, "processNot": ["chmod"]}
     ]},
    {"id": "M03", "name": "chmod +x in temp", "type": "marker", "category": "suspicious", "score": 0,
     "why": "chmod +x on a temp-located file.",
     "matchers": [
       {"kinds": ["exec"], "process": ["chmod"], "argsAny": ["(\\+x|[0-7]?[0-7][1357][0-7]\\b|u\\+x|a\\+x)"], "args": ["(^|\\s)((/private)?/(tmp|var/folders|Users/Shared)/|\\S*/\\.[A-Za-z0-9_-]+/)"], "setMark": {"name": "madeExecutable", "from": "args", "window": 600}}
     ]},
    {"id": "L06", "name": "Gatekeeper or quarantine disabled", "type": "strong", "category": "suspicious", "score": 75, "stage": "evasion", "subject": "lineage", "interactiveFactor": 0.4,
     "why": "Gatekeeper assessments or download quarantine were switched off from the command line.",
     "matchers": [
       {"kinds": ["exec"], "process": ["spctl"], "argsAny": ["--(master-disable|global-disable)"]},
       {"kinds": ["exec"], "process": ["socketfilterfw"], "argsAny": ["--setglobalstate\\s+off", "--setblockall\\s+off", "--setstealthmode\\s+off"], "ancestorNot": ["rampartd", "RamPart"]},
       {"kinds": ["exec"], "process": ["pfctl"], "args": ["(^|\\s)-d\\b"], "ancestorNot": ["rampartd", "RamPart"]},
       {"kinds": ["exec"], "process": ["defaults"], "args": ["write"], "argsAny": ["LSQuarantine\\s+-bool\\s+(no|false|0)", "GKAutoRearm\\s+-bool\\s+(no|false|0)", "EnableAssessment\\s+-bool\\s+(no|false|0)"]}
     ]},
    {"id": "L07", "name": "Inline AppleScript automating Finder/System Events/Terminal", "type": "weak", "category": "suspicious", "score": 40, "stage": "execution", "subject": "lineage",
     "why": "An untrusted chain ran inline AppleScript that drives Finder, System Events or Terminal (file collection and UI control).",
     "matchers": [
       {"kinds": ["exec"], "process": ["osascript"], "args": ["(^|\\s)-e\\s", "tell\\s+application\\s+\"?(system events|finder|terminal)"], "lineageUntrusted": true}
     ]},
    {"id": "L10", "name": "sudo fed a password from a script", "type": "weak", "category": "infostealer", "score": 45, "stage": "credential", "subject": "lineage",
     "why": "sudo -S read a password from standard input inside an untrusted chain, typically after phishing it.",
     "matchers": [
       {"kinds": ["exec"], "process": ["sudo"], "args": ["(^|\\s)-[A-Za-z]*S"], "lineageUntrusted": true}
     ]},
    {"id": "L11", "name": "Indicator removal", "type": "weak", "category": "suspicious", "score": 45, "stage": "evasion", "subject": "lineage", "interactiveFactor": 0.6,
     "why": "System logs were erased, or shell history or crash logs were deleted by a script, which hides what an attacker did.",
     "matchers": [
       {"kinds": ["exec"], "process": ["log"], "args": ["(^|\\s)erase\\b"]},
       {"kinds": ["exec"], "process": ["rm", "srm", "shred"], "argsAny": ["/\\.(zsh|bash)_history\\b", "(^|\\s)/var/log/", "/Library/Logs/DiagnosticReports"], "lineageUntrusted": true},
       {"kinds": ["exec"], "process": ["@shells"], "argsAny": ["\\bhistory\\s+-c\\b", "unset\\s+HISTFILE", "HISTFILE=/dev/null"], "lineageUntrusted": true}
     ]},
    {"id": "R55M", "name": "Memory of a security tool read", "type": "strong", "category": "malware", "score": 85, "stage": "credential", "subject": "lineage", "alwaysActive": true, "interactiveFactor": 0.3,
     "why": "A debugger or memory-inspection tool attached to RamPart or another security tool; it can read unlocked vault secrets straight out of memory.",
     "matchers": [
       {"kinds": ["exec"], "process": ["@memoryTools"], "argsAny": ["@securityTools"]},
       {"kinds": ["exec"], "process": ["@memoryTools"], "detail": {"target_process": "(?i)(rampart|lulu|blockblock|little ?snitch|knockknock|oversight|xprotect)"}}
     ]},
    {"id": "R59", "name": "Clipboard hijacker", "type": "weak", "category": "infostealer", "score": 50, "stage": "collection", "subject": "lineage",
     "why": "An untrusted program read and rewrote the clipboard over and over, as crypto-address swappers do.",
     "matchers": [
       {"kinds": ["exec"], "process": ["pbpaste", "pbcopy"], "lineageUntrusted": true, "threshold": {"count": 5, "window": 120, "groupBy": "story"}},
       {"kinds": ["other"], "detail": {"type": "^clipboardRead$"}, "trust": "untrusted", "threshold": {"count": 3, "window": 120, "groupBy": "actor"}}
     ]},
    {"id": "R59R", "name": "Clipboard read by an untrusted program", "type": "weak", "category": "infostealer", "score": 40, "stage": "collection", "subject": "actor",
     "why": "An unsigned or ad-hoc signed program read the clipboard, where copied passwords and one-time codes sit briefly.",
     "matchers": [
       {"kinds": ["other"], "detail": {"type": "^clipboardRead$"}, "trust": "untrusted"}
     ]},
    {"id": "R60", "name": "Installed app modified by an untrusted program", "type": "strong", "category": "malware", "score": 70, "stage": "persistence", "subject": "lineage",
     "why": "Code inside an installed app in /Applications was replaced by an untrusted program or script, which trojanises the app.",
     "matchers": [
       {"kinds": ["fileWrite", "fileCreate", "fileRename"], "path": ["^/Applications/[^/]+\\.app/Contents/"], "pathNot": ["^/Applications/(Ledger Live|Exodus|Trezor Suite|Electrum|Atomic Wallet|Wasabi Wallet|Sparrow|Coinomi|Guarda)\\.app/"], "lineageUntrusted": true, "processNot": ["@installers", "Autoupdate", "Sparkle.*", "Updater", "storedownloadd", "appstoreagent"], "ancestorNot": ["@installers", "Autoupdate", "Sparkle.*"]}
     ]},
    {"id": "R60W", "name": "Crypto wallet app trojanised", "type": "strong", "category": "infostealer", "score": 90, "stage": "credential", "subject": "lineage", "alwaysActive": true,
     "why": "A crypto wallet app's code (for example app.asar) was replaced by another program; trojanised wallets steal seed phrases.",
     "matchers": [
       {"kinds": ["fileWrite", "fileCreate", "fileRename"], "path": ["^/Applications/(Ledger Live|Exodus|Trezor Suite|Electrum|Atomic Wallet|Wasabi Wallet|Sparrow|Coinomi|Guarda)\\.app/Contents/"], "processNot": ["@installers", "Autoupdate", "Sparkle.*", "Ledger Live", "Exodus", "Trezor Suite", "Electrum", "Atomic Wallet", "ShipIt"], "ancestorNot": ["@installers"]}
     ]},
    {"id": "R62", "name": "Cryptominer", "type": "strong", "category": "miner", "score": 65, "stage": "impact", "subject": "lineage",
     "why": "A program started with mining-pool arguments (stratum URL, pool port, RandomX/Monero options) or an untrusted program connected to a well-known mining-pool port.",
     "matchers": [
       {"kinds": ["exec"], "argsAny": ["@minerArgs"]},
       {"kinds": ["networkConnect"], "detail": {"remote_port": "^(3333|4444|5555|7777|14444|14433|45700)$"}, "trust": "untrusted"}
     ]},
    {"id": "EV1", "name": "Apple tool copied out of the system and run", "type": "strong", "category": "suspicious", "score": 65, "stage": "evasion", "subject": "none", "builtin": true, "devSensitive": true,
     "why": "An Apple command-line tool (a shell, curl, osascript, python...) was copied to a temp, hidden or user folder, often under a new name, and run from there. Malware does this so rules keyed on the tool's name and path miss it, while the Apple signature still looks trustworthy (MITRE T1036.003)."},
    {"id": "EV2", "name": "Code injected with DYLD environment variables", "type": "strong", "category": "malware", "score": 70, "stage": "evasion", "subject": "none",
     "why": "A program was started with DYLD_INSERT_LIBRARIES pointing at a library in a temp, hidden or shared folder, or an app's Info.plist was given a DYLD_ launch environment: the library's code then runs inside the trusted app (MITRE T1574.006, T1647).",
     "matchers": [
       {"kinds": ["exec"], "detail": {"dyld_env": "DYLD_INSERT_LIBRARIES=(?![^ ]*libclang_rt)[^ ]*(/tmp/|/private/(tmp|var/folders)/|/var/folders/|/Users/Shared/|/Downloads/|/\\.[^/ ]+/)"}},
       {"kinds": ["exec"], "argsAny": ["(^|\\s)DYLD_INSERT_LIBRARIES=(?!\\S*libclang_rt)\\S*(/tmp/|/private/(tmp|var/folders)/|/var/folders/|/Users/Shared/|/Downloads/|/\\.[^/\\s]+/)"]},
       {"kinds": ["exec"], "process": ["plutil", "defaults", "PlistBuddy"], "args": ["LSEnvironment", "DYLD_"]}
     ]},
    {"id": "EV3", "name": "Program disguised as a system process", "type": "strong", "category": "suspicious", "score": 60, "stage": "evasion", "subject": "actor", "builtin": true,
     "why": "A program that is not part of macOS calls itself after a system process (launchd, mdworker, softwareupdated...), either by its file name outside the system folders or by faking its argv[0], so it blends into process lists (MITRE T1036.004, T1036.005)."},
    {"id": "EV4", "name": "Fake Apple security log message", "type": "strong", "category": "suspicious", "score": 55, "stage": "evasion", "subject": "actor",
     "why": "A third-party program wrote a log message under an Apple security subsystem (XProtect, TCC, Gatekeeper, background items). Real ones come from macOS itself; a fake one tries to mislead security tools that read the log (MITRE T1562.006).",
     "matchers": [
       {"kinds": ["other"], "detail": {"log_spoof": "^1$"}, "trust": "nonApple"}
     ]},
    {"id": "EV5", "name": "Event feed flooded or lost events", "type": "weak", "category": "suspicious", "score": 35, "stage": "evasion", "subject": "none",
     "why": "Real-time telemetry dropped events: the kernel event queue overflowed or events arrived faster than they could be checked. A flood like this can hide other activity, so it is recorded next to anything else found at the same time.",
     "matchers": [
       {"kinds": ["other"], "detail": {"type": "^telemetry_gap$"}}
     ]},
    {"id": "EV6", "name": "File timestamps forged by a script", "type": "weak", "category": "suspicious", "score": 35, "stage": "evasion", "subject": "lineage",
     "why": "An untrusted script reset a file's dates with touch -t/-r/-d on a launch item or a temp, shared or hidden path, so the new file looks old (MITRE T1070.006).",
     "matchers": [
       {"kinds": ["exec"], "process": ["touch"], "args": ["(^|\\s)-[acm]*[trd]\\b"], "argsAny": ["/Library/Launch(Agents|Daemons)/", "(^|\\s)/(private/)?tmp/", "/Users/Shared/", "/Application Support/", "/\\.[^/\\s]+/"], "lineageUntrusted": true}
     ]},
    {"id": "EV7", "name": "JavaScript for Automation reaching the shell", "type": "weak", "category": "suspicious", "score": 40, "stage": "execution", "subject": "lineage",
     "why": "An untrusted chain ran JavaScript for Automation that shells out or loads Objective-C frameworks, or ran a JXA script from a temp folder: a common way to run payloads without dropping a binary (MITRE T1059.007).",
     "matchers": [
       {"kinds": ["exec"], "process": ["osascript"], "args": ["-l\\s+JavaScript"], "argsAny": ["doShellScript", "ObjC\\.(import|unwrap|bindFunction)", "\\$\\.NS[A-Z]", "(^|\\s)/(private/)?tmp/", "/var/folders/", "/Users/Shared/"], "lineageUntrusted": true}
     ]},
    {"id": "EV8", "name": "Dropped program hidden from Finder", "type": "weak", "category": "suspicious", "score": 35, "stage": "evasion", "subject": "lineage",
     "why": "An untrusted script set the hidden flag on a file in a temp, shared or launch-item location, so Finder won't show it (MITRE T1564.001).",
     "matchers": [
       {"kinds": ["exec"], "process": ["chflags"], "args": ["(^|\\s)hidden\\b"], "argsAny": ["/Library/Launch(Agents|Daemons)/", "(^|\\s)/(private/)?tmp/", "/Users/Shared/", "/Application Support/"], "lineageUntrusted": true}
     ]}
  ]
}
"""#
}
