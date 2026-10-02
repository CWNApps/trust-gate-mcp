"""gate_vocabulary.py -- the gate's word tables, written out a second time on purpose.

tests/test_gate_decision.py checks that trust_gate_mcp.server holds exactly these words, and runs
its per-word tests over THESE lists. A test that looped over the module's own table would lose a
word's test at the same moment it lost the word. To add, remove or move a word you change both
files, so the change is visible in the diff.
"""
from __future__ import annotations

CRITICAL_VERBS = (
    "pay", "payment", "wire", "transfer", "remit", "disburse", "refund", "withdraw", "sell",
    "buy", "purchase", "trade", "liquidate", "deposit", "settle", "mint", "delete", "drop",
    "purge", "wipe", "destroy", "truncate", "erase", "shred", "nuke", "overwrite", "dd", "mkfs",
    "deploy", "rollout", "provision", "migrate", "reconfigure", "grant", "revoke", "elevate",
    "impersonate", "rm", "unlink", "kill", "shutdown", "poweroff", "uninstall", "deactivate",
    "unregister", "exec", "execute", "eval", "sudo", "chmod", "chown",
)

HIGH_VERBS = (
    "send", "email", "post", "message", "outreach", "publish", "escalate", "export", "egress",
    "exfil", "upload", "share", "approve", "deny", "reject", "decline", "cancel", "adverse",
    "terminate", "suspend", "forward", "relay", "transmit", "notify", "push", "broadcast",
    "submit", "download", "copy", "move", "rename", "encrypt", "decrypt", "swap", "sign",
    "authorize", "ban", "spawn", "launch", "run", "invoke", "trigger", "restart", "reboot",
    "stop", "install", "rotate", "enable", "disable", "curl", "wget", "ssh", "scp", "bash",
    "powershell", "format", "release", "remove", "reset", "flush", "flushall", "flushdb",
    "alter", "replace", "merge", "upsert", "attach", "load", "lock", "unlock", "import",
    "restore", "call", "mount", "umount", "nc", "netcat",
)

MEDIUM_VERBS = (
    "write", "create", "update", "edit", "modify", "change", "insert", "append", "book",
    "schedule", "reserve", "charge", "save", "store", "patch", "apply",
)

LOW_VERBS = (
    "read", "get", "list", "search", "query", "find", "show", "view", "inspect", "describe",
)

READ_NOUNS = (
    "a", "account", "accounts", "all", "an", "branch", "branches", "by", "calendar", "column",
    "columns", "comment", "comments", "commit", "commits", "contact", "contacts", "content",
    "contents", "count", "counts", "current", "customer", "customers", "data", "database",
    "databases", "db", "deal", "deals", "detail", "details", "diff", "dir", "directories",
    "directory", "dirs", "doc", "docs", "document", "documents", "entries", "entry", "event",
    "events", "file", "files", "folder", "folders", "for", "id", "ids", "in", "index", "info",
    "information", "invoice", "invoices", "issue", "issues", "item", "items", "latest", "lead",
    "leads", "list", "lists", "log", "logs", "meta", "metadata", "metric", "metrics", "my",
    "name", "names", "note", "notes", "of", "order", "orders", "org", "organization",
    "organizations", "page", "pages", "path", "paths", "product", "products", "profile",
    "profiles", "project", "projects", "recent", "record", "records", "repo", "report",
    "reports", "repos", "repositories", "repository", "result", "results", "row", "rows",
    "schema", "schemas", "size", "stat", "statistics", "stats", "status", "summaries",
    "summary", "table", "tables", "task", "tasks", "team", "teams", "text", "the", "ticket",
    "tickets", "top", "tree", "user", "users", "version", "versions",
)

SENSITIVE_NOUNS = (
    "admin", "apikey", "authenticator", "bearer", "biometric", "birthdate", "birthday",
    "bitwarden", "classified", "confidential", "cookie", "cookies", "coredump", "cred",
    "credential", "credentials", "creds", "cvv", "dotenv", "dsn", "env", "envrc", "genome",
    "heapdump", "hotp", "htdigest", "htpasswd", "iban", "ibans", "jwt", "keepass", "keychain",
    "keypair", "keyring", "keystore", "keytab", "kubeconfig", "lastpass", "mfa", "mnemonic",
    "nda", "netrc", "npmrc", "ntlm", "otp", "pass", "passcode", "passphrase", "passwd",
    "password", "passwords", "pem", "pgpass", "phi", "pii", "pin", "pincode", "private",
    "privilege", "privileges", "pswd", "pw", "pwd", "pypirc", "restricted", "root", "rsa",
    "secret", "secrets", "seed", "shadow", "ssn", "ssns", "sudoers", "tfstate", "tfvars",
    "token", "tokens", "totp", "vault", "viminfo", "wallet", "webhook",
)

SENSITIVE_PHRASES = (
    "api key", "private key", "signing key", "access key", "secret key", "master key",
    "ssh key", "encryption key", "session id", "auth code", "security code", "recovery code",
    "credit card", "card number", "bank account", "routing number", "social security",
    "passport number", "swift code", "dea number", "medical record", "health record",
    "patient record", "connection string", "id ed 25519", "id ecdsa", "id dsa",
    "authorized key", "known host", "login data", "shell history", "zsh history",
    "fish history", "command history", "web data", "local state", "auth header",
    "authorization header", "cc number", "backup code", "driver license", "lab result",
    "date of birth", "recovery phrase", "one time code", "driver licence", "driving licence",
    "national id", "tax return", "bank statement", "criminal record", "hiv status",
    "hiv result", "dna result", "genetic test", "birth date", "scratch code", "database dump",
    "sentry dsn", "pg authid",
)

ORDINARY_EXTENSIONS = (
    "c", "cc", "cjs", "cpp", "cs", "css", "go", "h", "hpp", "htm", "html", "java", "js", "jsx",
    "kt", "markdown", "md", "mjs", "php", "py", "rb", "rs", "rst", "swift", "ts", "tsx", "txt",
)

SENSITIVE_RESOURCE_NOUNS = (
    "cmdline", "config", "configuration", "dob", "environ", "environment", "gshadow", "history",
    "key", "keys", "login", "logins", "opasswd", "pat", "proc", "sam", "settings",
)

SENSITIVE_STEMS = (
    "password", "passwd", "secret", "token", "apikey", "credential", "privatekey", "privkey",
    "sshkey", "creditcard", "cardnumber", "socialsecurity", "keyvault", "sessionid", "idrsa",
    "userdata", "pii", "2fa", "diagnos", "payroll", "salar", "patient", "medical", "rsakey",
    "krb5cc", "otpauth", "passport", "prescription", "therapy", "secring", "databaseurl",
    "mongouri", "redisurl", "serviceaccount", "ntds", "lsass", "sendmail", "useradd", "userdel",
    "visudo", "xpcmdshell", "spexecutesql", "rmrf", "dropdb", "dropall", "onetimecode",
)

RESOURCE_EXTRA_WORDS = (
    "api", "app", "article", "articles", "blog", "changelog", "chapter", "chapters", "cli",
    "contributing", "design", "example", "examples", "faq", "guide", "guides", "intro",
    "introduction", "lesson", "lessons", "lib", "license", "main", "manual", "manuals",
    "overview", "plan", "plans", "readme", "reference", "references", "section", "sections",
    "site", "spec", "specs", "src", "test", "tests", "todo", "topic", "topics", "tutorial",
    "tutorials", "usage", "web",
)

RESOURCE_EXCLUDED_WORDS = (
    "database", "databases", "db", "log", "logs",
)

RISKY_MIDDLE_EXTENSIONS = (
    "7z", "backup", "bak", "bat", "bin", "bz2", "cer", "cfg", "conf", "crt", "csv", "dat", "db",
    "dll", "dump", "env", "exe", "gz", "ini", "jks", "json", "kdbx", "key", "keystore", "ldb",
    "leveldb", "lock", "log", "mdb", "p12", "pem", "pfx", "ps1", "rar", "sh", "so", "sql",
    "sqlite", "sqlite3", "tar", "tgz", "toml", "tsv", "wallet", "xml", "xz", "yaml", "yml",
    "zip",
)

GLUE_WORDS = (
    "backup", "data", "db", "dump", "file", "files", "list", "my", "raw", "store", "text",
    "the",
)

GLUED_VERB_EXEMPT = (
    "mint", "payment", "sell", "trade", "wire",
)

VERBS_BY_TIER = {
    "CRITICAL": CRITICAL_VERBS,
    "HIGH": HIGH_VERBS,
    "MEDIUM": MEDIUM_VERBS,
    "LOW": LOW_VERBS,
}
