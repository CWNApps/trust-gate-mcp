"""Trust Gate MCP server -- hybrid-signed agent-decision receipts as MCP tools.

One MCP server, seven tools, one shared signing primitive (the open-source
OpenAgentOntology `mint_receipt`: Ed25519 + ML-DSA-65).

  mint_receipt_for_record_change(record)  -- a CRM record changed; mint a per-change receipt
  audit_my_agent_inventory(inventory)     -- rank a CALLER-PROVIDED list of MCP tools by
                                             worst-regret if they act (read-only: mints nothing)
  mint_action_receipt(action, decision)   -- general-purpose agent-action receipt
  verify_receipt(receipt)                 -- verify from the certificate alone (offline)
  gate_decision(action, resource, ...)   -- two-phase PREVIEW->COMMIT decision gate: an
                                             ALLOW / DENY / ESCALATE verdict + signed receipt
  check_egress(destination, data_sample) -- egress data-classification check with receipt
  run_exit_drill()                       -- vendor exit readiness check with receipt

Honesty constraints (encoded, not optional):

  * audit_my_agent_inventory CANNOT auto-discover other MCP servers. The MCP protocol gives
    one server no view of the host's other installed servers. The caller must pass the list
    in. The tool's docstring + every response says so explicitly.

  * The receipts are "tamper-evident", not "proof of compliance" or "admissible". Wording is
    deliberate; do not edit it to be marketing-flavoured.

  * All crypto is the merged OAO `mint_receipt`. This server adds no signing code of its own,
    so every receipt carries whichever post-quantum legs the installed backend provides.

Run:
    pip install mcp "openagentontology[pq]"
    python server.py                 # stdio (the standard MCP transport)
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import itertools
import json
import os
import re
import sys
import unicodedata
from urllib.parse import urlsplit
from typing import Any, Dict, List, Optional

# One source of truth for the version a running server reports (the static server card, the MCP
# registry entry and pyproject.toml must all say this; tests/test_release_consistency.py checks).
SERVER_VERSION = "0.3.0"

# ---- the receipt primitive (one source of truth, hybrid-signed by default) ---------
# If the package is not installed the tools return a clear, structured error rather than
# silently returning unsigned receipts.
try:
    from openagentontology import receipt as _oao_receipt  # type: ignore
    _OAO_SOURCE = "installed"
except ImportError:
    _oao_receipt = None  # type: ignore[assignment]
    _OAO_SOURCE = "missing"


# ---- worst-regret scoring (sourced; for audit_my_agent_inventory and gate_decision) -------
# A tool that can act on the world in side-effecting ways is worst-regret if it acts
# unexpectedly. We tier
# by the verbs the tool/server's NAME (and declared capabilities) carry. This is a
# heuristic ranking, not a proof; the tool's output says so.
#
# Verbs are matched as whole TOKENS. Identifiers are split on underscores, hyphens, dots,
# slashes, letter/digit boundaries and camelCase, and each verb also matches its regular
# inflections ("delete" matches deleted, deleting, deletes). The earliest version matched with
# \b regexes and could not see "delete_user" or "deleteUser" at all ("_" is a word character).
# Whole-token matching also keeps "payload" from matching "pay".
#
# WHAT A TIER IS FOR. The gate never asks "is a bad word absent?" (a list of bad words is always
# incomplete). It asks "is this a known read-only name?": ALLOW needs a read verb followed only by
# nouns from a small closed vocabulary. The risky-verb lists below decide DENY versus ESCALATE and
# rank an inventory; they are not what keeps an unknown action from being allowed.
_TIER_VERBS: Dict[str, tuple] = {
    "CRITICAL": (
        "pay", "payment", "wire", "transfer", "remit", "disburse", "refund", "withdraw",
        "sell", "buy", "purchase", "trade", "liquidate", "deposit", "settle", "mint",
        "delete", "drop", "purge", "wipe", "destroy", "truncate", "erase", "shred", "nuke",
        "overwrite", "dd", "mkfs",
        "deploy", "rollout", "provision", "migrate", "reconfigure",
        "grant", "revoke", "elevate", "impersonate",
        "rm", "unlink", "kill", "shutdown", "poweroff", "uninstall", "deactivate",
        "unregister", "exec", "execute", "eval", "sudo", "chmod", "chown"),
    "HIGH": (
        "send", "email", "post", "message", "outreach", "publish", "escalate",
        "export", "egress", "exfil", "upload", "share",
        "approve", "deny", "reject", "decline", "cancel", "adverse", "terminate", "suspend",
        "forward", "relay", "transmit", "notify", "push", "broadcast", "submit",
        "download", "copy", "move", "rename", "encrypt", "decrypt", "swap", "sign",
        "authorize", "ban", "spawn", "launch",
        "run", "invoke", "trigger", "restart", "reboot", "stop", "install", "rotate",
        "enable", "disable",
        "curl", "wget", "ssh", "scp", "bash", "powershell",
        "format", "release", "remove", "reset",
        "flush", "flushall", "flushdb", "alter", "replace", "merge", "upsert", "attach", "load",
        "lock", "unlock", "import", "restore", "call", "mount", "umount", "nc", "netcat"),
    "MEDIUM": ("write", "create", "update", "edit", "modify", "change", "insert", "append",
               "book", "schedule", "reserve", "charge", "save", "store", "patch", "apply"),
    "LOW": ("read", "get", "list", "search", "query", "find", "show", "view", "inspect", "describe"),
}
_TIER_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
_TIER_SCORE = {"CRITICAL": 90, "HIGH": 70, "MEDIUM": 40, "LOW": 10}
_UNKNOWN_SCORE = 50  # absent signal -> assume the middle, surface it
_DEMOTE = {"CRITICAL": "HIGH", "HIGH": "MEDIUM", "MEDIUM": "LOW", "LOW": "LOW"}


def _verb_forms(verb: str) -> set:
    forms = {verb, verb + "s", verb + "es", verb + "ed", verb + "d", verb + "ing",
             verb + verb[-1] + "ed", verb + verb[-1] + "ing"}  # transferred, dropping, getting
    if verb.endswith("e"):
        forms.add(verb[:-1] + "ing")  # deleting, wiring
    if verb.endswith("y"):
        forms |= {verb[:-1] + "ies", verb[:-1] + "ied"}  # queries, queried
    return forms


# The forms of a READ verb are written out, not generated: a generated form can be a different word
# ("read" + "d" is "readd", re-add), and a read verb is exactly what ALLOW trusts. The risky tiers may
# over-generate, because an extra form there only makes more names escalate.
_READ_VERB_FORMS = {
    "read": ("read", "reads", "reading"),
    "get": ("get", "gets", "getting"),
    "list": ("list", "lists", "listed", "listing"),
    "search": ("search", "searches", "searched", "searching"),
    "query": ("query", "queries", "queried", "querying"),
    "find": ("find", "finds", "finding"),
    "show": ("show", "shows", "showed", "showing"),
    "view": ("view", "views", "viewed", "viewing"),
    "inspect": ("inspect", "inspects", "inspected", "inspecting"),
    "describe": ("describe", "describes", "described", "describing"),
}


def _build_token_table() -> Dict[str, tuple]:
    table: Dict[str, tuple] = {}
    for tier in _TIER_ORDER:  # most severe first: setdefault lets the worst tier win a collision
        for verb in _TIER_VERBS[tier]:
            forms = _READ_VERB_FORMS[verb] if tier == "LOW" else _verb_forms(verb)
            for form in forms:
                table.setdefault(form, (tier, verb))
    return table


_TOKEN_TABLE = _build_token_table()

# The only words allowed after a read verb in an ALLOW action name. Closed on purpose: a word
# that is not here (including every verb, every glued or misspelled word, every unknown noun)
# makes the action ESCALATE. Nothing in this set may be a verb form in _TIER_VERBS or a
# sensitive noun; tests/test_gate_decision.py enforces both.
_READ_NOUNS = frozenset({
    "file", "files", "dir", "dirs", "directory", "directories", "folder", "folders",
    "path", "paths", "page", "pages", "doc", "docs", "document", "documents",
    "record", "records", "row", "rows", "table", "tables", "column", "columns",
    "schema", "schemas", "database", "databases", "db", "log", "logs",
    "status", "info", "information", "metadata", "meta", "list", "lists",
    "item", "items", "entry", "entries", "result", "results", "report", "reports",
    "summary", "summaries", "detail", "details", "content", "contents", "text", "data",
    "count", "counts", "stat", "stats", "statistics", "version", "versions",
    "tree", "index", "size", "name", "names", "id", "ids",
    "user", "users", "customer", "customers", "account", "accounts",
    "order", "orders", "ticket", "tickets", "issue", "issues",
    "repo", "repos", "repository", "repositories", "branch", "branches", "commit", "commits",
    "diff", "comment", "comments", "event", "events", "metric", "metrics",
    "invoice", "invoices", "product", "products", "project", "projects",
    "team", "teams", "org", "organization", "organizations",
    "contact", "contacts", "lead", "leads", "deal", "deals", "note", "notes",
    "task", "tasks", "calendar", "profile", "profiles",
    # function words that make a name read naturally ("list files in dir", "get user by id")
    "by", "of", "for", "in", "the", "a", "an", "all", "my", "current", "latest", "recent", "top",
})
# Reading these is not harmless: a read-only verb on credentials is how they leave. A hit
# anywhere in the action or the resource makes the action ESCALATE. Spelled-out forms such as
# "api key" or "credit card" are caught by the joined-token regexes further down.
_SENSITIVE_NOUNS = frozenset({
    "secret", "secrets", "credential", "credentials", "cred", "creds",
    "password", "passwords", "passwd", "pwd", "pw", "passphrase",
    "token", "tokens", "bearer", "apikey", "jwt", "otp", "pin", "cvv", "iban", "ssn", "pii", "phi",
    "cookie", "cookies", "mnemonic", "seed", "wallet", "keystore", "keychain", "vault",
    "kubeconfig", "dotenv", "env", "shadow", "sudoers", "privilege", "privileges",
    "admin", "root", "rsa", "pem",
    "npmrc", "netrc", "pypirc", "pgpass", "htpasswd", "tfstate", "tfvars", "keytab", "keyring",
    "totp", "hotp", "mfa", "ssns", "ibans",
    "pass", "pswd", "passcode", "pincode", "keepass", "lastpass", "bitwarden", "envrc", "keypair",
    "confidential", "classified", "restricted", "private", "birthdate", "birthday", "biometric", "genome",
    "ntlm", "authenticator", "webhook", "htdigest", "viminfo", "heapdump", "coredump", "dsn", "nda",
})
# Words that are ordinary in an ACTION name ("get_history", "read_file") but name a secret-bearing
# thing when they are the RESOURCE ("zsh_history", "wp-config.php", "/proc/self/environ").
_SENSITIVE_RESOURCE_NOUNS = frozenset({
    "history", "key", "keys", "environ", "environment", "config", "configuration", "settings",
    "login", "logins", "sam", "gshadow", "opasswd", "proc", "cmdline", "pat", "dob",
})
# Secret-bearing words that are often glued to another word ("accesstoken", "dbpassword",
# "privatekey"). Checked as substrings of the joined action and resource, also with common
# digit-for-letter swaps folded ("passw0rd", "s3cret"). Longer than four letters on purpose,
# except "pii", so ordinary words are not swept in.
_SENSITIVE_STEMS = (
    "password", "passwd", "secret", "token", "apikey", "credential", "privatekey", "privkey",
    "sshkey", "creditcard", "cardnumber", "socialsecurity", "keyvault", "sessionid", "idrsa",
    "userdata", "pii", "2fa", "diagnos", "payroll", "salar", "patient", "medical",
    "rsakey", "krb5cc", "otpauth", "passport", "prescription", "therapy", "secring",
    "databaseurl", "mongouri", "redisurl", "serviceaccount", "ntds", "lsass", "sendmail", "useradd",
    "userdel", "visudo", "xpcmdshell", "spexecutesql", "rmrf", "dropdb", "dropall", "onetimecode",
)
_LEET = str.maketrans("013457", "oieast")
# A "1" stands for an "i" or an "l" ("d1sable", "de1ete"), so undoing the swaps is done both ways.
_LEET_TABLES = (_LEET, str.maketrans("013457", "oleast"))
_GLUED_VERB_EXEMPT = frozenset({"wire", "sell", "mint", "trade", "payment"})
# Words of four or more letters are also matched as substrings of a single token ("keychains",
# "configs", "mywallet.txt"); shorter words, which sit inside ordinary words, match only as a whole
# token, with a plural s, or glued to one of these common filler words ("keyfile", "mykey").
_GLUE = frozenset({"my", "the", "file", "files", "data", "dump", "store", "backup", "list", "text", "db", "raw"})
_LONG_ACTION_WORDS = tuple(sorted(w for w in _SENSITIVE_NOUNS if len(w) >= 4))
_SHORT_ACTION_WORDS = tuple(sorted(w for w in _SENSITIVE_NOUNS if len(w) < 4))
_LONG_RESOURCE_WORDS = tuple(sorted(w for w in _SENSITIVE_RESOURCE_NOUNS if len(w) >= 4 and w != "proc"))
_SHORT_RESOURCE_WORDS = tuple(sorted(w for w in _SENSITIVE_RESOURCE_NOUNS if len(w) < 4 or w == "proc"))


def _glued_critical_verb(token: str):
    """A CRITICAL verb glued to the front of a resource word ("deleteall", "dropdb", "deployment") is
    treated as that verb. Words shorter than four letters and a few common English words are exempt."""
    if token in _TOKEN_TABLE or token in vocab_read_nouns():
        return None
    for verb in _TIER_VERBS["CRITICAL"]:
        if len(verb) >= 4 and verb not in _GLUED_VERB_EXEMPT and token.startswith(verb):
            return verb
    return None


def vocab_read_nouns():
    return _READ_NOUNS


def _short_hit(token: str, words) -> bool:
    for w in words:
        if token == w or token == w + "s":
            return True
        if token.startswith(w) and token[len(w):] in _GLUE:
            return True
        if token.endswith(w) and token[:-len(w)] in _GLUE:
            return True
    return False


def _is_sensitive(a_tokens: List[str], r_tokens: List[str]) -> bool:
    tokens = a_tokens + r_tokens
    if any(t in _SENSITIVE_NOUNS for t in tokens) or any(t in _SENSITIVE_RESOURCE_NOUNS for t in r_tokens):
        return True
    if any(_short_hit(t, _SHORT_ACTION_WORDS) for t in tokens):
        return True
    if any(_short_hit(t, _SHORT_RESOURCE_WORDS) for t in r_tokens):
        return True
    if any(w in t for t in tokens for w in _LONG_ACTION_WORDS):
        return True
    if any(w in t for t in r_tokens for w in _LONG_RESOURCE_WORDS):
        return True
    if any(len(t) > 3 and (t.endswith("key") or t.endswith("keys")) for t in r_tokens):
        return True   # hostkey, apikey-style names: a resource that ends in 'key' is a key
    flat = "".join(tokens)
    if any(stem in flat for stem in _SENSITIVE_STEMS + _PHRASE_STEMS):
        return True
    return False


# Multi-word sensitive things, written out one by one so each is pinned by a test. Matched below as
# _PHRASE_STEMS against the joined tokens of the action and resource.
_SENSITIVE_PHRASE_LIST = (
    "api key", "private key", "signing key", "access key", "secret key", "master key", "ssh key",
    "encryption key", "session id", "auth code", "security code", "recovery code",
    "credit card", "card number", "bank account", "routing number", "social security",
    "passport number", "swift code", "dea number",
    "medical record", "health record", "patient record", "connection string",
    "id ed 25519", "id ecdsa", "id dsa", "authorized key", "known host",
    "login data", "shell history", "zsh history", "fish history", "command history",
    "web data", "local state", "auth header", "authorization header", "cc number",
    "backup code", "driver license", "lab result", "date of birth", "recovery phrase", "one time code",
    "driver licence", "driving licence", "national id", "tax return", "bank statement", "criminal record",
    "hiv status", "hiv result", "dna result", "genetic test", "birth date", "scratch code", "database dump",
    "sentry dsn", "pg authid",
)


def _phrase_stems(phrases) -> tuple:
    """Every phrase with its spaces removed ("accesskey"), with any of its words in the plural
    ("accesskeys", "driverslicense", "datesofbirth"), and, for two words, in the other order
    ("historyshell"). Matched as substrings of the joined words, so glued forms hit too."""
    stems = set()
    for phrase in phrases:
        words = phrase.split(" ")
        orders = [words] + ([list(reversed(words))] if len(words) == 2 else [])
        for order in orders:
            for marks in itertools.product(("", "s"), repeat=len(order)):
                stems.add("".join(w + m for w, m in zip(order, marks)))
    return tuple(sorted(stems))


_PHRASE_STEMS = _phrase_stems(_SENSITIVE_PHRASE_LIST)
# A read-only ACTION must be a plain identifier or phrase, and a read-only RESOURCE a plain path
# or name. Full match, because `$` would let a trailing newline through. Shell metacharacters,
# quotes, backticks, control characters and the like mean the string is a command line.
_SIMPLE_ACTION = re.compile(r"[A-Za-z0-9 _\-]+")
_SIMPLE_RESOURCE = re.compile(r"[A-Za-z0-9 _.\-/]+")
# File types a read-only ALLOW may name: source code and prose. Configuration, data, key, state and
# archive formats are where secrets live, so a resource that ends in any other extension escalates,
# as does any hidden or parent-directory segment (.env, .ssh, .git, ..). A bare name with no
# extension (a table, a label, a Makefile) is judged by the word lists like any other name.
_ORDINARY_EXTENSIONS = frozenset({
    "md", "markdown", "txt", "rst",
    "py", "js", "mjs", "cjs", "ts", "tsx", "jsx", "java", "kt", "go", "rs", "c", "h", "cc", "cpp",
    "hpp", "cs", "rb", "php", "swift", "html", "htm", "css",
})
# A network address written the ways resolvers accept: four dotted numbers of any width (octal
# forms such as 0177.0.0.1 included), a hexadecimal address, or one long integer (2130706433).
# Short dotted numbers such as 1.2.3 stay ordinary (versions far more often than addresses), unless
# the last number is too large for a version or the first begins a loopback address (127.1).
# Words, besides the read nouns, that an ALLOW resource may be made of. Closed on purpose, like the nouns:
# a resource with any other word (a name this gate has never seen) goes to a human. Digits are allowed
# between words (versions, dates, page numbers), never alone.
_RESOURCE_EXTRA_WORDS = frozenset({
    "readme", "license", "changelog", "contributing", "main", "src", "lib", "app", "test", "tests",
    "example", "examples", "guide", "guides", "spec", "specs", "design", "plan", "plans", "todo", "faq",
    "overview", "intro", "introduction", "usage", "api", "cli", "web", "site", "blog", "article",
    "articles", "lesson", "lessons", "tutorial", "tutorials", "reference", "references", "manual",
    "manuals", "topic", "topics", "section", "sections", "chapter", "chapters",
})
# Nouns that are fine in an ACTION ("query_db users") but name a data store or a log when they are the
# RESOURCE: "db.php", "database.py" and "logs/" are where connection strings and personal data sit.
_RESOURCE_EXCLUDED_WORDS = frozenset({"db", "database", "databases", "log", "logs"})
_RESOURCE_VOCABULARY = (_READ_NOUNS - _RESOURCE_EXCLUDED_WORDS) | _RESOURCE_EXTRA_WORDS | _ORDINARY_EXTENSIONS


def _identifier_shaped_number(text: str) -> bool:
    """A number that is probably an identifier (a card, a social security number, an address written as one
    integer): such a value is signed into the receipt in clear text and is not a name."""
    return bool(_SSN_SHAPE.search(text) or _has_card_number(text) or re.search(r"[0-9]{9,}", text))


def _resource_in_vocabulary(r_tokens: List[str]) -> bool:
    words = [t for t in r_tokens if not t.isdigit()]
    return bool(words) and all(t in _RESOURCE_VOCABULARY for t in words)


_NUMERIC_ADDRESS = re.compile(r"[0-9]+(?:\.[0-9]+){3}|0[xX][0-9a-fA-F]+(?:\.[0-9a-fA-FxX]+){0,3}|[0-9]{9,}")
_SHORT_DOTTED = re.compile(r"([0-9]+)\.([0-9]+)(?:\.([0-9]+))?")
# A host name as the first part of a multi-part resource: "example.com/api".
_HOST_NAME = re.compile(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
_LOCAL_HOSTS = frozenset({"localhost", "localhost4", "localhost6", "ip6-localhost", "ip6-loopback",
                          "instance-data"})
# Data and executable types that do not make a name safe when an ordinary extension follows them
# ("users.csv.txt", "x.tar.gz.md").
_RISKY_MIDDLE_EXTENSIONS = frozenset({
    "sql", "csv", "tsv", "db", "sqlite", "sqlite3", "mdb", "json", "yaml", "yml", "xml", "ini", "cfg",
    "conf", "toml", "env", "key", "pem", "p12", "pfx", "crt", "cer", "tar", "gz", "tgz", "zip", "rar",
    "7z", "bz2", "xz", "bak", "backup", "dump", "log", "exe", "dll", "so", "bin", "sh", "bat", "ps1",
    "kdbx", "keystore", "jks", "ldb", "leveldb", "wallet", "dat", "lock",
})


def _part_value(part: str) -> int:
    """A number as an address parser reads it: a leading zero means octal ("0177" is 127)."""
    if len(part) > 1 and part[0] == "0" and all(c in "01234567" for c in part):
        return int(part, 8)
    return int(part)


def _looks_like_address(segment: str) -> bool:
    seg = segment.lower().rstrip(".")      # "127.0.0.1." is the same host to a URL parser
    if _NUMERIC_ADDRESS.fullmatch(seg) or seg in _LOCAL_HOSTS or re.fullmatch(r"0+", seg):
        return True            # "0" is this host
    m = _SHORT_DOTTED.fullmatch(seg)
    if m:
        parts = [_part_value(p) for p in m.groups() if p is not None]
        return parts[0] in (0, 127) or parts[-1] > 255
    return False


def _resource_is_ordinary(resource: str) -> bool:
    """True when the resource names something a read-only ALLOW may cover: no hidden or parent
    segment, and a final segment that is either a bare name or ends in an ordinary extension
    (or is purely numeric, as in a version or an address)."""
    resource = resource.strip()
    if resource.startswith("/"):
        return False  # absolute (and network) paths are for a human to approve
    if resource.startswith("-"):
        return False  # would read as an option to any tool the caller hands it to
    if resource.count(" ") >= 2:
        return False  # a phrase or a statement, not a name
    if "--" in resource:
        return False  # the start of a comment in a query language
    # Judge every segment as its whitespace-trimmed self, so " .git" and "docs/ ./x" cannot hide.
    segments = [seg.strip() for seg in resource.split("/")]  # a backslash never gets this far
    if any(seg.startswith(".") and seg != "." for seg in segments):
        return False
    if any(_looks_like_address(seg) for seg in segments):
        return False  # a network address, in any of its usual spellings
    # Judge the last REAL segment: "a.key/", "a.key//" and "a.key/./" all name the file a.key, and
    # many path libraries drop the trailing separator before opening it.
    real = [seg for seg in segments if seg not in ("", ".")]
    if not real:
        return True
    if len(real) > 1 and _HOST_NAME.fullmatch(real[0].rstrip(".")):
        return False  # "example.com/x": a host, then a path
    last = real[-1]
    if "." not in last:
        return True
    if " " in last:
        return False  # "name.ext other.md": more than one name in the last segment
    parts = last.split(".")
    while len(parts) > 1 and parts[-1].isdigit():
        parts.pop()   # a rotation or version counter ("app.log.1", "archive.zip.001") is not the file type
    if len(parts) == 1:
        return True   # a bare name that only carries counters ("1.2.3", "notes.1")
    if any(p.lower() in _RISKY_MIDDLE_EXTENSIONS for p in parts[1:-1]):
        return False  # "users.csv.txt": the data type is still the data type
    return parts[-1].lower() in _ORDINARY_EXTENSIONS

_CAMEL_LOWER_UPPER = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_CAMEL_ACRONYM = re.compile(r"(?<=[A-Z])(?=[A-Z][a-z])")
_LETTER_DIGIT = re.compile(r"(?<=[A-Za-z])(?=[0-9])|(?<=[0-9])(?=[A-Za-z])")
_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def _tokens(label: str) -> List[str]:
    """Split an identifier or phrase into lowercase tokens. NFKC first, so full-width
    letters fold to ASCII instead of hiding a verb."""
    text = unicodedata.normalize("NFKC", str(label))
    text = _CAMEL_LOWER_UPPER.sub(" ", text)
    text = _CAMEL_ACRONYM.sub(" ", text)
    text = _LETTER_DIGIT.sub(" ", text)
    return [t for t in _NON_ALNUM.split(text.lower()) if t]


# ---- egress data-sensitivity classification (heuristic, for check_egress) ----------------
def _words(alternatives: str) -> "re.Pattern[str]":
    """Keyword regex that also matches inside snake_case and SCREAMING_CASE names (DB_PASSWORD, user_ssn):
    a match may not touch a letter or digit, but an underscore is a boundary."""
    return re.compile(r"(?<![A-Za-z0-9])(" + alternatives + r")s?(?![A-Za-z0-9])", re.I)


_RESTRICTED_DATA = _words(
    r"ssn|social.?security|passport.?num(?:ber)?|credit.?card|card.?number|"
    r"bank.?account|routing.?number|iban|swift.?code|"
    r"dea.?number|medical.?record|health.?record|diagnos\w*|date.?of.?birth|birth.?date|dob")
_CONFIDENTIAL_DATA = _words(
    r"passwords?|passwd|pwd|pw|creds?|secrets?|tokens?|api.?keys?|private.?keys?|credentials?|"
    r"bearer|session.?id|auth.?code|signing.?key|access.?keys?")
_INTERNAL_DATA = _words(
    r"internal|draft|proprietary|roadmap|unreleased|"
    r"embargoed|pre.?release|nda|board.?minutes")
# Values that look like secrets or identifiers even when no keyword names them.
_SSN_SHAPE = re.compile(r"(?<!\d)\d{3}[- ]\d{2}[- ]\d{4}(?!\d)")
_CARD_SHAPE = re.compile(r"(?<!\d)(?:\d[ ._-]?){12,18}\d(?!\d)")
_SECRET_SHAPES = re.compile(
    r"(?:AKIA|ASIA)[0-9A-Z]{16}|gh[opsu]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|"
    r"[Bb]earer\s+[A-Za-z0-9._~+/=-]{20,}|"
    r"sk-[A-Za-z0-9_-]{20,}|[rs]k_(?:live|test)_[A-Za-z0-9]{10,}|AIza[0-9A-Za-z_-]{35}|"
    r"glpat-[A-Za-z0-9_-]{20,}|ya29\.[A-Za-z0-9_-]{20,}|hf_[A-Za-z0-9]{30,}|npm_[A-Za-z0-9]{30,}|"
    r"pypi-[A-Za-z0-9_-]{40,}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}|"
    r"(?i:authorization)\s*[:=]\s*(?i:basic|bearer|token)\s+\S{8,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|"
    r"(?<![A-Za-z0-9])[A-Za-z0-9_]{0,40}(?i:pass(?:word|wd|phrase)?|pwd|pw|secret|token|key)s?[\"']?\s*[=:]\s*[\"']?[^\s\"']{6,}|"
    r"hooks\.slack\.com/services/[A-Za-z0-9/]{10,}|PuTTY-User-Key-File|"
    r"://[^/\s:@]{0,64}:[^/\s@]{1,128}@")
_JWT_CHUNK = re.compile(r"[A-Za-z0-9_.\-]{30,}")


def _has_jwt(text: str) -> bool:
    """A JSON Web Token: three dot-separated segments, the first starting 'eyJ'. Found by splitting
    candidate runs on '.', so a sample of repeated 'eyJ' costs one pass, not one per repeat."""
    for run in _JWT_CHUNK.finditer(text):
        parts = run.group(0).split(".")
        for k in range(len(parts) - 2):
            a, b, c = parts[k], parts[k + 1], parts[k + 2]
            if a.startswith("eyJ") and len(a) >= 10 and len(b) >= 10 and len(c) >= 10:
                return True
    return False


_MAX_EGRESS_CHARS = 65536
_MAX_PROVIDER_CHARS = 200


def _luhn_ok(digits: str) -> bool:
    total, flip = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if flip:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total += d
        flip = not flip
    return total % 10 == 0


def _has_card_number(text: str) -> bool:
    for m in _CARD_SHAPE.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            return True
    return False


_EGRESS_RETENTION: Dict[str, str] = {
    "NO_MARKERS_FOUND": "no retention constraint implied; this is not clearance to send",
    "INTERNAL": "90-day minimum retention recommended",
    "CONFIDENTIAL": "365-day retention, audit trail recommended",
    "RESTRICTED": "no egress permitted; data must remain within the trust boundary",
}


def _classify_egress(data_sample: str, destination: str) -> tuple[str, str]:
    """Classify data sensitivity based on content markers. Heuristic, not exhaustive."""
    combined = f"{data_sample} {destination}"
    if (_RESTRICTED_DATA.search(combined) or _SSN_SHAPE.search(combined) or _has_card_number(combined)
            or _SECRET_SHAPES.search(combined) or _has_jwt(combined)):
        return "RESTRICTED", ("restricted-class markers detected (PII, financial or health identifiers, "
                              "or a value shaped like a credential)")
    if _CONFIDENTIAL_DATA.search(combined):
        return "CONFIDENTIAL", "confidential-class keywords detected (credentials/keys/tokens)"
    if _INTERNAL_DATA.search(combined):
        return "INTERNAL", "internal-class markers detected (proprietary/draft/embargoed)"
    return ("NO_MARKERS_FOUND", "none of a finite list of sensitive markers was found in the sample; "
            "this is not a determination that the data is safe to send")


def _worst(tiers) -> tuple[str, int]:
    for tier in _TIER_ORDER:
        if tier in tiers:
            return tier, _TIER_SCORE[tier]
    return "UNKNOWN", _UNKNOWN_SCORE


def _tier_for_row(tool: str, capability: str, server: str) -> tuple[str, int]:
    """Tier for one inventory row. The tool NAME's lead word counts fully and its other words one
    tier lower; the DECLARED capability counts fully (the caller said what the tool does); the
    server name counts one tier lower (it is a label, not a verb)."""
    tiers = []
    for pos, tok in enumerate(_tokens(tool)):
        hit = _TOKEN_TABLE.get(tok)
        if hit:
            tiers.append(hit[0] if pos == 0 else _DEMOTE[hit[0]])
    for tok in _tokens(capability):
        hit = _TOKEN_TABLE.get(tok)
        if hit:
            tiers.append(hit[0])
    for tok in _tokens(server):
        hit = _TOKEN_TABLE.get(tok)
        if hit:
            tiers.append(_DEMOTE[hit[0]])
    return _worst(tiers)


# ---- the decision gate: policy ---------------------------------------------------------------
# What the gate DOES with a tier. Fail closed: only a known read-only name is allowed, anything
# the classifier cannot place is escalated to a human, and a critical LEAD verb is denied.
# There is no operator override in this package: a custom policy is a human decision outside it.
_VERDICT_BY_TIER = {
    "LOW": "ALLOW",
    "MEDIUM": "ESCALATE",
    "HIGH": "ESCALATE",
    "CRITICAL": "DENY",
    "UNKNOWN": "ESCALATE",
}
_PERMIT_BY_VERDICT = {
    "ALLOW": "GRANTED",
    "DENY": "DENIED",
    "ESCALATE": "WITHHELD_PENDING_HUMAN",
}
_MAX_LABEL_CHARS = 512
_MAX_MANIFEST_CHARS = 262144
_NOTE_PQ = ("Hybrid signature: Ed25519, plus ML-DSA-65 (and a hash-based leg only if the installed liboqs "
            "still ships one). Each leg signs the same canonical body. A valid leg shows the bytes are unchanged "
            "and were signed by the key embedded for that leg; it does not say who holds that key. Pin the "
            "Ed25519 kid out of band to check the signer. Unsigned field.")
_NOTE_NO_ED = ("No Ed25519 signature was produced on this host: this receipt carries post-quantum signatures only. "
               "A valid signature shows the bytes are unchanged and were signed by the key embedded for that leg; it "
               "does not say who holds that key, and the kid (which names the Ed25519 key) cannot pin it. Unsigned field.")
_NOTE_NO_PQ = ("Ed25519 signature only: no post-quantum signature was produced on this host. A valid signature "
               "shows the bytes are unchanged and were signed by the embedded key; it does not say who holds that "
               "key. Pin the Ed25519 kid out of band to check the signer. Unsigned field.")
_MAX_CONTEXT_CHARS = 65536
_GATE_POLICY_ID = "trust-gate-mcp default read-only-allowlist policy v2"
_GATE_SCOPE_NOTE = (
    "This verdict applies only to actions the caller routes through this gate. Trust Gate MCP "
    "does not observe, intercept or block anything an agent does, and does not check afterward "
    "whether an action happened. ALLOW means the action name is a known read-only name with no "
    "risky or sensitive word anywhere; every other action is escalated or denied. That is a "
    "name-based heuristic, not a determination that an action is safe. Read the verdict from "
    "receipt.decision: the top-level verdict and permit fields are not signed. The action and "
    "resource are recorded in the receipt in clear text, so do not put secrets or personal data "
    "in them; context is recorded as a hash and is not used to decide; triggered_by_type, "
    "triggered_by_source and decision_model are caller claims, signed but not verified. A receipt shows that the "
    "holder of the signing key signed these bytes; on a deployment without bearer "
    "authentication it says nothing about who asked."
)


def _gate_assessment(action: str, resource: str) -> Dict[str, Any]:
    """Classify an action and choose a verdict. Deterministic, and it looks only at the
    action name and the resource: never at context, attestation fields or anything else a
    caller could use to talk the gate into a permit. Reasons are built from fixed strings and
    fixed verb names, never from the caller's own text.

    Order of decision:
      1. non-ASCII text after normalisation           -> UNKNOWN (escalate)
      2. a CRITICAL verb as the LEAD word of the action -> CRITICAL (deny)
      3. a sensitive-data noun or marker anywhere     -> HIGH (escalate)
      4. a HIGH or MEDIUM verb as the lead word       -> that tier (escalate)
      5. any listed risky word elsewhere in the action, or anywhere in the resource
                                                       -> HIGH or MEDIUM (escalate; a human decides)
      6. a known read verb, then only known nouns or digits, plain action, plain resource that
         is not hidden and is not a configuration, data, key or archive file
                                                       -> LOW (allow)
      7. everything else                              -> UNKNOWN (escalate)
    """
    a_norm = unicodedata.normalize("NFKC", action)
    r_norm = unicodedata.normalize("NFKC", resource)
    if not (a_norm.isascii() and r_norm.isascii()):
        tier = "UNKNOWN"
        reasons = ["non-ASCII characters remain after normalisation; not classified"]
    else:
        a_tokens = _tokens(action)
        r_tokens = _tokens(resource)
        # The same text with digit-for-letter swaps read as the letters ("sh4d0w" as "shadow"): a word
        # the lists know is caught either way. The plain pass alone still decides what is ALLOWED.
        swapped = [(_tokens(a_norm.lower().translate(table)), _tokens(r_norm.lower().translate(table)))
                   for table in _LEET_TABLES]
        lead = _TOKEN_TABLE.get(a_tokens[0]) if a_tokens else None
        others: Dict[str, str] = {}
        for a_toks, r_toks in [(a_tokens, r_tokens)] + swapped:
            for tok in a_toks[1:] + r_toks:
                hit = _TOKEN_TABLE.get(tok)
                if hit and hit[0] != "LOW":
                    others[hit[1]] = hit[0]
            for tok in r_toks:
                glued = _glued_critical_verb(tok)
                if glued:
                    others[glued] = "CRITICAL"
        sensitive = any(_is_sensitive(a_toks, r_toks) for a_toks, r_toks in [(a_tokens, r_tokens)] + swapped)
        if lead and lead[0] == "CRITICAL":
            tier = "CRITICAL"
            reasons = [f"critical lead verb detected: {lead[1]}"]
        elif sensitive:
            tier = "HIGH"
            reasons = ["sensitive-data marker detected in the action or resource "
                       "(credentials, keys, tokens or regulated personal data)"]
            if lead and lead[0] in ("HIGH", "MEDIUM"):
                reasons.append(f"{lead[0].lower()}-risk lead verb detected: {lead[1]}")
        elif lead and lead[0] in ("HIGH", "MEDIUM"):
            tier = lead[0]
            reasons = [f"{tier.lower()}-risk lead verb detected: {lead[1]}"]
        elif others:
            tier = "HIGH" if any(t in ("CRITICAL", "HIGH") for t in others.values()) else "MEDIUM"
            reasons = [f"listed risky verb(s) outside the lead position: {', '.join(sorted(others))}; "
                       "a human decides"]
        elif not a_tokens or not lead or lead[0] != "LOW":
            tier = "UNKNOWN"
            reasons = ["the action name does not start with a recognised read-only verb; not classified"]
        elif not _SIMPLE_ACTION.fullmatch(a_norm) or re.search(r"(?:^|\s)-", a_norm):
            tier = "UNKNOWN"
            reasons = ["the action name contains characters other than letters, digits, spaces, _ and -, or a "
                       "word that starts with - (it would read as an option); not classified"]
        elif not all(t in _READ_NOUNS or t.isdigit() for t in a_tokens[1:]):
            tier = "UNKNOWN"
            reasons = ["the action name contains words outside the built-in read-only vocabulary; "
                       "not classified"]
        elif not _SIMPLE_RESOURCE.fullmatch(r_norm):
            tier = "UNKNOWN"
            reasons = ["the resource contains characters other than letters, digits, spaces and "
                       "_ . - /; not classified"]
        elif lead[1] == "query" and re.search(r"\s", r_norm.strip()):
            tier = "UNKNOWN"
            reasons = ["a multi-word resource after a query verb is a query expression, not a name; "
                       "not classified"]
        elif not _resource_is_ordinary(r_norm):
            tier = "UNKNOWN"
            reasons = ["the resource is an absolute or hidden path, a parent-directory path, a network address, "
                       "or a file type other than ordinary source code or prose; not classified"]
        elif not _resource_in_vocabulary(r_tokens):
            tier = "UNKNOWN"
            reasons = ["the resource contains a word outside the built-in vocabulary of ordinary names; "
                       "not classified"]
        elif _identifier_shaped_number(f"{a_norm} {r_norm}"):
            tier = "UNKNOWN"
            reasons = ["a number that looks like a card, a social security number or an address appears in the "
                       "name or resource; not classified"]
        else:
            tier = "LOW"
            reasons = ["known read-only action name; no risky or sensitive word found"]
    return {
        "tier": tier,
        "score": _TIER_SCORE.get(tier, _UNKNOWN_SCORE),
        "verdict": _VERDICT_BY_TIER[tier],
        "reasons": reasons,
    }


def _ascii_hash(s: str) -> str:
    # surrogatepass: a lone surrogate hashes deterministically instead of raising
    return "sha256:" + hashlib.sha256(s.encode("utf-8", "surrogatepass")).hexdigest()


def _kid(receipt: Dict[str, Any]) -> str:
    """Key identifier = the first 32 hex characters (128 bits) of the sha256 of the canonical base64 of
    the receipt's Ed25519 public key. It names a key; it does not show who used it. It is copyable, so a
    kid printed in a receipt proves nothing by itself: `verify_receipt` reports a kid only when that
    key's own Ed25519 signature verified, and `expected_kid` pins it. 128 bits is ample for the
    second-preimage resistance a pin relies on (it is not 128-bit collision resistance); a shorter
    prefix would not be. Empty string for a receipt with no usable Ed25519 public key."""
    pub = receipt.get("verify_pubkey_b64", "") if isinstance(receipt, dict) else ""
    if not pub or not isinstance(pub, str):
        return ""
    # Hash the canonical re-encoding of the 32 key bytes, so a different spelling of the same key
    # (padding, non-canonical trailing bits) cannot produce a different kid.
    try:
        raw = base64.b64decode(pub, validate=True)
    except (ValueError, binascii.Error):
        return ""
    if len(raw) != 32:
        return ""
    return hashlib.sha256(base64.b64encode(raw)).hexdigest()[:32]


def _mint(manifest: Dict[str, Any], decision: str) -> Dict[str, Any]:
    """Reuse OAO's mint_receipt for every receipt -- one signing path, hybrid-signed by default."""
    if _oao_receipt is None:
        return {
            "error": "openagentontology_unavailable",
            "remedy": "pip install \"openagentontology[pq]\"",
            "decision": decision,
            "manifest": manifest,
        }
    try:
        too_big = len(json.dumps(manifest, ensure_ascii=True, default=str)) > _MAX_MANIFEST_CHARS
    except (TypeError, ValueError):
        return {"error": "manifest_not_serialisable", "decision": decision}
    if too_big:
        return {"error": "manifest_too_large", "detail": f"the receipt body may not exceed {_MAX_MANIFEST_CHARS} characters",
                "decision": decision}
    try:
        receipt = _oao_receipt.mint_receipt(manifest, decision=decision)
    except Exception:   # a key that cannot be read or written must not leak a path in an error message
        return {"error": "mint_failed", "detail": "the receipt could not be signed on this host", "decision": decision}
    has_pq = bool(receipt.get("ml_dsa_signature_b64") or receipt.get("slh_dsa_signature_b64"))
    has_ed = bool(receipt.get("signature_b64"))
    receipt["note_pq"] = _NOTE_PQ if (has_pq and has_ed) else _NOTE_NO_PQ if has_ed else _NOTE_NO_ED  # replaces the primitive's wording, which claims more than is true
    # Add the kid for key-rotation continuity. Cost: one sha256 per mint. Inherited by
    # every tool because they all funnel through _mint.
    receipt["kid"] = _kid(receipt)
    return receipt


# Values a caller may not put in a receipt made by mint_action_receipt, because they read as a
# gate verdict or permit. Compared after NFKC, lower-casing and removing everything that is not a
# letter or digit, so "ALLOW.", "A L L O W", "Allowed" and "DECISION-COMMITTED" are all caught.
# Both fields must also be printable ASCII, which removes look-alike and invisible characters.
_RESERVED_DECISION_CANON = frozenset({
    "allow", "allowed", "deny", "denied", "escalate", "escalated", "grant", "granted",
    "approve", "approved", "permit", "permitted", "permitgranted", "withheldpendinghuman",
    "decisioncommitted", "committed", "notissued",
})
# A decision that merely CONTAINS one of these reads as a verdict too ("GATE_ALLOW", "ALLOW_ALL",
# "ACCESS_GRANTED"). This is a best-effort convenience, not the trust boundary: the boundary is the
# signed `issuer_tool` field, which a consumer must check (see README).
_RESERVED_DECISION_FRAGMENTS = ("allow", "deny", "denied", "escalat", "grant", "permit", "withheld",
                                "notissued", "committed", "approved", "approve")


def _is_reserved_decision(decision: Any) -> bool:
    canon = _canon_alnum(decision)
    for form in [canon] + [canon.translate(t) for t in _LEET_TABLES]:   # "ALL0W", "GR4NTED", "A11OW" read as verdicts too
        if form in _RESERVED_DECISION_CANON or any(f in form for f in _RESERVED_DECISION_FRAGMENTS):
            return True
    return False


def _looks_like_gate_operation(operation: Any) -> bool:
    """An operation name that could pass for the gate's own ("decision_gate_commit"): it mentions
    both words, in any order, with any separators or extra letters between them, or it has "gate"
    as a word of its own ("gate_commit", "trust-gate", "gateVerdict")."""
    # "decision" and "gate" contain no letter that a digit can stand in for twice over (no l), so one reading of
    # the swaps is enough here.
    canon = _canon_alnum(operation).translate(_LEET)
    return (("decision" in canon and "gate" in canon) or canon == "gate"
            or "gate" in _tokens(str(operation).translate(_LEET)))

_ATTESTATION_ALLOW = re.compile(r"[A-Za-z0-9._\-/]{1,80}")


_SYMBOL_FOLD = str.maketrans("@$!", "asi")   # "ALL0W", "g@te" and "GR4NTED" read as the words they imitate


def _canon_alnum(value: Any) -> str:
    text = unicodedata.normalize("NFKC", str(value)).lower().translate(_SYMBOL_FOLD)
    return re.sub(r"[^a-z0-9]+", "", text)


def _safe_attestation(val: str) -> str:
    """Allowlist attestation field values by character class: [A-Za-z0-9._-/] max 80 chars.
    Returns empty on reject. This limits the SHAPE of the value, not its meaning: an allowed value
    can still be a name or an identifier, and it is signed in clear text. Do not put personal
    data in it."""
    return val if _ATTESTATION_ALLOW.fullmatch(val) else ""


def _require_pq_default() -> bool:
    """Env switch (default ON). Accepts BOTH `TRUST_GATE_REQUIRE_PQ` and `OAO_REQUIRE_PQ`
    so one variable configures this server and the signing primitive. `TRUST_GATE_REQUIRE_PQ`
    wins when it is non-empty. Only an explicit 0 / false / no / off turns it off; any other value, including a typo,
    leaves it ON (fail closed). When ON, verify FAILS unless at least one post-quantum leg
    (ML-DSA-65 or a hash-based leg) verifies; the Ed25519-only path is still available for callers that
    pass require_pq=False explicitly."""
    raw = (os.environ.get("TRUST_GATE_REQUIRE_PQ")
           or os.environ.get("OAO_REQUIRE_PQ")
           or "true").strip().lower()
    return raw not in ("0", "false", "no", "off")


_SIGNED_BODY_KEYS = ("atom_id", "type", "decision", "evidence_hash", "signed_at")
_SIGNATURE_KEYS = frozenset({
    "signature_b64", "verify_pubkey_b64", "ml_dsa_signature_b64", "ml_dsa_public_key_b64",
    "slh_dsa_signature_b64", "slh_dsa_public_key_b64",
})
_COVERED_TOP_LEVEL = frozenset(_SIGNED_BODY_KEYS) | _SIGNATURE_KEYS | {"evidence"}


def _verify(receipt: Dict[str, Any], *, require_pq: Optional[bool] = None,
            expected_kid: Optional[str] = None) -> Dict[str, Any]:
    if _oao_receipt is None:
        return {"ok": False, "reason": "openagentontology not installed (cannot verify)"}
    try:
        out = _oao_receipt.verify_receipt(receipt)
    except Exception:  # a hostile or malformed receipt must give a clean "no", never a stack trace
        return {"ok": False, "reason": "receipt is malformed and could not be verified"}
    actual_kid = _kid(receipt)
    legs = out.get("legs") if isinstance(out.get("legs"), dict) else {}
    ed_ok = legs.get("ed25519") == "ok"
    # The kid fingerprints the Ed25519 public key the receipt carries. It means something only when
    # that key's own signature verified: otherwise it is a public string anyone can copy into a
    # receipt signed with other keys. Report it only in that case.
    out["kid"] = actual_kid if ed_ok else ""
    out["signed_fields"] = ([k for k in _SIGNED_BODY_KEYS if k in receipt]
                            + (["evidence (through evidence_hash)"] if "evidence" in receipt else []))
    out["unsigned_top_level_keys"] = sorted(str(k) for k in receipt if k not in _COVERED_TOP_LEVEL)

    # 1. A receipt with no signature proves nothing: anyone can build one. (The underlying
    #    primitive reports ok=True for it so that legacy files still parse; this server does not.)
    if out.get("ok") and not out.get("signed"):
        out["ok"] = False
        out["reason"] = "receipt carries no signature; an unsigned receipt proves nothing"

    # 1b. A receipt that names an Ed25519 signer (a public key or a kid) must carry a valid signature from
    #     that key. Otherwise the parts that read as an identity belong to nobody who signed: anyone can
    #     copy a genuine key and kid into a receipt whose only signatures are their own.
    if out.get("ok") and not ed_ok and (receipt.get("verify_pubkey_b64") or receipt.get("kid")):
        out["ok"] = False
        out["reason"] = ("the receipt names an Ed25519 signer (public key or kid) but carries no valid "
                         "signature from that key")

    # 2. The kid is outside the signed bytes, so check it against the key the receipt carries.
    claimed = receipt.get("kid")
    if out.get("ok") and claimed and str(claimed) != actual_kid:
        out["ok"] = False
        out["reason"] = "the receipt's kid does not match its embedded public key"

    # 3. Optional pin: the caller says which key it expects. Without a pin, a valid result means
    #    only that whoever holds the embedded key(s) signed these bytes. A pin identifies the
    #    ED25519 key, so it counts only when that key's own signature verified: the post-quantum
    #    legs carry their own embedded keys, which the kid does not cover, so they cannot stand in.
    #    `signer_pinned` is True only when a pin was supplied, matched and the result is ok.
    out["signer_pinned"] = False
    matched = False
    if out.get("ok") and ed_ok and not actual_kid:
        # The Ed25519 leg verified against a key that is not in canonical base64 (the primitive
        # decodes leniently). No kid can be derived for it, so nothing about it can be pinned.
        out["ok"] = False
        out["reason"] = "the receipt's Ed25519 public key is not in canonical form, so its kid cannot be confirmed"
    was_ok = bool(out.get("ok"))  # only a still-ok result may have its reason replaced by the pin's
    if expected_kid is not None:
        want = str(expected_kid).strip().lower()
        if not re.fullmatch(r"[0-9a-f]{32}", want):
            out["ok"] = False
            out["expected_kid_matched"] = False
            if was_ok:
                out["reason"] = ("expected_kid is blank or malformed; pass the 32-hex kid of the key you "
                                 "trust, or omit it")
        elif not ed_ok:
            out["ok"] = False
            out["expected_kid_matched"] = False
            if was_ok:
                out["reason"] = ("cannot confirm the signer: the Ed25519 signature of the pinned key did not "
                                 "verify (the post-quantum legs alone do not identify who signed)")
        elif want == actual_kid:
            out["expected_kid_matched"] = True
            matched = True
        else:
            out["ok"] = False
            out["expected_kid_matched"] = False
            if was_ok:
                out["reason"] = "signer mismatch: the receipt was not signed by the expected key (kid)"

    # 4. PQ-required gate.
    must = _require_pq_default() if require_pq is None else bool(require_pq)
    if must and out.get("ok") and out.get("signed"):
        legs = out.get("legs", {})
        pq_ok = any(legs.get(name) == "ok" for name in ("ml_dsa", "slh_dsa"))
        if not pq_ok:
            # No PQ leg verified -- either both stripped, or none installed. A receipt with no valid
            # post-quantum signature is refused under PQ-required mode. This shows a PQ signature is
            # present and valid; it does not show whose it is (the kid covers Ed25519 only, so a
            # stranger's PQ leg added to a genuine receipt passes). A server that installs only ML-DSA-65 (no hash-based leg)
            # still serves valid PQ verifications. Requiring BOTH was over-strict and broke
            # consumers when the hash-based backend was unavailable.
            states = ", ".join(f"{n}={legs.get(n, 'absent')}" for n in ("ml_dsa", "slh_dsa"))
            out["ok"] = False
            out["reason"] = (f"PQ-required: no post-quantum signature leg verified ({states}). "
                             "Set TRUST_GATE_REQUIRE_PQ=false (or pass require_pq=False) to "
                             "allow Ed25519-only verification of legacy receipts.")
    out["signer_pinned"] = bool(matched and out.get("ok"))
    names = (("ed25519", "Ed25519"), ("ml_dsa", "ML-DSA-65"), ("slh_dsa", "hash-based"))
    verified = [label for key, label in names if legs.get(key) == "ok"]
    out["signature_alg"] = "+".join(verified)  # derived from the legs that verified, not the receipt's own label
    if out.get("ok"):
        # Read these from here, not from your own copy of the receipt: they are the values that were verified
        # (a parser that keeps the first of two duplicate JSON keys would otherwise read another value).
        evidence = receipt.get("evidence")
        ontology = evidence.get("ontology") if isinstance(evidence, dict) else None
        out["verified"] = {k: receipt.get(k) for k in _SIGNED_BODY_KEYS if k in receipt}
        if isinstance(ontology, dict):
            out["verified"].update({k: ontology[k] for k in ("issuer_tool", "operation") if k in ontology})
            out["verified"]["ontology"] = ontology      # bound to the signature through evidence_hash
        out["reason"] = ("unchanged since signing; verified signature(s): " + ", ".join(verified)
                         + ("; signer pinned: the Ed25519 key with the expected kid signed these bytes"
                            if out["signer_pinned"]
                            else "; signer not identified: pass expected_kid to pin the Ed25519 key"))
    return out


# ---- tool implementations (pure, unit-testable) --------------------------------------

def tool_mint_receipt_for_record_change(
    record_id: str,
    object_type: str,
    field: str,
    old_value: str,
    new_value: str,
    changed_by_agent: str,
    tenant: Optional[str] = None,
    policy: str = "per-decision CRM change evidence",
) -> Dict[str, Any]:
    """Mint a hybrid-signed (Ed25519 + ML-DSA-65) receipt for one CRM record change.

    The full new/old values are carried as SHA-256 hashes (tamper-evidence, not redaction;
    low-entropy values are guessable). Designed for any CRM with an MCP integration -- the
    open-core Relaticle, a hosted CRM via its own MCP, or a custom one. The receipt is
    verifiable offline from its certificate alone.
    """
    if not record_id or not object_type or not field:
        return {"error": "record_id, object_type, and field are required"}
    manifest = {
        "operation": "crm_record_change",
        "issuer_tool": "mint_receipt_for_record_change",
        "record_id": str(record_id),
        "object_type": str(object_type),       # Person / Company / Opportunity / ...
        "field": str(field),
        "old_value_hash": _ascii_hash(str(old_value)),
        "new_value_hash": _ascii_hash(str(new_value)),
        "changed_by_agent": str(changed_by_agent),
        "tenant": str(tenant) if tenant else None,
        "policy": policy,
    }
    return _mint(manifest, decision="CRM_RECORD_CHANGED")


def tool_audit_my_agent_inventory(
    inventory: List[Dict[str, Any]],
    notes: Optional[str] = None,
) -> Dict[str, Any]:
    """Rank a CALLER-PROVIDED list of MCP tools by worst-regret if they act.

    The first word of a tool name is weighted most (a leading verb), so `delete_file` ranks above
    `file_delete`; the ranking is a name-based heuristic, not an analysis of what a tool does.

    HONEST SCOPE (in every response): the MCP protocol does NOT let one server introspect
    the host's other installed servers. So this tool cannot auto-discover the caller's
    inventory; the caller must pass it in, e.g.:
        [{"server": "gmail", "tool": "send_email", "capability": "send"}, ...]

    Each row is tiered (CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN) using side-effecting verbs
    in its label. This is a heuristic ranking, not a
    proof; verb inference from a tool NAME can misfire (e.g. "delete_label" vs "delete_user").

    READ-ONLY by design: this tool returns the ranking only and does NOT mint a receipt.
    Receipt-minting is a separate, side-effecting action -- the caller, if it wants the
    audit recorded, calls `mint_action_receipt` with the returned manifest hash. Keeping
    the auditor read-only avoids it being a side-effecting authority surface itself.
    """
    if not isinstance(inventory, list):
        return {"error": "inventory must be a list of {server, tool, capability?} dicts"}
    ranked: List[Dict[str, Any]] = []
    for position, row in enumerate(inventory):
        if not isinstance(row, dict):
            # Never drop a row silently: a shorter ranking would read as "nothing else there".
            return {"error": f"inventory row {position} is not an object with server, tool and capability fields"}
        tier, score = _tier_for_row(str(row.get("tool", "")), str(row.get("capability", "")),
                                    str(row.get("server", "")))
        ranked.append({
            "server": row.get("server"),
            "tool": row.get("tool"),
            "capability": row.get("capability"),
            "tier": tier,
            "worst_regret_score": score,
        })
    ranked.sort(key=lambda r: r["worst_regret_score"], reverse=True)

    # the deterministic manifest the caller can hand to mint_action_receipt
    audit_manifest = {
        "operation": "agent_inventory_audit",
        "scope_note": "input-driven: the MCP protocol does not allow auto-discovery of other servers; the caller supplied the inventory",
        "owasp_anchor": "Agentic Threats T2 (Tool Misuse), T3 (Privilege Compromise); LLM Top 10 LLM06 (Excessive Agency)",
        "ranking_method": "verb-tier heuristic (CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN); not a proof",
        "row_count": len(ranked),
        "ranked": ranked,
        "notes": notes or "",
    }
    return {
        "scope_note": audit_manifest["scope_note"],
        "owasp_anchor": audit_manifest["owasp_anchor"],
        "ranking_method": audit_manifest["ranking_method"],
        "ranked": ranked,
        "audit_manifest_for_receipt": audit_manifest,
        "note": "this tool is read-only and does not mint a receipt; pass audit_manifest_for_receipt to mint_action_receipt if you want the audit recorded",
    }


def tool_mint_action_receipt(
    agent_id: str,
    operation: str,
    target: str,
    policy: str = "agent action evidence",
    inputs: Optional[str] = None,
    decision: str = "ACTION_GOVERNED",
    triggered_by_type: Optional[str] = None,
    triggered_by_source: Optional[str] = None,
    decision_model: Optional[str] = None,
) -> Dict[str, Any]:
    """Mint a hybrid-signed (Ed25519 + ML-DSA-65) receipt for an arbitrary consequential agent action.

    Optional attestation provenance fields (triggered_by_type, triggered_by_source,
    decision_model) are included in the manifest and signed into the receipt when
    provided. These fields are allowlisted to [A-Za-z0-9._-/] max 80 chars.
    """
    if not agent_id or not operation or not target:
        return {"error": "agent_id, operation, and target are required"}
    # A receipt that looks like a gate decision must come from the gate. Without this a caller
    # could hand-mint a signed "ALLOW" / "decision_gate_commit" record with this same tool.
    # Both fields must be printable ASCII (no look-alike or invisible characters) and must not
    # canonicalise to a reserved verdict word or gate operation name.
    for field_name, value in (("decision", decision), ("operation", operation)):
        text = str(value)
        if not text.isascii() or not text.isprintable():
            return {"error": f"{field_name} must be printable ASCII"}
    if (_is_reserved_decision(decision) or _looks_like_gate_operation(operation)
            or _canon_alnum(policy) == _canon_alnum(_GATE_POLICY_ID)):
        return {"error": ("decision values that contain a gate verdict word (allow, deny, escalate, grant, "
                          "permit, approve, withheld, committed), operation names with 'gate' as a word or containing "
                          "'decision' and 'gate', and the gate's own policy id are reserved for gate_decision; "
                          "choose another value")}
    manifest = {
        "operation": str(operation),
        "issuer_tool": "mint_action_receipt",
        "agent_id": str(agent_id),
        "target": str(target),
        "policy": str(policy),
        "inputs_hash": _ascii_hash(inputs or ""),
    }
    for key, val in [("triggered_by_type", triggered_by_type),
                     ("triggered_by_source", triggered_by_source),
                     ("decision_model", decision_model)]:
        if val is not None:
            safe = _safe_attestation(str(val))
            if safe:
                manifest[key] = safe
    return _mint(manifest, decision=decision)


def tool_verify_receipt(receipt: Dict[str, Any],
                        require_pq: Optional[bool] = None,
                        expected_kid: Optional[str] = None) -> Dict[str, Any]:
    """Verify a Trust Gate receipt from the certificate alone (no DB, no network).

    What "ok" means: the evidence is unchanged since it was signed, the receipt is signed, any Ed25519
    signer it names (public key or kid) has a valid signature on it and its kid matches that key, and
    (in PQ-required mode) a post-quantum leg verifies. It does
    NOT mean the receipt came from a server you trust: anyone can generate keys and sign a
    receipt. Pin the signer by passing expected_kid (the kid of the Ed25519 key you trust); a pin
    counts only when that key's own Ed25519 signature verifies, and `signer_pinned` says so. The
    post-quantum keys inside a receipt are not covered by the kid. Read the verdict from
    `decision` or `evidence.ontology.verdict`, never from unsigned top-level keys (listed in
    `unsigned_top_level_keys`).

    expected_kid  Optional. When given, ok is False unless the receipt's Ed25519 signature verified
                  under a key with this kid.

    require_pq  None (default) -> obey TRUST_GATE_REQUIRE_PQ / OAO_REQUIRE_PQ (default ON).
                True            -> FAIL unless at least one post-quantum leg (ML-DSA-65 or a hash-based leg)
                                   verifies. That shows a post-quantum signature is present and
                                   valid over the same bytes; it does not say whose key made it.
                False           -> Ed25519-only verification is allowed (legacy mode).
    """
    if not isinstance(receipt, dict):
        return {"ok": False, "reason": "receipt must be a JSON object"}
    return _verify(receipt, require_pq=require_pq, expected_kid=expected_kid)


def tool_gate_decision(
    action: str,
    resource: str,
    context: Dict[str, Any],
    phase: str = "PREVIEW",
    preview_id: Optional[str] = None,
    triggered_by_type: Optional[str] = None,
    triggered_by_source: Optional[str] = None,
    decision_model: Optional[str] = None,
) -> Dict[str, Any]:
    """Two-phase decision gate with a real verdict: ALLOW, DENY or ESCALATE.

    PREVIEW evaluates the action and returns the verdict, the risk tier and the reasons,
    without minting anything. COMMIT evaluates the same inputs again (it never reads a
    verdict from the caller), mints a signed receipt for the verdict, and returns a permit:
    GRANTED only for ALLOW; DENIED for DENY; WITHHELD_PENDING_HUMAN for ESCALATE, which a
    human must decide outside this tool. If the receipt cannot be minted and signed, no
    permit is issued.

    The preview_id is a deterministic fingerprint of the inputs. It checks that COMMIT
    describes the same action as PREVIEW; it is not a secret and not an approval.

    Scope: applies only to actions the caller routes through this gate. It does not observe,
    intercept or block anything an agent does. The verdict comes from a name-based heuristic on
    the action name and resource, not a proof, and never from context or attestation fields.
    triggered_by_type, triggered_by_source and decision_model are caller claims: they are signed
    into the receipt and not verified. ALLOW needs a known read verb followed only by words from a small closed vocabulary.
    The receipt is tamper-evident, not proof of compliance.
    """
    if (not isinstance(action, str) or not isinstance(resource, str)
            or not action.strip() or not resource.strip()):
        return {"error": "action and resource are required"}
    if len(action) > _MAX_LABEL_CHARS or len(resource) > _MAX_LABEL_CHARS:
        return {"error": f"action and resource must each be at most {_MAX_LABEL_CHARS} characters"}
    try:
        (action + resource).encode("utf-8")
    except UnicodeEncodeError:
        return {"error": "action and resource must be valid text"}
    if not isinstance(phase, str) or phase.upper().strip() not in ("PREVIEW", "COMMIT"):
        return {"error": "phase must be 'PREVIEW' or 'COMMIT'"}
    phase_upper = phase.upper().strip()
    if context is not None and not isinstance(context, dict):
        return {"error": "context must be an object"}
    if preview_id is not None and not isinstance(preview_id, str):
        return {"error": "preview_id must be a string"}
    try:
        ctx_canonical = json.dumps(context, sort_keys=True, default=str) if context else ""
    except (TypeError, ValueError, RecursionError):
        return {"error": "context could not be serialised"}
    if len(ctx_canonical) > _MAX_CONTEXT_CHARS:
        return {"error": f"context must serialise to at most {_MAX_CONTEXT_CHARS} characters"}

    # Deterministic preview_id over an unambiguous encoding of (action, resource, context):
    # a plain "|" join let ("a|b", "c") and ("a", "b|c") collide.
    ctx_hash = hashlib.sha256(ctx_canonical.encode()).hexdigest()
    preview_payload = json.dumps([action, resource, ctx_hash], separators=(",", ":"))
    expected_id = "pvw_" + hashlib.sha256(preview_payload.encode()).hexdigest()[:24]

    assessment = _gate_assessment(action, resource)
    tier, score, verdict = assessment["tier"], assessment["score"], assessment["verdict"]
    reasons = assessment["reasons"]

    if phase_upper == "PREVIEW":
        next_step = {
            "ALLOW": "pass this preview_id to phase='COMMIT' with the same action, resource, and "
                     "context to mint the signed ALLOW receipt and receive a GRANTED permit",
            "DENY": "this action would be denied; phase='COMMIT' mints a signed DENY record and "
                    "issues no permit",
            "ESCALATE": "this action needs a human decision outside this tool; phase='COMMIT' "
                        "mints a signed ESCALATE record and issues no permit",
        }[verdict]
        return {
            "phase": "PREVIEW",
            "preview_id": expected_id,
            "action": action,
            "resource": resource,
            "verdict": verdict,
            "risk_assessment": {
                "tier": tier,
                "worst_regret_score": score,
                "reasons": reasons,
                "method": "read-only allowlist plus verb tiers; a name-based heuristic, not a proof",
            },
            "policy_evaluation": {
                "policy": _GATE_POLICY_ID,
                "action_hash": _ascii_hash(action),
                "resource_hash": _ascii_hash(resource),
                "context_hash": _ascii_hash(ctx_canonical),
            },
            "next_step": next_step,
            "scope_note": _GATE_SCOPE_NOTE,
        }

    # COMMIT phase -- verify preview_id matches
    if not preview_id:
        return {"error": "preview_id is required for COMMIT phase (run PREVIEW first)"}
    if preview_id != expected_id:
        return {"error": "preview_id mismatch -- inputs changed since PREVIEW, or wrong preview_id"}

    manifest = {
        "operation": "decision_gate_commit",
        "issuer_tool": "gate_decision",
        "action": action,
        "resource": resource,
        "context_hash": _ascii_hash(ctx_canonical),
        "preview_id": expected_id,
        "risk_tier": tier,
        "risk_score": score,
        "verdict": verdict,
        "reasons": reasons,
        "policy": _GATE_POLICY_ID,
        "policy_scope": "name-based heuristic; applies only to actions routed through this gate",
    }
    for key, val in [("triggered_by_type", triggered_by_type),
                     ("triggered_by_source", triggered_by_source),
                     ("decision_model", decision_model)]:
        if val is not None:
            safe = _safe_attestation(str(val))
            if safe:
                manifest[key] = safe
    receipt = _mint(manifest, decision=verdict)
    problem = None
    if "error" in receipt:
        problem = receipt.get("error")
    elif receipt.get("signed") is not True or not receipt.get("signature_b64"):
        problem = "receipt is unsigned"
    else:
        check = _verify(receipt)
        if not check.get("ok"):
            problem = f"receipt does not verify under this server's own policy: {check.get('reason')}"
    if problem:
        # Never hand out a permit that has no signed record behind it, or whose receipt this
        # server's own default verify would reject.
        return {
            "phase": "COMMIT",
            "preview_id": expected_id,
            "verdict": verdict,
            "permit": "NOT_ISSUED",
            "error": "the receipt could not be minted and signed, so no permit was issued",
            "detail": problem,
            "scope_note": _GATE_SCOPE_NOTE,
        }
    return {
        "phase": "COMMIT",
        "preview_id": expected_id,
        "verdict": verdict,
        "permit": _PERMIT_BY_VERDICT[verdict],
        "risk_tier": tier,
        "reasons": reasons,
        "receipt": receipt,
        "scope_note": _GATE_SCOPE_NOTE,
        "note": ("receipt is tamper-evident, not proof of compliance; read the verdict from "
                 "receipt.decision, not from the unsigned top-level verdict or permit fields"),
    }


def tool_check_egress(
    destination: str,
    data_sample: str,
    provider: str,
) -> Dict[str, Any]:
    """Flag sensitive markers in outbound data and sign the result.

    Scans the data_sample and destination for a finite list of markers (keywords, SSN and
    card-number shapes, common credential formats) and classifies as NO_MARKERS_FOUND /
    INTERNAL / CONFIDENTIAL / RESTRICTED. RESTRICTED sets `blocked: true`. This tool cannot
    block anything itself: your code must read `blocked` and obey it. NO_MARKERS_FOUND is not
    clearance to send.

    The receipt is tamper-evident, not proof of compliance. The classification is a
    heuristic signal, not a regulatory determination.
    """
    if not destination or not data_sample or not provider:
        return {"error": "destination, data_sample, and provider are required"}
    if not all(isinstance(v, str) for v in (destination, data_sample, provider)):
        return {"error": "destination, data_sample, and provider must be text"}
    if len(destination) > _MAX_EGRESS_CHARS or len(data_sample) > _MAX_EGRESS_CHARS:
        return {"error": f"destination and data_sample may not exceed {_MAX_EGRESS_CHARS} characters"}
    if len(provider) > _MAX_PROVIDER_CHARS:
        return {"error": f"provider may not exceed {_MAX_PROVIDER_CHARS} characters"}

    classification, reason = _classify_egress(data_sample, f"{destination} {provider}")
    if _classify_egress(provider, "")[0] == "RESTRICTED":
        provider = "[withheld: sensitive value]"   # the receipt records the provider in clear text
    blocked = classification == "RESTRICTED"
    retention = _EGRESS_RETENTION.get(classification, "unknown")

    manifest = {
        "operation": "egress_classification",
        "issuer_tool": "check_egress",
        "destination_hash": _ascii_hash(destination),
        "data_sample_hash": _ascii_hash(data_sample),
        "provider": str(provider),
        "classification": classification,
        "blocked": blocked,
        "policy": "egress data-sensitivity gate",
    }
    receipt = _mint(manifest, decision="EGRESS_RESTRICTED" if blocked else "EGRESS_CLASSIFIED")

    return {
        "classification": classification,
        "reason": reason,
        "blocked": blocked,
        "retention": retention,
        "provider": provider,
        "destination_hash": _ascii_hash(destination),
        "receipt": receipt,
        "note": "classification is heuristic, not a regulatory determination; receipt is tamper-evident, not proof of compliance",
    }


def _pq_backend() -> str:
    """Name of the ML-DSA backend the signing primitive is using: liboqs, dilithium_py, none or
    unknown. dilithium_py is a pure-Python educational library (its own README says not to use it
    for cryptographic applications and that it is not constant time); liboqs is the native one."""
    if _oao_receipt is None:
        return "none"
    try:
        from openagentontology import pqsign as _pqsign  # type: ignore
        return str(_pqsign.backend())
    except Exception:
        return "unknown"


def _hash_leg_available() -> bool:
    if _oao_receipt is None:
        return False
    try:
        from openagentontology import pqsign as _pqsign  # type: ignore
        return bool(_pqsign.SLH_DSA_AVAILABLE)
    except Exception:
        return False


def _is_local_endpoint(value: str) -> bool:
    text = str(value).strip()
    try:
        host = urlsplit(text if "://" in text else "//" + text).hostname or ""
    except ValueError:      # a malformed address such as "http://[abc" is not a local endpoint
        return False
    return host in ("localhost", "127.0.0.1", "::1") or text.startswith("unix:")


def _endpoint_label(value: str) -> str:
    """scheme, host and port of an endpoint, and nothing else: no credentials, path or query."""
    text = str(value).strip()
    try:
        parts = urlsplit(text if "://" in text else "//" + text)
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        return "[unparseable]"
    if not host:
        return "[unparseable]"
    host = f"[{host}]" if ":" in host else host
    return (f"{parts.scheme}://" if parts.scheme else "") + host + (f":{port}" if port else "")


def tool_run_exit_drill() -> Dict[str, Any]:
    """Check vendor exit readiness: the local signing key and a local model host.

    Informational -- shows the operator whether a local signing key and a local model endpoint are set up. Each check reports
    PASS, WARN, FAIL, or UNKNOWN. The receipt covers the drill itself (tamper-evident, not
    proof of compliance).
    """
    steps: List[Dict[str, Any]] = []

    # 1. Local signing key (OAO receipt minting)
    signing_ok = _oao_receipt is not None
    backend = _pq_backend()
    steps.append({
        "check": "local_signing_key",
        "description": "OpenAgentOntology receipt signing available locally",
        "status": ("FAIL" if not signing_ok
                   else "WARN" if backend == "dilithium_py" else "PASS"),
        "detail": ((f"source: {_OAO_SOURCE}; post-quantum backend: {backend}"
                    + ("; this backend is a pure-Python educational library, install liboqs-python "
                       "for production use" if backend == "dilithium_py" else "")
                    + f"; hash-based leg: {'available' if _hash_leg_available() else 'unavailable'}")
                   if signing_ok
                   else "pip install 'openagentontology[pq]' to enable local signing"),
    })

    # 2. Local model access (Ollama or compatible)
    ollama_host = os.environ.get("OLLAMA_HOST") or os.environ.get("OLLAMA_BASE_URL")
    steps.append({
        "check": "local_model_access",
        "description": "A local LLM endpoint is configured (Ollama or compatible); it is not contacted",
        "status": "PASS" if ollama_host and _is_local_endpoint(ollama_host) else "UNKNOWN",
        "detail": ((f"OLLAMA_HOST={_endpoint_label(ollama_host)}"
                    + ("" if _is_local_endpoint(ollama_host) else " (not a local host: not counted)")
                    )
                   if ollama_host
                   else "OLLAMA_HOST not set; Ollama may still be reachable at default localhost:11434"),
    })

    passed = sum(1 for s in steps if s["status"] == "PASS")
    total = len(steps)

    manifest = {
        "operation": "vendor_exit_drill",
        "issuer_tool": "run_exit_drill",
        "checks_passed": passed,
        "checks_total": total,
        "steps_summary": [{"check": s["check"], "status": s["status"]} for s in steps],
        "policy": "vendor exit readiness assessment",
    }
    receipt = _mint(manifest, decision="EXIT_DRILL_COMPLETED")
    if "error" in receipt or not receipt.get("signature_b64"):   # the signing step must not pass when this host could not sign
        steps[0]["status"] = "FAIL"
        steps[0]["detail"] = "a receipt could not be signed on this host"
        passed = sum(1 for st in steps if st["status"] == "PASS")

    return {
        "readiness": "READY" if passed == total else "PARTIAL",
        "passed": passed,
        "total": total,
        "steps": steps,
        "receipt": receipt,
        "note": "informational assessment; receipt is tamper-evident, not proof of compliance",
    }


# ---- MCP server wiring (FastMCP -- the high-level API in the modelcontextprotocol Python SDK) -

def build_server():
    """Build the FastMCP server with all seven tools. Importable so tests don't need stdio."""
    from mcp.server.fastmcp import FastMCP  # imported lazily so tests can run without mcp
    from mcp.server.transport_security import TransportSecuritySettings

    # FastMCP's DNS-rebinding protection defaults to ON with an empty allow-list, which
    # rejects every request with 421 "Invalid Host header" behind a TLS-terminating proxy
    # (Render, Smithery gateway, Cloudflare, etc.). We disable it here because:
    #   - Trust Gate is reached through an upstream proxy that you control
    #   - CORS is wide open unless bearer auth is on (see server_http.py), so treat this as a proxy-level control
    #   - bearer-auth, when enabled, provides per-request authentication
    # This server has no switch for it: on a direct-exposure deploy put it behind a proxy that
    # checks the Host header, or turn bearer auth on.
    security = TransportSecuritySettings(enable_dns_rebinding_protection=False)

    mcp = FastMCP("trust-gate", instructions=(
        "Trust Gate -- tamper-evident, hybrid-signed receipts for consequential agent actions. "
        "All receipts reuse the open-source OpenAgentOntology mint_receipt (Ed25519 + ML-DSA-65). "
        "Integrity is verifiable offline from the "
        "receipt alone; authenticity needs the signer's Ed25519 kid pinned out of band."
    ), transport_security=security,
        # json_response: return application/json instead of streaming text/event-stream.
        # Required for one-shot directory scanners (e.g. Smithery) that POST a JSON-RPC
        # call and wait for a JSON body, not an open SSE stream.
        # stateless_http: every request handled independently, no mcp-session-id
        # continuation needed. Safe for this tool surface -- none of the seven tools share
        # state across calls; each mint/verify is self-contained.
        json_response=True, stateless_http=True)

    @mcp.tool(description="Mint a signed receipt (Ed25519, plus ML-DSA-65 when the post-quantum backend is available) for one CRM record change. Old/new values "
              "are carried as SHA-256 hashes. Works with any CRM (Relaticle, hosted CRMs, custom).")
    def mint_receipt_for_record_change(
        record_id: str, object_type: str, field: str,
        old_value: str, new_value: str, changed_by_agent: str,
        tenant: Optional[str] = None,
        policy: str = "per-decision CRM change evidence",
    ) -> Dict[str, Any]:
        return tool_mint_receipt_for_record_change(
            record_id, object_type, field, old_value, new_value,
            changed_by_agent, tenant, policy)

    @mcp.tool(description="Rank a CALLER-PROVIDED list of MCP tools by worst-regret if they act "
              "(a name-based heuristic that weights a name's first word most). Read-only: it mints no "
              "receipt. Cannot auto-discover the inventory -- MCP does not allow that; the caller must "
              "pass it in.")
    def audit_my_agent_inventory(
        inventory: List[Dict[str, Any]],
        notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        return tool_audit_my_agent_inventory(inventory, notes)

    @mcp.tool(description="Mint a signed receipt (Ed25519, plus ML-DSA-65 when the post-quantum backend is available) for an arbitrary consequential agent action. "
              "Optional attestation: triggered_by_type (human/agent/script), triggered_by_source "
              "(api/cli/cron), decision_model (the LLM model used). Attestation values are caller "
              "claims: allowlisted to safe characters, signed, not verified. Decisions that contain a "
              "gate verdict word are reserved for gate_decision.")
    def mint_action_receipt(
        agent_id: str, operation: str, target: str,
        policy: str = "agent action evidence",
        inputs: Optional[str] = None,
        decision: str = "ACTION_GOVERNED",
        triggered_by_type: Optional[str] = None,
        triggered_by_source: Optional[str] = None,
        decision_model: Optional[str] = None,
    ) -> Dict[str, Any]:
        return tool_mint_action_receipt(
            agent_id, operation, target, policy, inputs, decision,
            triggered_by_type, triggered_by_source, decision_model)

    @mcp.tool(description="Verify a Trust Gate receipt from the certificate alone (offline). "
              "ok=true means unchanged since signing, signed, kid consistent with the embedded key, "
              "and (require_pq default on) at least one post-quantum leg verified; unsigned receipts "
              "fail. It does not prove who signed: pass expected_kid to pin the signer's Ed25519 key; "
              "a pin counts only when that key's own signature verifies (see signer_pinned). The "
              "post-quantum keys in a receipt are not covered by the kid.")
    def verify_receipt(receipt: Dict[str, Any],
                       require_pq: Optional[bool] = None,
                       expected_kid: Optional[str] = None) -> Dict[str, Any]:
        return tool_verify_receipt(receipt, require_pq, expected_kid)

    @mcp.tool(description="Two-phase decision gate with a real verdict. PREVIEW returns ALLOW, DENY "
              "or ESCALATE with the risk tier and reasons, plus a preview_id, without acting. COMMIT "
              "re-evaluates the same inputs and mints a signed receipt for the verdict. Only ALLOW "
              "returns a GRANTED permit; DENY returns DENIED; ESCALATE returns WITHHELD_PENDING_HUMAN "
              "and a human must decide outside this tool. Applies only to actions the caller routes "
              "through it: it does not observe or block what an agent does. Verb-tier heuristic on the "
              "action name and resource, not a proof. Stateless. Optional attestation: "
              "triggered_by_type, triggered_by_source, decision_model.")
    def gate_decision(
        action: str, resource: str, context: Dict[str, Any],
        phase: str = "PREVIEW",
        preview_id: Optional[str] = None,
        triggered_by_type: Optional[str] = None,
        triggered_by_source: Optional[str] = None,
        decision_model: Optional[str] = None,
    ) -> Dict[str, Any]:
        return tool_gate_decision(
            action, resource, context, phase, preview_id,
            triggered_by_type, triggered_by_source, decision_model)

    @mcp.tool(description="Egress classification check. Scans a data sample for a finite list of "
              "sensitivity markers and classifies as NO_MARKERS_FOUND / INTERNAL / CONFIDENTIAL / "
              "RESTRICTED. RESTRICTED sets blocked=true; this tool cannot block anything itself, and "
              "NO_MARKERS_FOUND is not clearance to send. Returns classification, retention info, and a "
              "tamper-evident receipt.")
    def check_egress(
        destination: str, data_sample: str, provider: str,
    ) -> Dict[str, Any]:
        return tool_check_egress(destination, data_sample, provider)

    @mcp.tool(description="Vendor exit readiness drill. Checks local signing key, local model "
              "access (Ollama). Returns step-by-step results "
              "and a tamper-evident receipt. Informational; it signs one receipt, which creates the signing key on a host that has none yet.")
    def run_exit_drill() -> Dict[str, Any]:
        return tool_run_exit_drill()

    return mcp


def describe_tools(mcp) -> List[Dict[str, str]]:
    """Name and description of every tool the server registers, read from the server itself so a
    published card can never drift from the code. Call from synchronous code (not inside a
    running event loop)."""
    import asyncio
    tools = asyncio.run(mcp.list_tools())
    return [{"name": t.name, "description": (t.description or "").strip()} for t in tools]


def build_server_card(mcp) -> Dict[str, Any]:
    """The static server card served at /.well-known/mcp/server-card.json, built from the server
    itself: the version is the running package's version and the tool list is whatever is
    registered, so it cannot drift from the code (an earlier hand-written card kept announcing an old
    version and a smaller tool count after the server had grown)."""
    tools = describe_tools(mcp)
    return {
        "schemaVersion": "v1",
        "name": "trust-gate",
        "version": SERVER_VERSION,
        "description": ("Tamper-evident, hybrid-signed receipts for consequential agent actions. "
                        f"{len(tools)} tools, one shared signing primitive (Ed25519 + ML-DSA-65, via "
                        "OpenAgentOntology). Integrity is "
                        "verifiable offline; pin the signer's Ed25519 kid to verify authenticity."),
        "homepage": "https://github.com/CWNApps/trust-gate-mcp",
        "license": "Apache-2.0",
        "tools": tools,
    }


def main() -> None:
    server = build_server()
    server.run()  # stdio is the FastMCP default; the MCP host launches us as a subprocess


if __name__ == "__main__":
    main()
