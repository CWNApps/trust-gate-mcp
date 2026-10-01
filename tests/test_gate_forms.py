"""test_gate_forms.py -- spellings of a listed word, a network address or a file type that must not slip
past the gate. Each family below is a regression case: an input that once got ALLOW.

The word lists come from tests/gate_vocabulary.py (an independent copy), never from the module under
test, so deleting a word from the source fails a test here.
"""
from __future__ import annotations

import itertools

import pytest

import gate_vocabulary as vocab
from trust_gate_mcp import server as srv

_TO_DIGIT = str.maketrans("oieast", "013457")     # the inverse of the digit-for-letter swaps the gate reads back
FORBIDDEN_AS_RESOURCE_TIERS = ("CRITICAL", "HIGH", "MEDIUM")


def verdict(action, resource="docs"):
    return srv._gate_assessment(action, resource)["verdict"]


def assert_not_allowed(action, resource):
    got = srv._gate_assessment(action, resource)
    assert got["verdict"] != "ALLOW", (action, resource, got)


# ---- digit-for-letter swaps ("sh4d0w", "4dm1n") -------------------------------------------------------
SWAPPABLE_NOUNS = [w for w in vocab.SENSITIVE_NOUNS if w.translate(_TO_DIGIT) != w]


@pytest.mark.parametrize("word", SWAPPABLE_NOUNS)
def test_a_digit_swapped_sensitive_noun_is_not_allowed(word):
    swapped = word.translate(_TO_DIGIT)
    for action in ("read_file", "get_file"):
        assert_not_allowed(action, f"{swapped}.txt")
        assert_not_allowed(action, f"docs/{swapped}")


def test_the_swapped_nouns_cover_the_known_forms():
    for name in ("c0nf1g.txt", "k3ych4in", "sh4d0w", "4dm1n.txt", "h1st0ry.txt", "l0g1n.txt", "3nv.txt", "v4ult",
                 "w4ll3t.txt", "c00k1es.txt", "r00t.txt", "cr3ds.txt", "p4ss.txt", "k3y.txt", "sud0ers", "b3arer",
                 "mn3monic", "p1n.txt", "0tp.txt", "ib4n.txt", "pr0c/self/cmdl1ne", "tfst4te", "htp4sswd", "b1twarden"):
        assert_not_allowed("read_file", name)


@pytest.mark.parametrize("phrase", [p for p in vocab.SENSITIVE_PHRASES if not any(ch.isdigit() for ch in p)])
def test_a_digit_swapped_sensitive_phrase_is_not_allowed(phrase):
    # (a phrase that already contains digits, "id ed 25519", is matched in its plain spelling)
    swapped = "_".join(word.translate(_TO_DIGIT) for word in phrase.split(" "))
    assert_not_allowed("read_file", f"{swapped}.txt")


@pytest.mark.parametrize("swapped", ["DR0P", "D3LETE", "TRUNC4TE", "GR4NT", "d3l3te", "dr0p", "s3nd", "wr1te"])
def test_a_digit_swapped_risky_verb_in_the_resource_is_not_allowed(swapped):
    assert_not_allowed("query_db", swapped)
    assert_not_allowed("read_file", swapped)


@pytest.mark.parametrize("resource", ["de1ete", "1ock", "f1ush", "pub1ish", "D3L3T3", "1oad", "a1ter"])
def test_a_one_standing_for_an_l_is_read_back_in_verbs_in_the_resource(resource):
    assert_not_allowed("read_file", resource)
    assert_not_allowed("query_db", resource)


def test_plain_digits_in_a_name_still_pass():
    for resource in ("docs/2024/report.md", "notes-1.2.3.md", "docs/2/readme.md", "summary-3.md", "chapter-12.txt"):
        assert verdict("read_file", resource) == "ALLOW", resource


# ---- plural and glued forms of the multi-word phrases -------------------------------------------------
def _plural_combinations(phrase):
    words = phrase.split(" ")
    for marks in itertools.product(("", "s"), repeat=len(words)):
        yield "_".join(w + m for w, m in zip(words, marks))


@pytest.mark.parametrize("phrase", vocab.SENSITIVE_PHRASES)
def test_every_plural_combination_of_a_sensitive_phrase_is_not_allowed(phrase):
    for name in _plural_combinations(phrase):
        assert_not_allowed("read_file", f"{name}.txt")
        assert_not_allowed("query_db", name)


def test_the_known_phrases_are_covered_in_their_plural_forms():
    for name in ("drivers_license.txt", "drivers_licenses.txt", "dates_of_birth.md", "driver_licence.md",
                 "national_ids.txt", "tax_returns.txt", "bank_statements.md", "criminal_records.md", "hiv_results.txt",
                 "dna_results.md", "birth_dates.md", "scratch_codes.txt", "database_dumps", "sentry_dsn", "pg_authid"):
        assert_not_allowed("read_file", name)


def test_the_plainly_regulated_or_confidential_names_are_not_allowed():
    for name in ("confidential/board-minutes.md", "private/notes.md", "classified.md", "restricted/", "birthdate.txt",
                 "employee_birthdates.md", "ntlm_hashes.txt", "google_authenticator", "heapdump", "coredump", "nda.txt",
                 "genome.txt", "biometrics.md", "webhook_url.txt", "htdigest", "viminfo"):
        assert_not_allowed("read_file", name)


# ---- every form of a risky verb ------------------------------------------------------------------------
def _forms(verb):
    forms = {verb, verb + "s", verb + "es", verb + "ed", verb + "d", verb + "ing", verb + verb[-1] + "ed",
             verb + verb[-1] + "ing"}
    if verb.endswith("e"):
        forms.add(verb[:-1] + "ing")
    if verb.endswith("y"):
        forms |= {verb[:-1] + "ies", verb[:-1] + "ied"}
    return forms


RISKY_FORMS = sorted({form for tier, verbs in vocab.VERBS_BY_TIER.items() if tier in FORBIDDEN_AS_RESOURCE_TIERS
                      for verb in verbs for form in _forms(verb)})


@pytest.mark.parametrize("form", RISKY_FORMS)
def test_every_form_of_a_risky_verb_in_the_resource_is_not_allowed(form):
    assert_not_allowed("read_file", form)


def test_the_known_verb_forms_are_covered():
    for form in ("sending", "stopped", "copies", "pushes", "deleting", "wiring", "dropping", "transferred"):
        assert form in RISKY_FORMS, form
        assert_not_allowed("read_file", form)


GLUEABLE = [verb for verb in vocab.VERBS_BY_TIER["CRITICAL"]
            if len(verb) >= 4 and verb not in ("wire", "sell", "mint", "trade", "payment")]


@pytest.mark.parametrize("verb", GLUEABLE)
def test_a_critical_verb_glued_to_a_word_in_the_resource_is_not_allowed(verb):
    for suffix in ("all", "db", "now"):
        assert_not_allowed("read_file", f"{verb}{suffix}.md")


def test_exempt_words_that_merely_start_like_a_verb_are_not_read_as_that_verb():
    for word in ("wireframe", "seller", "mintish", "tradeoff", "paymentish"):
        assert srv._glued_critical_verb(word) is None, word


@pytest.mark.parametrize("resource", ["XDelete", "SQLDrop", "HTTPDelete", "DeleteAll", "rm1", "rm2.txt", "pin1234.txt",
                                      "sudo1", "kill9"])
def test_acronym_and_letter_digit_splits_in_the_resource_are_seen(resource):
    assert_not_allowed("read_file", resource)


# ---- paths written with compatibility characters, and other grammar cases -----------------------------
@pytest.mark.parametrize("resource", ["／etc／hosts", "．hidden", "docs／．env", "ｄｏｃｓ／．git／config", "docs/．．/x.md",
                                      "⁄etc/passwd"])
def test_compatibility_characters_do_not_hide_a_path(resource):
    assert_not_allowed("read_file", resource)


def test_a_two_word_resource_after_a_query_verb_is_a_query_expression():
    assert verdict("query_db", "users where") == "ESCALATE"
    assert verdict("query_db", "users") == "ALLOW"


@pytest.mark.parametrize("action", ["read\\file", "read_file\\x", "read file; ls", "read_file && ls"])
def test_an_action_with_a_backslash_or_shell_syntax_is_not_allowed(action):
    assert_not_allowed(action, "docs")


@pytest.mark.parametrize("resource", ["7oken.txt", "pwdump", "keysfile", "mykey.txt", "tokenfile", "passfile"])
def test_short_sensitive_words_glued_to_filler_words_are_seen(resource):
    assert_not_allowed("read_file", resource)


# ---- network addresses in every spelling ----------------------------------------------------------------
ADDRESSES = [
    "169.254.169.254/latest/meta-data", "2852039166/latest/meta-data", "0xa9fea9fe/latest/meta-data",
    "0251.0376.0251.0376/latest/meta-data", "169.254.43518/latest/meta-data", "0x7f000001/x.md", "127.1",
    "127.0.1", "2130706433", "10.0.0.5/notes.md", "docs/192.168.1.1/x.md", "localhost/metrics", "localhost",
    "instance-data/latest/meta-data", "metadata.google.internal/computeMetadata/v1/instance",
    "169.254.169.254.nip.io/latest/meta-data", "attacker.example/readme.md", "example.com/api", "www.example.org/x/y",
    "evil.py/x",
]


@pytest.mark.parametrize("resource", ADDRESSES)
def test_a_network_address_or_host_in_any_spelling_escalates(resource):
    for action in ("read_file", "get_page", "get"):
        got = srv._gate_assessment(action, resource)
        assert got["verdict"] == "ESCALATE", (action, resource, got)


@pytest.mark.parametrize("resource", ["docs/1.2.3", "notes-1.2.3.md", "2024/report.md", "1.0/README.md", "docs/10.2/notes.md",
                                      "src/app.py", "docs/12345", "docs/2.5", "docs/a.c/notes.md"])
def test_versions_dates_and_ordinary_paths_are_not_mistaken_for_addresses(resource):
    assert verdict("read_file", resource) == "ALLOW", resource


# ---- file-type chains -----------------------------------------------------------------------------------
@pytest.mark.parametrize("resource", ["backup.sql.txt", "users.csv.txt", "db.sqlite.txt", "docker-compose.yml.txt",
                                      "x.tar.gz.md", "x.exe.md", "dump.bak.md", "keys.pem.txt", "notes.env.md"])
def test_a_data_type_followed_by_an_ordinary_extension_is_still_that_data_type(resource):
    assert_not_allowed("read_file", resource)


@pytest.mark.parametrize("resource", ["app.test.ts", "readme.guide.md", "notes.spec.md", "guide.test.py", "docs.notes.txt"])
def test_dotted_names_with_only_ordinary_parts_pass(resource):
    assert verdict("read_file", resource) == "ALLOW", resource
