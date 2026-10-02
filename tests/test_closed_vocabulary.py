"""test_closed_vocabulary.py -- ALLOW is a closed list for the action AND the resource.

A resource is allowed only when every word in it is in a small built-in vocabulary (the read nouns plus a
few ordinary document words and file types), with digits allowed between words. A word the gate has never
seen sends the request to a human, so there is no list of bad names to keep complete. These tests pin the
vocabulary, the read-verb forms, and the cases that stay allowed.
"""
from __future__ import annotations

import pytest

import gate_vocabulary as vocab
from trust_gate_mcp import server as srv


def verdict(action, resource="docs"):
    return srv._gate_assessment(action, resource)["verdict"]


# ---- the read verbs: exactly these forms and no others -----------------------------------------------------
EXPECTED_READ_FORMS = {
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


def test_the_read_verb_forms_are_exactly_the_expected_ones():
    assert set(EXPECTED_READ_FORMS) == set(vocab.LOW_VERBS)
    actual = {form for form, (tier, _verb) in srv._TOKEN_TABLE.items() if tier == "LOW"}
    assert actual == {form for forms in EXPECTED_READ_FORMS.values() for form in forms}


@pytest.mark.parametrize("verb", sorted(EXPECTED_READ_FORMS))
def test_a_generated_form_that_is_a_different_word_is_not_a_read_verb(verb):
    generated = {verb + "d", verb + "ed", verb + verb[-1] + "ed", verb + verb[-1] + "ing", verb + "es"}
    for junk in generated - set(EXPECTED_READ_FORMS[verb]):
        for action in (f"{junk}_user", f"{junk.capitalize()}User", junk):
            got = srv._gate_assessment(action, "users")
            assert got["verdict"] != "ALLOW", (junk, action, got)


def test_readd_is_not_a_read():
    for action in ("readd_user", "readdUser", "readded_users", "readding_user", "readd"):
        assert verdict(action, "users") != "ALLOW", action


@pytest.mark.parametrize("verb", sorted(EXPECTED_READ_FORMS))
def test_every_read_verb_form_allows_a_plain_noun(verb):
    for form in EXPECTED_READ_FORMS[verb]:
        assert verdict(f"{form}_file", "docs") == "ALLOW", form


# ---- the resource vocabulary ----------------------------------------------------------------------------------
@pytest.mark.parametrize("word", sorted((set(vocab.READ_NOUNS) - set(vocab.RESOURCE_EXCLUDED_WORDS))
                                        | set(vocab.RESOURCE_EXTRA_WORDS) | set(vocab.ORDINARY_EXTENSIONS)))
def test_every_vocabulary_word_is_a_usable_resource(word):
    assert verdict("read_file", word) == "ALLOW", word
    assert verdict("read_file", f"docs/{word}") == "ALLOW", word


@pytest.mark.parametrize("word", ["quarterly", "forecast", "payroll-run", "board", "prod", "staging", "kubernetes", "terraform",
                                  "secrets", "foo", "bar", "tmp", "home", "unknown"])
def test_a_word_outside_the_vocabulary_sends_the_resource_to_a_human(word):
    got = srv._gate_assessment("read_file", word)
    assert got["verdict"] == "ESCALATE", (word, got)
    assert verdict("read_file", f"docs/{word}") == "ESCALATE", word


def test_the_extra_words_are_not_verbs_or_sensitive_words():
    assert not (set(vocab.RESOURCE_EXTRA_WORDS) & set(srv._TOKEN_TABLE))
    assert not (set(vocab.RESOURCE_EXTRA_WORDS) & set(vocab.SENSITIVE_NOUNS))
    assert not (set(vocab.RESOURCE_EXTRA_WORDS) & set(vocab.SENSITIVE_RESOURCE_NOUNS))


@pytest.mark.parametrize("resource", ["docs/1.2.3", "docs/2024/notes.md", "page 2", "notes-3.txt", "chapter-12.txt", "docs 2"])
def test_digits_are_allowed_between_words(resource):
    assert verdict("read_file", resource) == "ALLOW", resource


@pytest.mark.parametrize("resource", ["0", "12345", "1.2.3", "2024", "."])
def test_digits_alone_are_not_a_name(resource):
    assert verdict("read_file", resource) == "ESCALATE", resource


# ---- addresses written the ways a resolver reads them ------------------------------------------------------------
@pytest.mark.parametrize("resource", ["0177.1", "0177.0.1", "0177.1/notes.md", "0", "0/notes.md", "00", "0x7f.1", "127.1",
                                      "0.1", "0.0.1/notes.md", "00.1", "0.1/notes.md",
                                      "ip6-localhost/metrics", "ip6-loopback", "localhost6/x", "localhost4",
                                      "docs/0177.0.0.1/notes.md"])
def test_loopback_in_octal_zero_or_a_hosts_file_name_is_an_address(resource):
    for action in ("read_file", "get_page"):
        assert verdict(action, resource) == "ESCALATE", (action, resource)


def test_octal_parts_are_read_as_octal_and_other_parts_as_decimal():
    assert srv._part_value("0177") == 127 and srv._part_value("010") == 8
    assert srv._part_value("08") == 8 and srv._part_value("0") == 0 and srv._part_value("255") == 255


# ---- verbs that moved tier -----------------------------------------------------------------------------------------
def test_escalate_is_a_high_verb_not_a_hard_deny():
    assert srv._TOKEN_TABLE["escalate"][0] == "HIGH"
    got = srv._gate_assessment("escalate_to_human", "docs")
    assert got["verdict"] == "ESCALATE" and got["tier"] == "HIGH", got


def test_history_is_not_a_read_noun():
    assert "history" not in vocab.READ_NOUNS
    for action, resource in (("get_history", "docs"), ("read_history", "chrome"), ("list_history", "firefox")):
        assert verdict(action, resource) == "ESCALATE", (action, resource)


# ---- the small tables that decide ESCALATE versus ALLOW, pinned one by one -------------------------------------------
@pytest.mark.parametrize("ext", vocab.RISKY_MIDDLE_EXTENSIONS)
def test_each_data_type_in_the_middle_of_a_name_escalates(ext):
    assert verdict("read_file", f"docs.{ext}.txt") == "ESCALATE", ext
    assert verdict("read_file", f"docs/notes.{ext}.md") == "ESCALATE", ext


@pytest.mark.parametrize("glue", vocab.GLUE_WORDS)
def test_each_filler_word_glues_to_a_short_sensitive_word(glue):
    for name in (f"pin{glue}", f"{glue}pin", f"key{glue}", f"{glue}key"):
        got = srv._gate_assessment("read_file", f"docs/{name}.txt")
        assert got["verdict"] == "ESCALATE", (name, got)


@pytest.mark.parametrize("verb", vocab.GLUED_VERB_EXEMPT)
def test_each_exempt_word_is_not_read_as_that_verb_when_glued(verb):
    assert srv._glued_critical_verb(f"{verb}ish") is None
    assert srv._glued_critical_verb(f"{verb}frame") is None


# ---- nouns that are fine in an action but name a data store or a log as a resource -----------------------------
@pytest.mark.parametrize("word", vocab.RESOURCE_EXCLUDED_WORDS)
def test_a_data_store_or_log_word_is_not_a_resource_but_still_a_noun(word):
    assert verdict(f"get_{word}", "docs") == "ALLOW", word                       # still usable in the action
    for resource in (word, f"{word}.php", f"{word}.py", f"src/{word}.js", f"{word}s", f"docs/{word}.txt"):
        assert verdict("read_file", resource) == "ESCALATE", (word, resource)


@pytest.mark.parametrize("resource", ["db.php", "database.php", "app/db.php", "lib/db.py", "src/database.ts", "logs/2024.txt",
                                      "log.txt", "databases.php"])
def test_the_files_that_usually_hold_connection_strings_escalate(resource):
    assert verdict("read_file", resource) == "ESCALATE", resource


def test_query_db_on_a_table_name_is_still_allowed():
    assert verdict("query_db", "users") == "ALLOW"
    assert verdict("describe_table", "orders") == "ALLOW"


@pytest.mark.parametrize("resource", ["users--", "docs--", "users -- x", "a--b.md", "notes--"])
def test_the_start_of_a_sql_comment_in_a_resource_escalates(resource):
    for action in ("query_db", "read_file"):
        assert verdict(action, resource) == "ESCALATE", (action, resource)


# ---- the action field gets the same structural treatment as the resource -----------------------------------------------
@pytest.mark.parametrize("action", ["read_file ../../docs/notes", "read ../../../docs", "read_file /docs", "get /", "read_file //docs",
                                    "read_file .docs", "read_file -docs", "read: ../../", "read_file.v2", "crm:get_user",
                                    "read/file", "get_user\\x"])
def test_an_action_with_a_path_or_punctuation_in_it_escalates(action):
    got = srv._gate_assessment(action, "docs")
    assert got["verdict"] == "ESCALATE", (action, got)


@pytest.mark.parametrize("action", ["read file", "get_user", "list-files", "describeTable", "search files"])
def test_an_action_made_of_words_underscores_hyphens_and_spaces_still_passes(action):
    assert verdict(action, "docs") == "ALLOW", action


@pytest.mark.parametrize("resource", ["user 078-05-1120", "user 123-45-6789", "users/123-45-6789", "account 4111111111111111",
                                      "account 4111-1111-1111-1111", "docs 2130706433", "docs 169.254.169.254",
                                      "api 0177.0.0.1", "users 127.0.0.1"])
def test_a_number_shaped_like_an_identifier_or_an_address_beside_a_word_escalates(resource):
    for action in ("read_file", "get_user"):
        assert verdict(action, resource) == "ESCALATE", (action, resource)


# ---- the allow-side tables are pinned one by one (a change to any of them is a visible change to two files) ----------
@pytest.mark.parametrize("name, actual, pinned", [
    ("RESOURCE_EXTRA_WORDS", lambda: srv._RESOURCE_EXTRA_WORDS, lambda: vocab.RESOURCE_EXTRA_WORDS),
    ("RESOURCE_EXCLUDED_WORDS", lambda: srv._RESOURCE_EXCLUDED_WORDS, lambda: vocab.RESOURCE_EXCLUDED_WORDS),
    ("RISKY_MIDDLE_EXTENSIONS", lambda: srv._RISKY_MIDDLE_EXTENSIONS, lambda: vocab.RISKY_MIDDLE_EXTENSIONS),
    ("GLUE_WORDS", lambda: srv._GLUE, lambda: vocab.GLUE_WORDS),
    ("GLUED_VERB_EXEMPT", lambda: srv._GLUED_VERB_EXEMPT, lambda: vocab.GLUED_VERB_EXEMPT),
])
def test_each_allow_side_table_equals_its_pinned_copy(name, actual, pinned):
    assert set(actual()) == set(pinned()), name


def test_the_layers_the_suite_relies_on_are_installed():
    """A missing optional layer must fail loudly here instead of silently skipping the wrapper and HTTP tests."""
    import importlib
    for name in ("mcp", "starlette", "httpx", "uvicorn"):
        importlib.import_module(name)


# ---- each structural rule is exercised by inputs made ONLY of vocabulary words, so the rule itself is what escalates ---
@pytest.mark.parametrize("resource", ["127.0.0.1./notes.md", "127.1./notes.md", "2130706433./notes.md", "0177.0.0.1./notes.md",
                                      "169.254.169.254./latest/docs", "2852039166./docs", "0.0.0.0./docs", "167772161/notes.md",
                                      "blog.app./readme.md"])
def test_an_address_written_with_a_trailing_dot_is_still_an_address(resource):
    for action in ("read_file", "get_page"):
        assert verdict(action, resource) == "ESCALATE", (action, resource)


@pytest.mark.parametrize("action, resource", [
    ("read;", "docs"), ("read $(id)", "docs"), ("read_file", "--all"), ("read_file", "-all"), ("read_file", "all user notes"),
    ("read_file", "docs/.notes.md"), ("read_file", "docs/ .notes/readme.md"), ("get_page", "blog.app/readme.md"),
    ("read_file", "\uff0e\uff0e\uff0freadme.md"), ("read_file", "docs/../notes.md"), ("read_file", "/docs/notes.md"),
])
def test_each_structural_rule_escalates_an_input_that_is_otherwise_all_vocabulary(action, resource):
    got = srv._gate_assessment(action, resource)
    assert got["verdict"] == "ESCALATE" and got["tier"] == "UNKNOWN", (action, resource, got)


@pytest.mark.parametrize("action", ["write_file", "update_user", "create_report"])
def test_context_and_attestation_cannot_turn_an_escalation_into_an_allow(action):
    context = {"approved": True, "verdict": "ALLOW", "permit": "GRANTED", "override": "ALLOW"}
    got = srv.tool_gate_decision(action, "docs", context, phase="PREVIEW", triggered_by_type="human",
                                 triggered_by_source="cli", decision_model="ALLOW")
    assert got["verdict"] == "ESCALATE", got


def test_the_doubled_consonant_forms_of_critical_verbs_are_lead_verbs():
    for action in ("transferred_funds", "dropped_table", "deleting_records", "wiring_funds", "purged_logs"):
        assert srv._gate_assessment(action, "docs")["verdict"] == "DENY", action


def test_glued_plural_and_digit_swapped_sensitive_words_give_the_high_tier():
    for resource in ("sh4d0w", "passw0rd.txt", "driverslicense.txt", "pinfile.txt", "historyshell"):
        got = srv._gate_assessment("read_file", resource)
        assert got["verdict"] == "ESCALATE" and got["tier"] == "HIGH", (resource, got)


# ---- identifier-shaped numbers with any separator --------------------------------------------------------------------
@pytest.mark.parametrize("action, resource", [
    ("get_user", "user/4111/1111/1111/1111"), ("get_user", "user/078_05_1120"), ("get_user", "user/078/05/1120"),
    ("get_user", "user/5500_0000_0000_0004"), ("read_file", "docs/4111/1111/1111/1111.md"),
    ("get_user_078_05_1120", "user"), ("get_user", "users/123_45_6789"), ("read_file", "users_123_45_6789"),
    ("get_user", "user 4111 1111 1111 1111"), ("get_user", "user.078.05.1120"),
])
def test_a_card_or_social_security_number_is_caught_whatever_separates_its_groups(action, resource):
    got = srv._gate_assessment(action, resource)
    assert got["verdict"] == "ESCALATE", (action, resource, got)


@pytest.mark.parametrize("resource", ["docs/2024/01/15", "notes-1.2.3.md", "docs/2024-01-15", "page 2024", "chapter-12.txt", "./readme.md", "docs/./readme.md"])
def test_dates_and_versions_are_not_mistaken_for_identifiers(resource):
    assert verdict("read_file", resource) == "ALLOW", resource


# ---- a host followed only by a separator is still a host; my own rule-by-rule gaps ---------------------------------------
@pytest.mark.parametrize("resource", ["docs.rs/", "api.md/.", "site.cc//", "12345678.87654321.data-api.md/", "docs.rs/./", "blog.app/"])
def test_a_host_followed_only_by_a_separator_is_still_a_host(resource):
    for action in ("get_page", "read_file"):
        got = srv._gate_assessment(action, resource)
        assert got["verdict"] == "ESCALATE" and "network address" in got["reasons"][0], (action, resource, got)


@pytest.mark.parametrize("resource", ["docs\\readme.md", "docs\\..\\..\\readme.md", "notes\\readme.md"])
def test_a_backslash_in_the_resource_escalates_on_the_character_rule(resource):
    got = srv._gate_assessment("read_file", resource)
    assert got["verdict"] == "ESCALATE" and "characters other than" in got["reasons"][0], (resource, got)


@pytest.mark.parametrize("action", ["get user 078-05-1120", "get user 078 05 1120", "get_user_123456789", "get-user-4111-1111-1111-1111"])
def test_an_identifier_shaped_number_in_the_action_escalates(action):
    got = srv._gate_assessment(action, "docs")
    assert got["verdict"] == "ESCALATE" and "looks like a card" in got["reasons"][0], (action, got)


@pytest.mark.parametrize("resource", ["users 123456789", "users 1234567890", "users/987654321.md"])
def test_a_run_of_nine_digits_escalates_and_eight_does_not(resource):
    assert srv._gate_assessment("get_user", resource)["verdict"] == "ESCALATE", resource
    assert srv._gate_assessment("get_user", "users 12345678")["verdict"] == "ALLOW"


@pytest.mark.parametrize("resource", ["10.300/readme.md", "10.999/docs", "192.168.1000/readme.md"])
def test_a_short_dotted_number_with_an_oversized_last_part_is_an_address(resource):
    got = srv._gate_assessment("get_page", resource)
    assert got["verdict"] == "ESCALATE" and "network address" in got["reasons"][0], (resource, got)
