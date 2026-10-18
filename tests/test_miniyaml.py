"""Regression tests for miniyaml hardening (anchors/aliases/tags, depth
limit, strict malformed-YAML rejection). Mirrored in pr-verify and
prompt-regress against their verbatim miniyaml copies."""

import unittest

from pr_verify import miniyaml


def _deep(nesting: int) -> str:
    return (
        "".join(f"{'  ' * i}k{i}:\n" for i in range(nesting))
        + "  " * nesting
        + "v: 1\n"
    )


class TestAnchorsAliasesTags(unittest.TestCase):
    def test_anchor_value_rejected(self):
        with self.assertRaisesRegex(ValueError, r"anchors \(&\).*line 2"):
            miniyaml.safe_load("a:\n  b: &x")

    def test_anchor_on_nested_block_rejected(self):
        with self.assertRaisesRegex(ValueError, r"anchors \(&\)"):
            miniyaml.safe_load("a: &x\n  b: 1")

    def test_anchor_list_item_rejected(self):
        with self.assertRaisesRegex(ValueError, r"anchors \(&\)"):
            miniyaml.safe_load("- &x foo")

    def test_alias_value_rejected(self):
        with self.assertRaisesRegex(ValueError, r"aliases \(\*\)"):
            miniyaml.safe_load("a: *x")

    def test_alias_list_item_rejected(self):
        with self.assertRaisesRegex(ValueError, r"aliases \(\*\)"):
            miniyaml.safe_load("- *x")

    def test_tag_value_rejected(self):
        with self.assertRaisesRegex(ValueError, r"tags \(!\)"):
            miniyaml.safe_load("a: !tag foo")

    def test_tag_shorthand_rejected(self):
        with self.assertRaisesRegex(ValueError, r"tags \(!\)"):
            miniyaml.safe_load("a: !!str foo")

    def test_anchors_never_silently_dropped(self):
        # Before the fix, "a: &x" parsed as the string "&x".
        with self.assertRaises(ValueError):
            miniyaml.safe_load("a: &x")


class TestDepthLimit(unittest.TestCase):
    def test_600_deep_raises_value_error_not_recursion_error(self):
        try:
            miniyaml.safe_load(_deep(600))
        except ValueError as e:
            self.assertIn("nesting depth", str(e))
            self.assertIn("(line ", str(e))
        except RecursionError:
            self.fail("RecursionError leaked; expected ValueError")
        else:
            self.fail("expected ValueError for 600-deep nesting")

    def test_shallow_nesting_still_parses(self):
        doc = miniyaml.safe_load(_deep(40))
        d = doc
        for i in range(40):
            d = d[f"k{i}"]
        self.assertEqual(d, {"v": 1})


class TestStrictMalformed(unittest.TestCase):
    def test_unclosed_flow_list_rejected(self):
        with self.assertRaisesRegex(ValueError, r"unclosed flow list.*line 1"):
            miniyaml.safe_load("a: [x")

    def test_embedded_mapping_indicator_rejected(self):
        with self.assertRaisesRegex(ValueError, r"unexpected ':'.*line 2"):
            miniyaml.safe_load("x: 1\na: b: c")

    def test_flow_map_rejected(self):
        with self.assertRaisesRegex(ValueError, r"flow-style maps.*line 1"):
            miniyaml.safe_load("a: {x: y}")

    def test_block_scalar_rejected(self):
        with self.assertRaisesRegex(ValueError, r"multi-line.*line 1"):
            miniyaml.safe_load("a: |")

    def test_unterminated_quote_rejected(self):
        with self.assertRaisesRegex(ValueError, r"unterminated quoted"):
            miniyaml.safe_load('a: "oops')

    def test_duplicate_key_rejected(self):
        with self.assertRaisesRegex(ValueError, r"duplicate key.*line 2"):
            miniyaml.safe_load("a: 1\na: 2")

    def test_valid_lookalikes_still_parse(self):
        self.assertEqual(miniyaml.safe_load("u: http://x"), {"u": "http://x"})
        self.assertEqual(miniyaml.safe_load("t: 12:30"), {"t": "12:30"})
        self.assertEqual(miniyaml.safe_load("t: b:c"), {"t": "b:c"})
        self.assertEqual(miniyaml.safe_load("g: 'a: b'"), {"g": "a: b"})


class TestSingleQuoteEscape(unittest.TestCase):
    """YAML single-quoted scalars: `''` is one `'`, and that is the only
    escape (no backslash escapes in single quotes)."""

    def load(self, text):
        return miniyaml.safe_load(text)

    def test_doubled_quote_is_one_quote(self):
        self.assertEqual(self.load("a: 'it''s'"), {"a": "it's"})
        self.assertEqual(self.load("a: 'a''b''c'"), {"a": "a'b'c"})

    def test_quote_at_the_edges_of_the_scalar(self):
        self.assertEqual(self.load("a: '''x'"), {"a": "'x"})
        self.assertEqual(self.load("a: 'x'''"), {"a": "x'"})
        self.assertEqual(self.load("a: ''''"), {"a": "'"})
        self.assertEqual(self.load("a: ''"), {"a": ""})

    def test_escaped_quote_does_not_end_the_quoted_region(self):
        # '#' and ':' after an escaped quote are still inside the string
        self.assertEqual(self.load("a: 'it''s # not a comment'"),
                         {"a": "it's # not a comment"})
        self.assertEqual(self.load("a: 'it''s: fine'"), {"a": "it's: fine"})
        self.assertEqual(self.load("a: 'it''s'  # a real comment"),
                         {"a": "it's"})

    def test_in_lists(self):
        self.assertEqual(self.load("a: ['it''s', 'x', 'y,''z']"),
                         {"a": ["it's", "x", "y,'z"]})
        self.assertEqual(self.load("a:\n  - 'it''s'\n  - 'plain'"),
                         {"a": ["it's", "plain"]})
        self.assertEqual(self.load("- 'don''t'"), ["don't"])

    def test_nothing_else_changes(self):
        # double quotes: `''` is two characters, the escapes are exactly
        # what they were
        self.assertEqual(self.load('a: "it\'\'s"'), {"a": "it''s"})
        self.assertEqual(self.load('a: "a\\"b"'), {"a": 'a"b'})
        # single quotes: backslashes stay literal
        self.assertEqual(self.load("a: 'C:\\dir\\x'"), {"a": "C:\\dir\\x"})
        self.assertEqual(self.load("a: 'a\\\"b'"), {"a": 'a\\"b'})
        # plain scalars have no escapes at all
        self.assertEqual(self.load("a: it's"), {"a": "it's"})
        self.assertEqual(self.load("a: it''s"), {"a": "it''s"})

    def test_unterminated_single_quote_still_rejected(self):
        with self.assertRaisesRegex(ValueError, r"unterminated quoted"):
            self.load("a: 'oops")


class TestEmptyBlockList(unittest.TestCase):
    def test_flow_list_on_own_line(self):
        self.assertEqual(miniyaml.safe_load("layers:\n  []\nrules: [a]\n"),
                         {"layers": [], "rules": ["a"]})

    def test_extra_line_after_flow_block_rejected(self):
        with self.assertRaises(ValueError):
            miniyaml.safe_load("layers:\n  []\n  - x\n")


if __name__ == "__main__":
    unittest.main()


class TestApostropheAndComments(unittest.TestCase):
    """A quote opens a quoted scalar only where a scalar starts. Elsewhere
    (the apostrophe in "It's") it is an ordinary character: it must neither
    hide a trailing "# comment" nor break a flow list."""

    def test_apostrophe_in_a_plain_scalar_keeps_comment_stripping(self):
        self.assertEqual(miniyaml.safe_load("input: It's fine   # TODO\n"),
                         {"input": "It's fine"})
        self.assertEqual(miniyaml.safe_load("a: don't # why\nb: 1\n"),
                         {"a": "don't", "b": 1})

    def test_apostrophe_in_a_list_item(self):
        self.assertEqual(miniyaml.safe_load("- It's fine # c\n- two\n"),
                         ["It's fine", "two"])

    def test_apostrophe_in_a_comment_is_ignored(self):
        self.assertEqual(miniyaml.safe_load("a: 5  # it's five\n"), {"a": 5})
        self.assertEqual(miniyaml.safe_load('a: "x" # it\'s fine\n'), {"a": "x"})
        self.assertEqual(miniyaml.safe_load("a: 'x' # it's fine\n"), {"a": "x"})

    def test_double_quote_in_a_plain_scalar(self):
        self.assertEqual(miniyaml.safe_load('a: 5" pipe # size\n'),
                         {"a": '5" pipe'})

    def test_hash_inside_quotes_is_not_a_comment(self):
        self.assertEqual(miniyaml.safe_load("a: 'x # y' # real\n"),
                         {"a": "x # y"})
        self.assertEqual(miniyaml.safe_load('a: "x # y" # real\n'),
                         {"a": "x # y"})
        self.assertEqual(miniyaml.safe_load("a: 'it''s # no' # yes\n"),
                         {"a": "it's # no"})
        self.assertEqual(miniyaml.safe_load('a: "q \\" # no" # yes\n'),
                         {"a": 'q " # no'})

    def test_hash_without_a_space_before_it_is_text(self):
        self.assertEqual(miniyaml.safe_load("a: x#y\n"), {"a": "x#y"})
        self.assertEqual(miniyaml.safe_load("u: http://h/p#frag # c\n"),
                         {"u": "http://h/p#frag"})

    def test_apostrophes_in_a_flow_list(self):
        self.assertEqual(
            miniyaml.safe_load("a: [it's, \"x, y\", 'p''q', z]  # c\n"),
            {"a": ["it's", "x, y", "p'q", "z"]})

    def test_quoted_values_after_a_dash_and_a_colon_still_work(self):
        self.assertEqual(miniyaml.safe_load("- 'a # b' # c\n"), ["a # b"])
        self.assertEqual(miniyaml.safe_load("- k: 'a # b' # c\n"),
                         [{"k": "a # b"}])

    def test_unterminated_quote_is_still_rejected(self):
        with self.assertRaisesRegex(ValueError, r"unterminated quoted"):
            miniyaml.safe_load("a: 'oops # c\n")


if __name__ == "__main__":
    unittest.main()
