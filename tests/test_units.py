"""Provenance + blast radius + risk tests."""

import unittest

from pr_verify import blastradius as br
from pr_verify import config as config_mod
from pr_verify import miniyaml
from pr_verify import provenance as pv
from pr_verify import risk as rk

from fixture import PASS_GATE, commit_at_new_base, make_pr_repo, yaml_str

MARKERS = ["claude", "bot"]


class TestProvenance(unittest.TestCase):
    def test_labels(self):
        tmp, BASE = make_pr_repo()
        prov = pv.analyze(tmp, BASE, "HEAD", MARKERS)
        self.assertIn("app/core.py", prov)
        self.assertIn("app/auth.py", prov)
        # core.py: human added double(), agent added cached_calc()
        core = prov["app/core.py"]
        self.assertEqual(core.label(), "mixed")
        self.assertGreater(core.agent_added, 0)
        self.assertGreater(core.human_added, 0)
        # auth.py: only the agent touched it in range
        self.assertEqual(prov["app/auth.py"].label(), "agent")
        # views.py: new file, agent-authored
        self.assertEqual(prov["app/views.py"].label(), "agent")

    def test_agent_identities(self):
        tmp, BASE = make_pr_repo()
        prov = pv.analyze(tmp, BASE, "HEAD", MARKERS)
        self.assertIn("claude-bot", prov["app/auth.py"].agents)

    def test_no_markers_no_agents(self):
        tmp, BASE = make_pr_repo()
        prov = pv.analyze(tmp, BASE, "HEAD", ["definitely-not-an-agent"])
        for f in prov.values():
            self.assertEqual(f.agent_added, 0)


class TestBlastRadius(unittest.TestCase):
    def test_transitive(self):
        tmp, BASE = make_pr_repo()
        # views.py imports app.core; core is imported by views
        radii = br.analyze(tmp, ["app/core.py"])
        r = radii["app/core.py"]
        self.assertIn("app/views.py", r.direct)
        self.assertIn("app/views.py", r.transitive)

    def test_leaf_has_no_dependents(self):
        tmp, BASE = make_pr_repo()
        radii = br.analyze(tmp, ["app/views.py"])
        self.assertEqual(radii["app/views.py"].size, 0)

    def test_unknown_file(self):
        tmp, BASE = make_pr_repo()
        radii = br.analyze(tmp, ["nope/missing.py"])
        self.assertTrue(radii["nope/missing.py"].external_only)


class TestRisk(unittest.TestCase):
    def _prov(self, added, agent_added):
        f = pv.FileProvenance(file="a.py")
        f.added, f.agent_added = added, agent_added
        return {"a.py": f}

    def test_all_agent_high(self):
        b = rk.score(self._prov(100, 100), {"a.py": br.BlastRadius("a.py", [], [])},
                     [], [], 70)
        self.assertEqual(b.factors["agent_share"]["points"], 40)
        self.assertGreaterEqual(b.score, 40)

    def test_blast_scaling(self):
        small = rk.score(self._prov(10, 0),
                         {"a.py": br.BlastRadius("a.py", [], ["x.py"])},
                         [], [], 70)
        big = rk.score(self._prov(10, 0),
                       {"a.py": br.BlastRadius(
                           "a.py", [], [f"d{i}.py" for i in range(99)])},
                       [], [], 70)
        self.assertLess(small.factors["blast"]["points"],
                        big.factors["blast"]["points"])
        self.assertEqual(big.factors["blast"]["points"], 25)

    def test_sensitive(self):
        prov = {"app/x.py": pv.FileProvenance(file="app/x.py")}
        prov["app/x.py"].added = 10
        b = rk.score(prov, {}, [], ["**/auth*.py"], 70)
        self.assertEqual(b.factors["sensitive"]["points"], 0)
        prov["app/auth.py"] = pv.FileProvenance(file="app/auth.py")
        prov["app/auth.py"].added = 5
        b = rk.score(prov, {}, [], ["**/auth*.py"], 70)
        self.assertEqual(b.factors["sensitive"]["points"], 20)

    def test_sensitive_basename_globs(self):
        # "*auth*" must catch auth.py at the repo root or nested anywhere,
        # via basename matching — not only under matched directories.
        def prov_for(*rels):
            prov = {}
            for r in rels:
                fp = pv.FileProvenance(file=r)
                fp.added = 3
                prov[r] = fp
            return prov

        b = rk.score(prov_for("pkg/auth.py"), {}, [], ["auth*"], 70)
        self.assertEqual(b.factors["sensitive"]["points"], 20)
        b = rk.score(prov_for("auth.py"), {}, [], ["*auth*"], 70)
        self.assertEqual(b.factors["sensitive"]["points"], 20)
        # unrelated files stay clean
        b = rk.score(prov_for("app/core.py"), {}, [], ["auth*"], 70)
        self.assertEqual(b.factors["sensitive"]["points"], 0)

    def test_bands_and_threshold(self):
        b = rk.score(self._prov(100, 100),
                     {"a.py": br.BlastRadius("a.py", [], [f"d{i}" for i in range(99)])},
                     [], ["**/a.py"], 70)
        self.assertEqual(b.band, "high")
        self.assertTrue(b.requires_review)
        calm = rk.score(self._prov(10, 0), {}, [], [], 70)
        self.assertEqual(calm.band, "low")
        self.assertFalse(calm.requires_review)

    def test_no_tests_factor(self):
        prov = {"app/x.py": pv.FileProvenance(file="app/x.py")}
        prov["app/x.py"].added = 5
        b = rk.score(prov, {}, [], [], 70)
        self.assertEqual(b.factors["no_tests"]["points"], 5)
        prov["tests/t.py"] = pv.FileProvenance(file="tests/t.py")
        prov["tests/t.py"].added = 3
        b = rk.score(prov, {}, [], [], 70)
        self.assertEqual(b.factors["no_tests"]["points"], 0)


class TestDeletionFactor(unittest.TestCase):
    def _deleted(self, rel, agent=True):
        fp = pv.FileProvenance(file=rel, deleted=True)
        if agent:
            fp.agents.add("claude-bot")
            fp.deleted_by.append("claude-bot")
        else:
            fp.deleted_by.append("dan")
        return {rel: fp}

    def test_sensitive_deletion_trips_high(self):
        # (a) agent deletes a sensitive file -> trips the HIGH threshold.
        # deletion 45 + sensitive 20 + no_tests 5 = 70.
        b = rk.score(self._deleted("app/auth.py"), {}, [], ["**/*auth*.py"], 70)
        self.assertEqual(b.factors["deletion"]["points"], 45)
        self.assertEqual(b.factors["sensitive"]["points"], 20)
        self.assertGreaterEqual(b.score, 70)
        self.assertEqual(b.band, "high")
        self.assertTrue(b.requires_review)

    def test_sensitive_factor_counts_deleted_files(self):
        # deleted sensitive files score like touched sensitive files (20),
        # even when the deletion is human-attributed.
        b = rk.score(self._deleted("app/auth.py", agent=False), {}, [],
                     ["**/*auth*.py"], 70)
        self.assertEqual(b.factors["sensitive"]["points"], 20)

    def test_human_deletion_stays_quiet(self):
        # no agent attribution -> no deletion points; human deletion of a
        # sensitive file is their own review problem, not agent-trust.
        b = rk.score(self._deleted("app/auth.py", agent=False), {}, [],
                     ["**/*auth*.py"], 70)
        self.assertEqual(b.factors["deletion"]["points"], 0)
        self.assertLess(b.score, 70)
        self.assertFalse(b.requires_review)

    def test_deletion_dependents_add_blast_points(self):
        # (b) agent deletes a file imported by two others -> blast-radius
        # points applied: 10 (any agent deletion) + log-scaled dependents.
        prov = self._deleted("app/util.py")
        blast = {"app/util.py": br.BlastRadius(
            "app/util.py", ["a.py", "b.py"], ["a.py", "b.py"])}
        b = rk.score(prov, blast, [], [], 70)
        self.assertGreater(b.factors["deletion"]["points"], 10)
        self.assertEqual(b.factors["deletion"]["points"], 10 + 6)
        self.assertLess(b.score, 70)

    def test_deletion_factor_capped_at_50(self):
        # sensitive deletion with huge dependents still caps at 50.
        prov = self._deleted("app/auth.py")
        blast = {"app/auth.py": br.BlastRadius(
            "app/auth.py", [], [f"d{i}.py" for i in range(999)])}
        b = rk.score(prov, blast, [], ["**/*auth*.py"], 70)
        self.assertEqual(b.factors["deletion"]["points"], 50)

    def test_benign_deletion_does_not_trip(self):
        # (c) agent deletes a docs-only file: 10 deletion + 5 no_tests,
        # nowhere near the threshold.
        b = rk.score(self._deleted("docs/guide.md"), {}, [], [], 70)
        self.assertEqual(b.factors["deletion"]["points"], 10)
        self.assertLess(b.score, 70)
        self.assertFalse(b.requires_review)

    def test_no_deletions_zero(self):
        b = rk.score({"a.py": pv.FileProvenance(file="a.py")},
                     {}, [], [], 70)
        self.assertEqual(b.factors["deletion"]["points"], 0)


class TestConfig(unittest.TestCase):
    def test_load_from_base_ref(self):
        # Config parses through the vendored stdlib parser (no PyYAML)
        # and is read from the base ref.
        tmp, old_base = make_pr_repo()
        base = commit_at_new_base(tmp, old_base, {".pr-verify.yaml": (
            "agent_markers:\n"
            "  - mybot\n"
            "sensitive_paths:\n"
            '  - "*sekrit*"\n'
            "gates:\n"
            f"  - {yaml_str(PASS_GATE)}\n"
            "risk_threshold: 55\n"
            "timeout: 60\n")})
        cfg = config_mod.load(tmp, base)
        self.assertEqual(cfg["agent_markers"], ["mybot"])
        self.assertEqual(cfg["sensitive_paths"], ["*sekrit*"])
        self.assertEqual(cfg["gates"], [PASS_GATE])
        self.assertEqual(cfg["risk_threshold"], 55)
        self.assertEqual(cfg["timeout"], 60)

    def test_missing_config_at_base_gives_defaults(self):
        tmp, BASE = make_pr_repo()
        cfg = config_mod.load(tmp, BASE)
        self.assertEqual(cfg["gates"], [])
        self.assertEqual(cfg["risk_threshold"], 70)
        self.assertIn("claude", cfg["agent_markers"])

    def test_example_config_parses(self):
        parsed = miniyaml.safe_load(config_mod.example_config())
        self.assertEqual(parsed["risk_threshold"], 70)
        self.assertEqual(parsed["timeout"], 300)
        self.assertIn("python -m pytest -x -q", parsed["gates"])
        self.assertIn("claude", parsed["agent_markers"])


if __name__ == "__main__":
    unittest.main()
