"""Offline regression checks for the retained census and paper's exact list."""

from collections import Counter
import csv
import hashlib
import json
from pathlib import Path
import re
import tarfile
import unittest

from census import classify, covers
from summarize import check_manifest

ROOT = Path(__file__).resolve().parent
FINAL = ROOT / "final-2026-09-09"


class CensusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not (FINAL / "observations.json").is_file():
            raise FileNotFoundError(
                "Restore the archived census outputs first. From the repository "
                "root, run: tar -xzf "
                "measurements/tld-census/outputs-2026-09-09.tar.gz"
            )
        cls.summary = json.loads((FINAL / "summary.json").read_text())
        cls.rows = json.loads((FINAL / "observations.json").read_text())
        cls.by_tld = {row["tld"]: row for row in cls.rows}

    def test_manifests(self):
        count = sum(check_manifest(ROOT / run) for run in
                    ("2026-09-09", "followup-2026-09-09"))
        self.assertEqual(count, 4473)
        self.assertEqual(count, self.summary["source_files_hash_verified"])
        self.assertEqual(check_manifest(FINAL), 6)

    def test_archive_preserves_all_outputs(self):
        archive_path = ROOT / "outputs-2026-09-09.tar.gz"
        expected = archive_path.with_suffix(".gz.sha256").read_text().split()[0]
        self.assertEqual(hashlib.sha256(archive_path.read_bytes()).hexdigest(), expected)
        prefix = "measurements/tld-census/"
        runs = {"2026-09-09", "followup-2026-09-09", "pilot-2026-09-09",
                "final-2026-09-09"}
        with tarfile.open(archive_path, "r:gz") as archive:
            members = archive.getmembers()
            self.assertTrue(all(member.isdir() or member.isfile() for member in members))
            files = [member for member in members if member.isfile()]
            self.assertEqual(len(files), 4511)
            self.assertEqual(len({member.name for member in files}), 4511)
            for member in files:
                self.assertTrue(member.name.startswith(prefix), member.name)
                relative = Path(member.name[len(prefix):])
                self.assertFalse(relative.is_absolute(), member.name)
                self.assertNotIn("..", relative.parts, member.name)
                self.assertIn(relative.parts[0], runs, member.name)
                with archive.extractfile(member) as source:
                    archived = hashlib.sha256(source.read()).digest()
                original = hashlib.sha256((ROOT / relative).read_bytes()).digest()
                self.assertEqual(archived, original, member.name)

    def test_complete_population(self):
        seeds = {name.lower() for name in
                 (ROOT / "2026-09-09/tlds-alpha-by-domain.txt").read_text().splitlines()
                 if name and not name.startswith("#")}
        self.assertEqual(set(self.by_tld), seeds)
        self.assertEqual(len(self.rows), 1438)
        self.assertEqual(len(self.by_tld), 1438)
        with (FINAL / "tld_results.csv").open(newline="") as handle:
            csv_rows = list(csv.DictReader(handle))
        self.assertEqual(len(csv_rows), 1438)
        self.assertEqual({r["tld"] for r in csv_rows}, seeds)
        counts = dict(Counter(r["denial_mechanism"] for r in self.rows))
        self.assertEqual(counts, {"nsec": 53, "nsec3": 1309, "unsigned_response": 76})
        self.assertEqual(counts, self.summary["counts"])
        self.assertEqual(sum(r["root_ds"] for r in self.rows), 1350)

    def test_reclassification_matches_retained_observations(self):
        count = 0
        for row in self.rows:
            for recorded in row["observations"]:
                raw = ROOT.joinpath(*Path(recorded["raw"]).parts[-3:])
                actual = classify(raw.read_text(), row["tld"], recorded["query"])
                for field in ("classification", "ad", "aa", "compact_nsec",
                              "nsec_covers_query", "denial_records"):
                    self.assertEqual(actual[field], recorded[field], (raw, field))
                count += 1
        self.assertEqual(count, 3021)

    def test_exact_candidate_lists(self):
        trusted = set(self.summary["nsec_with_root_ds"])
        candidates = set(self.summary["p21_nsec_parent_candidates"])
        self.assertEqual(len(trusted), 52)
        self.assertEqual(len(candidates), 51)
        self.assertEqual(trusted - candidates, {"gov"})
        self.assertEqual(set(self.summary["nsec_observed"]) - trusted, {"xn--fzc2c9e2c"})
        for name in trusted:
            self.assertGreaterEqual(self.by_tld[name]["ad_resolver_count"], 2)
        for name in candidates:
            row = self.by_tld[name]
            self.assertTrue(row["root_ds"])
            self.assertTrue(row["covering_nsec_authoritative"])
            self.assertTrue(row["authoritative_confirmed"])
            self.assertFalse(row["compact_nsec"])
        for filename, expected in (("nsec-root-ds.txt", trusted),
                                   ("p21-nsec-parent-candidates.txt", candidates)):
            self.assertEqual(set((FINAL / filename).read_text().splitlines()), expected)

    def test_paper_lists_exactly_52(self):
        paper = (ROOT / "tld_nsec_census.tex").read_text()
        body = paper.split("\\midrule", 1)[1].split("\\bottomrule", 1)[0]
        names = re.findall(r"\\texttt\{\.([^}]+)\}", body)
        self.assertEqual(len(names), 52)
        self.assertEqual(set(names), set(self.summary["nsec_with_root_ds"]))

    def test_special_cases(self):
        self.assertTrue(self.by_tld["gov"]["compact_nsec"])
        self.assertFalse(self.by_tld["gov"]["covering_nsec_authoritative"])
        self.assertFalse(self.by_tld["xn--fzc2c9e2c"]["root_ds"])
        self.assertEqual(self.by_tld["xn--kprw13d"]["denial_mechanism"], "nsec3")
        self.assertEqual(self.by_tld["xn--node"]["denial_mechanism"], "unsigned_response")

    def test_interval_boundaries(self):
        self.assertTrue(covers("a.test.", "c.test.", "b.test."))
        self.assertFalse(covers("a.test.", "c.test.", "a.test."))
        self.assertFalse(covers("a.test.", "c.test.", "c.test."))
        self.assertTrue(covers("z.test.", "a.test.", "zz.test."))
        self.assertTrue(covers("z.test.", "a.test.", "0.test."))
        self.assertFalse(covers("z.test.", "a.test.", "b.test."))


if __name__ == "__main__":
    unittest.main()
