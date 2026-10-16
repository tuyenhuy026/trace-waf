"""Run: python -m unittest discover -s tests -v"""
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from wafbench import (Case, build_cases, canonical, classify, escapes_document_root,
                      encode_every_char, variants)

class WafbenchTests(unittest.TestCase):
    def test_dataset_determinism_and_holdout(self):
        a=build_cases()
        self.assertEqual(a, build_cases())
        self.assertTrue(any(c.split=="test" for c in a))
        self.assertTrue(any(c.split=="dev" for c in a))
    def test_canonical_decodes_bounded_twice(self):
        s="<script>alert(1)</script>"
        self.assertEqual(canonical(encode_every_char(encode_every_char(s))),s)
    def test_path_normalization(self):
        self.assertTrue(escapes_document_root("docs/../../../private/x.txt"))
        self.assertFalse(escapes_document_root("docs/../docs/readme.md"))
    def test_tutorial_route_scoping(self):
        a=Case("x","test",0,"CWE-79","/api/tutorial","hard_negative","x", "<script>alert(0)</script>")
        self.assertTrue(classify(a,"raw_signature"))
        self.assertFalse(classify(a,"trace_policy"))
    def test_sql_obfuscated_comment(self):
        s="a' OR 1=1 --"
        item=Case("a","test",1,"CWE-89","/api/search","cwe_transform","a", variants(s,"CWE-89")[-1][1])
        self.assertTrue(classify(item,"trace_policy"))
    def test_no_external_network(self):
        self.assertFalse("http" in str(build_cases()[0].route))

if __name__ == "__main__":
    unittest.main()
