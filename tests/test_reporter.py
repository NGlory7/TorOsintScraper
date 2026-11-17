import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.analyzer import analyze_content
from core.reporter import generate_reports


class TestReporter(unittest.TestCase):
    def test_reports_are_written_and_escape_html(self):
        results = [
            {
                "url": "http://example.onion",
                "status": "Up",
                "title": "<script>alert(1)</script>",
                "analysis": {
                    "emails": ["a@b.org"],
                    "crypto_wallets": {"btc": ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"], "eth": [], "xmr": []},
                    "onion_links": [],
                },
            },
            {"url": "http://down.onion", "status": "Down", "analysis": {}},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            paths = generate_reports(results, tmp, exit_ip="1.2.3.4")
            for p in paths:
                self.assertTrue(os.path.isfile(p), p)
            with open(os.path.join(tmp, "results.json"), encoding="utf-8") as f:
                self.assertEqual(json.load(f), results)
            html_path = [p for p in paths if p.endswith(".html")][0]
            with open(html_path, encoding="utf-8") as f:
                page = f.read()
            # Sayfadan gelen başlık HTML'e kaçışsız girmemeli (rapor açılınca script çalışmasın)
            self.assertNotIn("<script>alert(1)</script>", page)

    def test_analyzer_handles_empty_and_plain_text(self):
        self.assertEqual(analyze_content("")["osint"]["emails"], [])
        out = analyze_content("no html here, contact me@example.com")
        self.assertIn("me@example.com", out["osint"]["emails"])


if __name__ == "__main__":
    unittest.main()
