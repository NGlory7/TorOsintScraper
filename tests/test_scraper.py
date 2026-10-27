import unittest
import sys
import os

# Add root directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.analyzer import analyze_content
from core.network import TorManager
from core.scanner import OSINTScanner

class TestTorOsintScraper(unittest.TestCase):
    def test_analyzer_extraction(self):
        sample_html = """
        <html>
        <head><title>Test Dark Web Market</title></head>
        <body>
            <h1>Welcome to Onion Service</h1>
            <p>Contact admin at: security@exploit.im or support@darkmarket.org</p>
            <p>Fake email image: icon@test.png should be ignored.</p>
            <p>Donate BTC: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa</p>
            <p>Segwit BTC: bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq</p>
            <p>Donate ETH: 0x742d35Cc6634C0532925a3b844Bc454e4438f44e</p>
            <p>Mirror: duckduckgogg42xjoc72x3sjasowoarfbgcmvfima3ogtwv7v64yyad.onion</p>
            <p>Telegram: t.me/dark_intel_channel</p>
            <pre>
            -----BEGIN PGP PUBLIC KEY BLOCK-----
            mQENBF...
            -----END PGP PUBLIC KEY BLOCK-----
            </pre>
        </body>
        </html>
        """
        analysis = analyze_content(sample_html)

        # 1. Başlık
        self.assertEqual(analysis["title"], "Test Dark Web Market")

        # 2. Geriye dönük uyumluluk ('osint' anahtarı)
        self.assertIn("osint", analysis)

        # 3. E-posta tespiti
        emails = analysis["osint"]["emails"]
        self.assertIn("security@exploit.im", emails)
        self.assertIn("support@darkmarket.org", emails)
        self.assertNotIn("icon@test.png", emails)

        # 4. Kripto cüzdanlar
        wallets = analysis["osint"]["crypto_wallets"]
        self.assertIn("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", wallets["btc"])
        self.assertIn("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", wallets["btc"])
        self.assertIn("0x742d35Cc6634C0532925a3b844Bc454e4438f44e", wallets["eth"])

        # 5. Onion linkler
        onions = analysis["osint"]["onion_links"]
        self.assertTrue(any("duckduckgogg42xjoc72x3sjasowoarfbgcmvfima3ogtwv7v64yyad.onion" in o for o in onions))

        # 6. PGP
        self.assertTrue(analysis["osint"]["has_pgp"])

        # 7. Telegram
        self.assertIn("dark_intel_channel", analysis["osint"]["telegram"])

    def test_url_normalization(self):
        scanner = OSINTScanner(targets=[])
        self.assertEqual(scanner.normalize_url("example.onion"), "http://example.onion")
        self.assertEqual(scanner.normalize_url("https://check.torproject.org"), "https://check.torproject.org")
        self.assertEqual(scanner.normalize_url("http://test.onion/path"), "http://test.onion/path")

    def test_tor_manager_defaults(self):
        manager = TorManager()
        self.assertIn(manager.proxy_addr, ["socks5://127.0.0.1:9150", "socks5://127.0.0.1:9050"])

if __name__ == "__main__":
    unittest.main()
