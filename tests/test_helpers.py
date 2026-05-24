import unittest
from helpers import vt_verdict, ip_verdict

class TestVtVerdict(unittest.TestCase):
    def test_malicious_returns_malicious(self):
        self.assertEqual(vt_verdict(1, 0), "MALICIOUS")

    def test_suspicious_returns_suspicious(self):
        self.assertEqual(vt_verdict(0, 1), "SUSPICIOUS")

    def test_clean_returns_clean(self):
        self.assertEqual(vt_verdict(0, 0), "CLEAN")

class TestIpVerdict(unittest.TestCase):
    def test_high_score_returns_malicious(self):
        self.assertEqual(ip_verdict(80), "MALICIOUS")

    def test_medium_score_returns_suspicious(self):
        self.assertEqual(ip_verdict(25), "SUSPICIOUS")

    def test_below_threshold_returns_clean(self):
        self.assertEqual(ip_verdict(24), "CLEAN")

    def test_zero_returns_clean(self):
        self.assertEqual(ip_verdict(0), "CLEAN")

if __name__ == "__main__":
    unittest.main()