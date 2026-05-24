import unittest
from ioc_detector import detect_ioc_type

class TestDetectIocType(unittest.TestCase):

    def test_url_http(self):
        self.assertEqual(detect_ioc_type("http://malicious.com"), "url")

    def test_url_https(self):
        self.assertEqual(detect_ioc_type("https://malicious.com"), "url")

    def test_ip(self):
        self.assertEqual(detect_ioc_type("8.8.8.8"), "ip")

    def test_md5(self):
        self.assertEqual(detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e"), "md5")

    def test_sha1(self):
        self.assertEqual(detect_ioc_type("da39a3ee5e6b4b0d3255bfef95601890afd80709"), "sha1")

    def test_sha256(self):
        self.assertEqual(detect_ioc_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), "sha256")

    def test_domain(self):
        self.assertEqual(detect_ioc_type("malicious.com"), "domain")

class TestInvalidIoc(unittest.TestCase):
    
    def test_gibberish_returns_unknown(self):
        self.assertEqual(detect_ioc_type("asdfgh"), "unknown")

    def test_no_tld_returns_unknown(self):
        self.assertEqual(detect_ioc_type("notadomain"), "unknown")

    def test_number_only_returns_unknown(self):
        self.assertEqual(detect_ioc_type("12345"), "unknown")

if __name__ == "__main__":
    unittest.main()