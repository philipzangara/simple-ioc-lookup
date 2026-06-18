import unittest
from unittest.mock import patch, MagicMock
from enrichment.otx import check_otx

class TestCheckOTX(unittest.TestCase):

    @patch('enrichment.otx.requests.get')
    def test_happy_path(self, mock_get):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "pulse_info": {
                "count": 3,
                "pulses": [],
                "related": {
                    "alienvault": {
                        "adversary": ["APT28"],
                        "malware_families": ["Mimikatz"],
                        "industries": []
                    },
                    "other": {
                        "adversary": [],
                        "malware_families": [],
                        "industries": []
                    }
                }
            },
            "validation": [
                {"name": "Known Malware"}
            ]
        }
        mock_get.return_value = mock_response
        result = check_otx("fakehash123", "sha256")
        self.assertEqual(result["pulse_count"], 3)
        self.assertEqual(result["adversaries"], ["APT28"])
        self.assertEqual(result["malware_families"], ["Mimikatz"])
        self.assertEqual(result["validation"], ["Known Malware"])

    @patch('enrichment.otx.api_key', '')
    def test_no_api_key(self):
        result = check_otx("fakehash123", "sha256")
        self.assertEqual(result["error"], "No OTX API key found in .env")

    def test_unsupported_ioc_type(self):
        result = check_otx("fakehash123", "unknown")
        self.assertIn("error", result)

    @patch('enrichment.otx.requests.get')
    def test_bad_response_structure(self, mock_get):
        mock_response = MagicMock()
        mock_response.json.return_value = {"unexpected": "structure"}
        mock_get.return_value = mock_response
        result = check_otx("fakehash123", "sha256")
        self.assertIn("error", result)

if __name__ == "__main__":
    unittest.main()