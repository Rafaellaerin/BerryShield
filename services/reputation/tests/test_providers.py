import unittest
from berry_reputation.providers import IPQSProvider, _maxmind_to_result

class ProviderParsingTests(unittest.TestCase):
    def test_maxmind_current_anonymizer_shape(self):
        out = _maxmind_to_result({
            "anonymizer": {"is_anonymous_vpn": True, "is_hosting_provider": True, "is_tor_exit_node": False},
            "traits": {"autonomous_system_number": 64500},
            "country": {"iso_code": "BR"},
        })
        self.assertTrue(out.proxy)
        self.assertTrue(out.vpn)
        self.assertTrue(out.hosting)
        self.assertEqual(out.country, "BR")
        self.assertEqual(out.asn, "64500")
        self.assertGreater(out.score, 0)


    def test_ipqs_response_flags(self):
        import unittest.mock as mock
        sample = {
            "success": True, "fraud_score": 81, "proxy": False,
            "active_vpn": True, "active_tor": False,
            "connection_type": "Data Center", "country_code": "BR", "ASN": 64500,
        }
        with mock.patch("berry_reputation.providers._json_post_request", return_value=sample) as req:
            out = IPQSProvider("test-key").lookup("8.8.8.8", user_agent="Mozilla/5.0", language="pt-BR")
        args, _ = req.call_args
        self.assertEqual(args[0], "https://www.ipqualityscore.com/api/json/ip/")
        self.assertEqual(args[1]["IPQS-KEY"], "test-key")
        self.assertEqual(args[2]["ip"], "8.8.8.8")
        self.assertEqual(args[2]["user_agent"], "Mozilla/5.0")
        self.assertEqual(out.score, 81)
        self.assertTrue(out.proxy)
        self.assertTrue(out.vpn)
        self.assertTrue(out.hosting)
        self.assertEqual(out.country, "BR")

    def test_maxmind_legacy_traits_fallback(self):
        out = _maxmind_to_result({"traits": {"is_tor_exit_node": True}})
        self.assertTrue(out.tor)
        self.assertGreaterEqual(out.score, 40)

class NoExternalLookupForPrivateIPTests(unittest.TestCase):
    def test_private_ip_uses_only_local_provider(self):
        from berry_reputation.service import ReputationService
        from berry_reputation.models import ProviderResult
        class P:
            def __init__(self, name): self.name=name; self.called=False
            def lookup(self, ip, user_agent="", language=""):
                self.called=True
                return ProviderResult(provider=self.name, score=99)
        local=P("local"); external=P("external")
        svc=ReputationService([local, external], ttl_seconds=1)
        out=svc.lookup("127.0.0.1")
        self.assertTrue(local.called)
        self.assertFalse(external.called)
        self.assertGreaterEqual(out["score"], 70)

if __name__ == "__main__":
    unittest.main()
