import unittest

from berry_reputation.models import ProviderResult, aggregate


class AggregateTests(unittest.TestCase):
    def test_high_provider_escalates(self):
        out = aggregate([
            ProviderResult(provider="a", score=90, proxy=True),
            ProviderResult(provider="b", score=20),
        ])
        self.assertGreaterEqual(out.score, 70)
        self.assertTrue(out.proxy)

    def test_warnings_do_not_raise_score(self):
        out = aggregate([
            ProviderResult(provider="a", warning="disabled"),
            ProviderResult(provider="local", score=0),
        ])
        self.assertEqual(out.score, 0)
        self.assertTrue(out.warnings)


if __name__ == "__main__":
    unittest.main()
