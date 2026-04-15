import unittest

from ghosttrace.engine import scan_identity


class EngineTest(unittest.TestCase):
    def test_scan_identity_returns_core_sections(self):
        result = scan_identity("maya.patel@example.com")

        self.assertGreaterEqual(result["score"]["score"], 0)
        self.assertLessEqual(result["score"]["score"], 100)
        self.assertTrue(result["exposures"]["breaches"])
        self.assertTrue(result["attackPaths"])
        self.assertGreater(result["businessImpact"]["estimatedFinancialRisk"], 0)
        self.assertTrue(result["report"]["fixPlan"])

    def test_hardening_reduces_or_holds_risk(self):
        base = scan_identity("maya.patel@example.com")
        hardened = scan_identity(
            "maya.patel@example.com",
            {
                "passwordManager": True,
                "mfaEnabled": True,
                "privacyLockdown": True,
                "breachMonitoring": True,
                "simSwapLock": True,
            },
        )

        self.assertLessEqual(hardened["score"]["score"], base["score"]["score"])
        self.assertGreaterEqual(hardened["beforeAfter"]["riskDrop"], 0)


if __name__ == "__main__":
    unittest.main()
