import unittest

from password_strength import analyze_password


class AnalyzePasswordTests(unittest.TestCase):
    def test_empty_password_is_very_weak(self):
        result = analyze_password("")

        self.assertEqual(result.score, 0)
        self.assertEqual(result.label, "Very weak")
        self.assertTrue(result.feedback)

    def test_common_password_is_penalized(self):
        common = analyze_password("password")
        less_predictable = analyze_password("sailboat")

        self.assertLess(common.score, less_predictable.score)
        self.assertTrue(any("common" in note for note in common.feedback))

    def test_long_mixed_password_scores_well(self):
        result = analyze_password("Cobalt!River7-Maple#29")

        self.assertEqual(result.label, "Very strong")
        self.assertGreaterEqual(result.score, 90)

    def test_repeated_and_sequential_patterns_are_flagged(self):
        result = analyze_password("Abcd1111!x")

        self.assertTrue(any("repeating" in note for note in result.feedback))
        self.assertTrue(any("sequences" in note for note in result.feedback))

    def test_score_stays_within_bounds(self):
        for password in ("a", "123456", "Aa1!long-enough-password"):
            with self.subTest(password=password):
                result = analyze_password(password)
                self.assertGreaterEqual(result.score, 0)
                self.assertLessEqual(result.score, 100)


if __name__ == "__main__":
    unittest.main()
