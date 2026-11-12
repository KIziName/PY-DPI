"""Тесты списка режимов и логики их определения."""
import unittest

from config import MODES


class TestModes(unittest.TestCase):

    def test_all_expected_modes_present(self):
        expected = {
            "split", "disorder",
            "triple_split", "triple_disorder",
            "fake+split", "fake+disorder",
        }
        self.assertEqual(set(MODES), expected)

    def test_triple_modes_present(self):
        self.assertIn("triple_split", MODES)
        self.assertIn("triple_disorder", MODES)

    def test_no_fake_triple_combination(self):
        # fake+triple — избыточный режим, его быть не должно
        for mode in MODES:
            self.assertFalse(
                "fake" in mode and "triple" in mode,
                f"Unexpected fake+triple mode: {mode}"
            )

    def test_mode_parsing_logic(self):
        # Проверяем, что парсинг режима (как в _fragment_and_send) работает
        for mode in MODES:
            use_fake = mode.startswith("fake")
            disorder = mode.endswith("disorder")
            use_triple = "triple" in mode

            if mode == "split":
                self.assertFalse(use_fake)
                self.assertFalse(disorder)
                self.assertFalse(use_triple)
            elif mode == "disorder":
                self.assertFalse(use_fake)
                self.assertTrue(disorder)
                self.assertFalse(use_triple)
            elif mode == "triple_split":
                self.assertFalse(use_fake)
                self.assertFalse(disorder)
                self.assertTrue(use_triple)
            elif mode == "triple_disorder":
                self.assertFalse(use_fake)
                self.assertTrue(disorder)
                self.assertTrue(use_triple)
            elif mode == "fake+split":
                self.assertTrue(use_fake)
                self.assertFalse(disorder)
                self.assertFalse(use_triple)
            elif mode == "fake+disorder":
                self.assertTrue(use_fake)
                self.assertTrue(disorder)
                self.assertFalse(use_triple)


if __name__ == "__main__":
    unittest.main()