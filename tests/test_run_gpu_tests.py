"""scripts/run_gpu_tests.py: how the compute dump tests judge vk_compute_test's output (no device needed)."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "runtime" / "test" / "shaders"))
import check
import run_gpu_tests as rgt

UNAVAILABLE = 77, "device: X (subgroup 32..32)\nfull 64-wide compute subgroups unavailable\n"
WAVE64 = sorted(rgt.NEEDS_WAVE64)


def dump(words, confirmed=True):
    """What vk_compute_test prints on success; the 64-wide confirmation comes first (--require-wave64 only)."""
    line = "out[0..7] = " + " ".join(str(w) for w in (list(words) + [0] * 8)[:8]) + "\n"
    return 0, ("compute subgroup size: 64\n" if confirmed else "") + line


class CsDump(unittest.TestCase):
    def run_dump(self, name, result):
        calls = []

        def fake(cmd, env=None):
            calls.append(cmd)
            return result
        with patch.object(rgt, "run_cmd", side_effect=fake):
            return rgt.run_cs_dump("vk_compute_test", f"{name}.spv", name), calls[0]

    def test_wave64_tests_ask_for_64_wide_subgroups_and_skip_without_them(self):
        self.assertEqual(set(WAVE64), set(rgt.CS_DUMP_WANTS) - {"cs_store"})
        for name in WAVE64:
            with self.subTest(name=name):
                (ok, detail), cmd = self.run_dump(name, UNAVAILABLE)
                self.assertIs(ok, None)
                self.assertIn("64-wide", detail)
                self.assertEqual(cmd[-1], "--require-wave64")

    def test_cs_store_runs_everywhere_and_a_77_is_not_a_skip(self):
        words = rgt.CS_DUMP_WANTS["cs_store"]
        (ok, detail), cmd = self.run_dump("cs_store", dump(words, confirmed=False))   # no confirmation line needed
        self.assertIs(ok, True)
        self.assertNotIn("--require-wave64", cmd)
        (ok, _), _ = self.run_dump("cs_store", UNAVAILABLE)
        self.assertIs(ok, False)

    def test_results_on_a_wave64_device(self):
        for name in WAVE64:
            want = rgt.CS_DUMP_WANTS[name]
            with self.subTest(name=name):
                self.assertIs(self.run_dump(name, dump(want))[0][0], True)
                for i in range(len(want)):           # any one word off fails
                    wrong = list(want)
                    wrong[i] ^= 1
                    self.assertIs(self.run_dump(name, dump(wrong))[0][0], False, f"word {i}")
                self.assertIs(self.run_dump(name, (1, "Vulkan pipeline failed\n"))[0][0], False)    # not a skip
                self.assertIs(self.run_dump(name, (0, "no dump line\n"))[0][0], False)

    def test_right_words_without_the_64_wide_confirmation_fail(self):
        for name in WAVE64:    # an old vk_compute_test that ignores --require-wave64 must not pass (check.py agrees)
            with self.subTest(name=name):
                (ok, detail), _ = self.run_dump(name, dump(rgt.CS_DUMP_WANTS[name], confirmed=False))
                self.assertIs(ok, False)
                self.assertIn("not confirmed", detail)

    def test_dump_line_must_be_eight_decimal_words_like_check_py(self):
        for name, want in rgt.CS_DUMP_WANTS.items():
            first = " ".join(str(w) for w in want)          # the words the test checks
            for label, line in (("only the expected words", first),
                                ("text after them", first + " BAD" + " 0" * (7 - len(want))),     # eight tokens, one bad
                                ("text inside", "1 BAD 3"),
                                ("seven words", " ".join(["0"] * 7)),
                                ("nine words", " ".join(["0"] * 9))):
                with self.subTest(name=name, line=label):
                    (ok, detail), _ = self.run_dump(name, (0, f"compute subgroup size: 64\nout[0..7] = {line}\n"))
                    self.assertIs(ok, False)
                    self.assertIn(line, detail)             # the harness output is shown, nothing raised

    def test_same_tests_and_words_as_check_py(self):
        self.assertEqual(rgt.CS_DUMP_WANTS, dict(check.CS_DUMPS))


if __name__ == "__main__":
    unittest.main()
